/*
 * Copyright (c) 2024, Polarity.io, Inc.
 *
 * Wraps every API request with OAuth2 Bearer token injection and handles:
 *   401 — expired token: invalidate cache, retry once
 *   403 — missing scope: throw descriptive error, no retry
 *   429 — rate limit: throw RetryRequestError (user can retry)
 *   500/502/504 — server error: throw RetryRequestError
 *   ETIMEDOUT/ECONNRESET — network error: throw RetryRequestError
 */
const _ = require('lodash');
const generateAccessToken = require('./generateAccessToken');
const { invalidateToken } = require('./tokenCache');
const { RequestError, RetryRequestError } = require('./responses');
const requestWithDefaults = require('./requestWithDefaults');
const { getLogger } = require('./logger');

const MAX_AUTH_RETRIES = 1;

async function authenticatedRequest(requestOptions, options, retryCount = 0) {
  const Logger = getLogger();
  try {
    const token = await generateAccessToken(options);
    requestOptions.headers = { authorization: `Bearer ${token}` };

    const response = await requestWithDefaults.request(requestOptions);
    const { statusCode } = response;

    Logger.trace({ statusCode, url: requestOptions.url || requestOptions.uri }, 'CS Exposure API response');

    if ([200, 201, 202, 204].includes(statusCode)) return response;

    // Auth failures — retry once after refreshing the token
    if (statusCode === 401 || statusCode === 403) {
      if (retryCount >= MAX_AUTH_RETRIES) {
        throw new RequestError(
          statusCode === 403
            ? 'Client ID/Secret does not have required scopes (vulnerabilities:read, hosts:read)'
            : 'Authentication failed after token refresh',
          statusCode,
          response.body,
          { ...requestOptions, headers: '********' }
        );
      }
      Logger.trace({ statusCode, retryCount }, 'Token invalid/expired — refreshing and retrying');
      invalidateToken(options);
      return authenticatedRequest(requestOptions, options, retryCount + 1);
    }

    // Retryable server errors
    if ([429, 500, 502, 504].includes(statusCode)) {
      const err = new RetryRequestError(
        statusCode === 429 ? 'CrowdStrike API rate limit reached' : 'CrowdStrike API server error',
        statusCode,
        response.body,
        { ...requestOptions, headers: '********' }
      );
      if (statusCode === 429) {
        err.meta = {
          rateLimitLimit: response.headers['x-ratelimit-limit'],
          rateLimitRemaining: response.headers['x-ratelimit-remaining']
        };
      }
      throw err;
    }

    // Generic failure
    const message = _.get(response, 'body.errors[0].message', `Unexpected status ${statusCode}`);
    throw new RequestError(message, statusCode, response.body, {
      ...requestOptions,
      headers: '********'
    });
  } catch (err) {
    const code = _.get(err, 'code', '');
    if (code === 'ETIMEDOUT' || code === 'ECONNRESET') {
      throw new RetryRequestError(
        'CrowdStrike API connection error — please retry',
        code,
        null,
        { ...requestOptions, headers: '********' }
      );
    }
    throw err;
  }
}

module.exports = authenticatedRequest;
