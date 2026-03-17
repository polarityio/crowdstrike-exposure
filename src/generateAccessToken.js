/*
 * Copyright (c) 2024, Polarity.io, Inc.
 */
const requestWithDefaults = require('./requestWithDefaults');
const { getLogger } = require('./logger');
const { TokenRequestError } = require('./responses');
const { getTokenFromCache, setTokenInCache } = require('./tokenCache');

/**
 * Fetches a cached Bearer token or requests a new one via OAuth2 Client Credentials.
 * Tokens are valid for 30 minutes; the cache is invalidated on 401 by authenticatedRequest.
 */
const generateAccessToken = async (options) => {
  const Logger = getLogger();

  const cached = getTokenFromCache(options);
  if (cached) return cached;

  const requestOptions = {
    uri: `${options.url}/oauth2/token`,
    method: 'POST',
    json: true,
    form: {
      client_id: options.id,
      client_secret: options.secret
    }
  };

  try {
    const response = await requestWithDefaults.request(requestOptions);
    const { body, statusCode } = response;

    if (statusCode === 201 && body && body.access_token) {
      setTokenInCache(options, body.access_token);
      return body.access_token;
    }

    Logger.error({ body, statusCode }, 'Failed to obtain CrowdStrike access token');

    let detail = `Unexpected error fetching OAuth2 token (status: ${statusCode})`;
    if (statusCode === 403) detail = 'Client Secret does not match the provided Client ID';
    if (statusCode === 400 || statusCode === 401) detail = `Invalid Client ID (status: ${statusCode})`;

    throw new TokenRequestError(detail, statusCode, body, {
      ...requestOptions,
      form: { client_id: '********', client_secret: '********' }
    });
  } catch (err) {
    err.source = 'generateAccessToken';
    throw err;
  }
};

module.exports = generateAccessToken;
