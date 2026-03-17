/*
 * Copyright (c) 2024, Polarity.io, Inc.
 */

/**
 * Safely serializes any Error object to a plain JSON-compatible object
 * so it can be logged or returned as a Polarity callback error.
 */
const parseErrorToReadableJSON = (err) =>
  err instanceof Error
    ? {
        ...err,
        name: err.name,
        message: err.message,
        stack: err.stack,
        detail: err.message || 'Unexpected error encountered'
      }
    : err;

/**
 * Generic REST request error
 */
class RequestError extends Error {
  constructor(message, status, description, requestOptions) {
    super(message);
    this.name = 'RequestError';
    this.status = status;
    this.description = description;
    this.requestOptions = requestOptions;
  }
}

/**
 * Thrown when the OAuth2 token fetch fails
 */
class TokenRequestError extends Error {
  constructor(message, status, description, requestOptions) {
    super(message);
    this.name = 'TokenRequestError';
    this.status = status;
    this.description = description;
    this.requestOptions = requestOptions;
  }
}

/**
 * Thrown for errors that the user should be able to retry (429, 5xx, timeouts)
 */
class RetryRequestError extends Error {
  constructor(message, status, description, requestOptions) {
    super(message);
    this.name = 'RetryRequestError';
    this.status = status;
    this.description = description;
    this.requestOptions = requestOptions;
    this.meta = null;
  }
}

module.exports = {
  parseErrorToReadableJSON,
  RequestError,
  TokenRequestError,
  RetryRequestError
};
