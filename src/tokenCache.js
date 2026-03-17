/*
 * Copyright (c) 2024, Polarity.io, Inc.
 */

// In-memory token cache keyed on url+id+secret
const tokenCache = new Map();

const _getTokenKey = (options) => `${options.url}${options.id}${options.secret}`;

const getTokenFromCache = (options) => tokenCache.get(_getTokenKey(options));

const setTokenInCache = (options, token) => tokenCache.set(_getTokenKey(options), token);

const invalidateToken = (options) => tokenCache.delete(_getTokenKey(options));

module.exports = {
  getTokenFromCache,
  setTokenInCache,
  invalidateToken
};
