/*
 * Copyright (c) 2024, Polarity.io, Inc.
 */
const fp = require('lodash/fp');
const reduce = require('lodash/fp/reduce').convert({ cap: false });

/**
 * Validates that the given string options are non-empty.
 */
const validateStringOptions = (errorMessages, options, otherErrors = []) =>
  reduce((acc, message, key) => {
    const val = options[key] && options[key].value;
    return typeof val !== 'string' || fp.isEmpty(val)
      ? acc.concat({ key, message })
      : acc;
  }, otherErrors)(errorMessages);

/**
 * Validates that the given URL option is a well-formed URL with no trailing slash.
 */
const validateUrlOption = (url, otherErrors = []) => {
  if (!url) return otherErrors;

  if (url.endsWith('/')) {
    return otherErrors.concat({ key: 'url', message: 'Base URL must not end with a /' });
  }

  try {
    new URL(url);
  } catch (_) {
    return otherErrors.concat({ key: 'url', message: 'Base URL is not a valid URL' });
  }

  return otherErrors;
};

module.exports = { validateStringOptions, validateUrlOption };
