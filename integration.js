/*
 * Copyright (c) 2024, Polarity.io, Inc.
 */
'use strict';

const { setLogger } = require('./src/logger');
const { getLookupResults } = require('./src/getLookupResults');
const { validateStringOptions, validateUrlOption } = require('./src/validateOptions');
const { parseErrorToReadableJSON, RetryRequestError } = require('./src/responses');

let Logger;

const startup = (logger) => {
  Logger = logger;
  setLogger(Logger);
};

const doLookup = async (entities, options, cb) => {
  Logger.debug({ entities }, 'CS Exposure doLookup');

  try {
    const lookupResults = await getLookupResults(entities, options, Logger);
    Logger.trace({ lookupResults }, 'CS Exposure Lookup Results');
    cb(null, lookupResults);
  } catch (error) {
    const err = parseErrorToReadableJSON(error);
    Logger.error({ error, formattedError: err }, 'CS Exposure Lookup Failed');

    if (error instanceof RetryRequestError) {
      return cb({
        detail: error.message,
        err,
        isVolatile: true  // allows user to retry from overlay
      });
    }

    cb({ detail: error.message || 'CrowdStrike Exposure lookup failed', err });
  }
};

const validateOptions = async (options, callback) => {
  const stringErrors = validateStringOptions(
    {
      url: 'You must provide a valid CrowdStrike API URL.',
      id: 'You must provide a valid Client ID.',
      secret: 'You must provide a valid Client Secret.'
    },
    options
  );

  const allErrors = validateUrlOption(
    options.url && options.url.value,
    stringErrors
  );

  callback(null, allErrors);
};

module.exports = { startup, doLookup, validateOptions };
