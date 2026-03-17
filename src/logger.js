/*
 * Copyright (c) 2024, Polarity.io, Inc.
 */

let _logger = null;

const setLogger = (logger) => {
  _logger = logger;
};

const getLogger = () => _logger;

module.exports = { setLogger, getLogger };
