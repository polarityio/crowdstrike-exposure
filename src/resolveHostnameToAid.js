/*
 * Copyright (c) 2024, Polarity.io, Inc.
 *
 * Resolves a hostname to a CrowdStrike Agent ID (AID) via the Devices API.
 * Spotlight only accepts AIDs (not hostnames) in its filter parameter.
 */
const authenticatedRequest = require('./authenticatedRequest');
const { getLogger } = require('./logger');

/**
 * @param {string} hostname - The hostname to resolve
 * @param {Object} options - Integration options
 * @returns {Promise<string|null>} The first matching AID, or null if not found
 */
const resolveHostnameToAid = async (hostname, options) => {
  const Logger = getLogger();

  const filter = `hostname:'${hostname.toUpperCase()}'`;
  const uri = `${options.url}/devices/queries/devices/v1?filter=${encodeURIComponent(filter)}&limit=1`;

  const requestOptions = {
    method: 'GET',
    uri,
    json: true
  };

  Logger.trace({ hostname, uri }, 'Resolving hostname to AID');

  const response = await authenticatedRequest(requestOptions, options);
  const resources = (response.body && response.body.resources) || [];

  if (resources.length === 0) {
    Logger.debug({ hostname }, 'No AID found for hostname');
    return null;
  }

  const aid = resources[0];
  Logger.trace({ hostname, aid }, 'Resolved hostname to AID');
  return aid;
};

module.exports = resolveHostnameToAid;
