/*
 * Copyright (c) 2024, Polarity.io, Inc.
 *
 * Fetches installed patch data for a given AID from the Spotlight Patches API.
 * Only called when options.enablePatches is true.
 * Requires the spotlight-patch:read OAuth2 scope.
 */
const authenticatedRequest = require('./authenticatedRequest');
const { getLogger } = require('./logger');

/**
 * @param {string} aid - CrowdStrike Agent ID
 * @param {Object} options - Integration options
 * @returns {Promise<Array>} Array of raw patch resource objects
 */
const getInstalledPatches = async (aid, options) => {
  const Logger = getLogger();

  const filter = `aid:'${aid}'`;
  const uri = `${options.url}/spotlight/combined/installed-patches/v1?filter=${encodeURIComponent(filter)}&limit=20`;

  const requestOptions = {
    method: 'GET',
    uri,
    json: true
  };

  Logger.trace({ aid, uri }, 'Fetching installed patches');

  const response = await authenticatedRequest(requestOptions, options);
  const resources = (response.body && response.body.resources) || [];

  Logger.trace({ aid, count: resources.length }, 'Installed patches fetched');
  return resources;
};

module.exports = getInstalledPatches;
