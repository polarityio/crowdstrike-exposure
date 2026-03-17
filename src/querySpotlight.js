/*
 * Copyright (c) 2024, Polarity.io, Inc.
 *
 * Queries /spotlight/combined/vulnerabilities/v1 with the appropriate filter and facets.
 * Facets always include: host_info, cve, remediation
 * Optionally includes: evaluation_logic (when options.enableEvalLogic is true)
 */
const authenticatedRequest = require('./authenticatedRequest');
const { getLogger } = require('./logger');
const { RequestError } = require('./responses');

/**
 * @param {string} filter - FQL filter string, e.g. "cve.id:'CVE-2022-38023'"
 * @param {Object} options - Integration options
 * @returns {Promise<Array>} Array of raw vulnerability resource objects
 */
const querySpotlight = async (filter, options) => {
  const Logger = getLogger();

  const facets = ['host_info', 'cve', 'remediation'];
  if (options.enableEvalLogic) facets.push('evaluation_logic');

  const limit = Math.min(Math.max(Number(options.maxResults) || 20, 1), 100);

  const params = new URLSearchParams();
  params.set('filter', filter);
  params.set('limit', String(limit));
  facets.forEach((f) => params.append('facet', f));

  const uri = `${options.url}/spotlight/combined/vulnerabilities/v1?${params.toString()}`;

  const requestOptions = {
    method: 'GET',
    uri,
    json: true
  };

  Logger.trace({ uri, filter, facets, limit }, 'Querying CrowdStrike Spotlight');

  const response = await authenticatedRequest(requestOptions, options);

  if (!response || !response.body) {
    throw new RequestError('Empty response from Spotlight API', response && response.statusCode, null, requestOptions);
  }

  const resources = response.body.resources || [];
  Logger.trace({ count: resources.length, filter }, 'Spotlight results');
  return resources;
};

module.exports = querySpotlight;
