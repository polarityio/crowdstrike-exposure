/*
 * Copyright (c) 2024, Polarity.io, Inc.
 *
 * Entity dispatch layer. Routes each entity to the correct API flow:
 *
 *   CVE        → Spotlight filter: cve.id:'CVE-xxxx'
 *   hostname   → Devices API (hostname → AID) → Spotlight filter: aid:'<id>'
 *   AID (32-hex) → Spotlight filter: aid:'<id>'
 *
 * For CVE lookups: returns one result object containing all affected hosts.
 * For hostname/AID lookups: returns one result object containing all open CVEs for that host.
 */
const { getLogger } = require('./logger');
const querySpotlight = require('./querySpotlight');
const resolveHostnameToAid = require('./resolveHostnameToAid');
const getInstalledPatches = require('./getInstalledPatches');
const { transformVulnerability, transformPatch, buildSummary } = require('./dataTransformations');

const getLookupResults = async (entities, options, Logger) => {
  return Promise.all(entities.map((entity) => lookupEntity(entity, options)));
};

const lookupEntity = async (entity, options) => {
  const Logger = getLogger();
  const { type, types, value } = entity;

  // Determine the entity subtype
  const isCve = type === 'cve';
  const isAid = !isCve && Array.isArray(types) && types.includes('custom.crowdstrikeAid');
  const isHostname = !isCve && !isAid && Array.isArray(types) && types.includes('custom.hostname');

  Logger.debug({ value, type, isCve, isAid, isHostname }, 'CS Exposure entity dispatch');

  let filter;
  let resolvedAid = null;

  if (isCve) {
    filter = `cve.id:'${value.toUpperCase()}'`;
  } else if (isAid) {
    resolvedAid = value.toLowerCase();
    filter = `aid:'${resolvedAid}'`;
  } else if (isHostname) {
    resolvedAid = await resolveHostnameToAid(value, options);
    if (!resolvedAid) {
      Logger.debug({ value }, 'Hostname not found in CrowdStrike — no result');
      return { entity, data: null };
    }
    filter = `aid:'${resolvedAid}'`;
  } else {
    Logger.debug({ value, type }, 'Unrecognized entity type — skipping');
    return { entity, data: null };
  }

  const rawVulns = await querySpotlight(filter, options);

  if (!rawVulns || rawVulns.length === 0) {
    Logger.debug({ value, filter }, 'No vulnerability records found');
    return { entity, data: null };
  }

  const entityType = isCve ? 'cve' : isAid ? 'crowdstrikeAid' : 'hostname';
  const vulns = rawVulns.map((v) => transformVulnerability(v, options.uiUrl));

  // Fetch installed patches for host-based lookups (AID or hostname)
  let patches = [];
  if (!isCve && options.enablePatches && resolvedAid) {
    try {
      const rawPatches = await getInstalledPatches(resolvedAid, options);
      patches = rawPatches.map(transformPatch);
    } catch (err) {
      // Patch data is optional — log and continue rather than failing the lookup
      Logger.warn({ err, aid: resolvedAid }, 'Failed to fetch installed patches (non-fatal)');
    }
  }

  return {
    entity,
    data: {
      summary: buildSummary(vulns, entityType),
      details: {
        entityType,
        entityValue: value,
        resolvedAid,
        vulns,
        patches,
        totalVulns: vulns.length,
        openVulns: vulns.filter((v) => v.status === 'open').length,
        enableEvalLogic: options.enableEvalLogic,
        enablePatches: options.enablePatches
      }
    }
  };
};

module.exports = { getLookupResults };
