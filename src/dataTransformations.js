/*
 * Copyright (c) 2024, Polarity.io, Inc.
 */

/**
 * Formats an ISO8601 date string to YYYY-MM-DD.
 * Returns 'N/A' if the value is null/undefined/invalid.
 */
const formatDate = (value) => {
  if (!value) return 'N/A';
  try {
    return new Date(value).toISOString().split('T')[0];
  } catch (_) {
    return value;
  }
};

/**
 * Normalizes a severity string to Title Case.
 * e.g. "HIGH" → "High", "CRITICAL" → "Critical"
 */
const normalizeSeverity = (value) => {
  if (!value) return 'N/A';
  return value.charAt(0).toUpperCase() + value.slice(1).toLowerCase();
};

/**
 * Maps a raw Spotlight vulnerability resource to a display-ready object.
 *
 * Field paths confirmed against live CrowdStrike Spotlight API (CVE-2022-38023):
 *   - apps[].product_name_version / vendor_normalized / sub_status (NOT name/version/vendor)
 *   - apps[].evaluation_logic.simplified_logic[] (NOT top-level evaluation_logic)
 *   - host_info.groups[] — Falcon host group memberships (live, not in spec)
 *   - host_info.service_provider / managed_by / internet_exposure — cloud/mgmt metadata
 *   - cve.exprt_rating — CrowdStrike ExPRT rating (separate from CVSSv3 severity)
 *   - cve.vector / exploitability_score / impact_score / cwes[] — full CVSS fields
 *   - remediation.entities[].action / link — full action text and KB URL
 *
 * @param {Object} raw - Raw vulnerability resource from /spotlight/combined/vulnerabilities/v1
 * @param {string} uiUrl - CrowdStrike Falcon UI base URL for deep links
 */
const transformVulnerability = (raw, uiUrl = 'https://falcon.crowdstrike.com') => {
  if (!raw) return null;

  const cve = raw.cve || {};
  const hostInfo = raw.host_info || {};
  const remediation = raw.remediation || {};
  const apps = Array.isArray(raw.apps) ? raw.apps : [];

  // Collect simplified_logic entries across all apps (most useful eval logic format)
  const evaluationLogic = apps.flatMap((a) => {
    const simplified = a.evaluation_logic && Array.isArray(a.evaluation_logic.simplified_logic)
      ? a.evaluation_logic.simplified_logic
      : [];
    return simplified.map((l) => ({
      title: l.title || 'N/A',
      checks: l.checks || null,
      matchRequired: l.match_required || null,
      found: Array.isArray(l.found) ? l.found : [],
      data: Array.isArray(l.data) ? l.data : []
    }));
  });

  return {
    // Vulnerability identity
    id: raw.id || 'N/A',
    aid: raw.aid || null,
    status: raw.status || 'N/A',
    confidence: raw.confidence || 'N/A',
    createdDate: formatDate(raw.created_timestamp),
    updatedDate: formatDate(raw.updated_timestamp),

    // CVE fields (confirmed live)
    cveId: cve.id || 'N/A',
    severity: normalizeSeverity(cve.severity),        // CVSSv3 severity: HIGH, CRITICAL, etc.
    exprtRating: normalizeSeverity(cve.exprt_rating), // CrowdStrike ExPRT rating (often higher)
    baseScore: cve.base_score != null ? cve.base_score : 'N/A',
    exploitabilityScore: cve.exploitability_score != null ? cve.exploitability_score : 'N/A',
    impactScore: cve.impact_score != null ? cve.impact_score : 'N/A',
    exploitStatus: cve.exploit_status != null ? cve.exploit_status : 'N/A',
    remediationLevel: cve.remediation_level || 'N/A',
    cveVector: cve.vector || null,
    cwes: Array.isArray(cve.cwes) ? cve.cwes : [],
    publishedDate: formatDate(cve.published_date),
    spotlightDate: formatDate(cve.spotlight_published_date),
    isCisaKev: cve.cisa_info ? cve.cisa_info.is_cisa_kev === true : false,
    cveDescription: (cve.description || '').trim() || null,
    vendorAdvisory: Array.isArray(cve.vendor_advisory) ? cve.vendor_advisory[0] : null,

    // Host info (confirmed live — host_info facet required)
    hostname: hostInfo.hostname || 'N/A',
    localIp: hostInfo.local_ip || 'N/A',
    machineDomain: hostInfo.machine_domain || null,
    osVersion: hostInfo.os_version || 'N/A',
    osBuild: hostInfo.os_build || null,
    platform: hostInfo.platform || 'N/A',
    productType: hostInfo.product_type_desc || 'N/A',
    assetCriticality: hostInfo.asset_criticality || 'Unassigned',
    internetExposure: hostInfo.internet_exposure || 'N/A',
    serviceProvider: hostInfo.service_provider || null,   // e.g. "AWS", "Azure"
    managedBy: hostInfo.managed_by || null,
    groups: Array.isArray(hostInfo.groups)
      ? hostInfo.groups.map((g) => g.name).filter(Boolean)
      : [],
    tags: Array.isArray(hostInfo.tags) ? hostInfo.tags : [],

    // Affected apps (confirmed live — field names differ from spec)
    apps: apps.map((a) => ({
      productName: a.product_name_version || a.product_name_normalized || 'Unknown',
      vendor: a.vendor_normalized || 'N/A',
      subStatus: a.sub_status || 'N/A',
      patchDate: formatDate(a.patch_publication_date)
    })),

    // Remediation (confirmed live — remediation facet required)
    remediations: Array.isArray(remediation.entities)
      ? remediation.entities.map((r) => ({
          title: r.title || 'N/A',
          reference: r.reference || null,   // KB article number, e.g. "KB5078766"
          action: r.action || null,          // Full action description
          link: r.link || null,              // Direct KB catalog link
          recommendationType: r.recommendation_type || null,  // "recommended" | "minimum"
          patchDate: formatDate(r.patch_publication_date)
        }))
      : [],

    // Evaluation logic — flattened simplified_logic from all apps[] entries
    evaluationLogic,

    // Deep links into Falcon UI
    deepLinks: {
      host: raw.aid ? `${uiUrl}/investigate/hosts/${raw.aid}/summary` : null,
      cve: cve.id ? `${uiUrl}/spotlight/vulnerabilities?filter=cve.id:'${cve.id}'` : null,
      advisory: cve.id && Array.isArray(cve.vendor_advisory) ? cve.vendor_advisory[0] : null
    }
  };
};

/**
 * Transforms an installed patch record from /spotlight/combined/installed-patches/v1
 *
 * @param {Object} raw - Raw patch resource
 */
const transformPatch = (raw) => {
  if (!raw) return null;
  return {
    aid: raw.aid || null,
    hostname: raw.hostname || 'N/A',
    activePatchCount: raw.active_patches != null ? raw.active_patches : 'N/A',
    pendingPatchCount: raw.pending_patches != null ? raw.pending_patches : 'N/A',
    rebootRequired: raw.reboot_required ? 'Yes' : 'No',
    lastPatchConfirmed: formatDate(raw.last_patch_confirmed),
    patches: Array.isArray(raw.installed_patches)
      ? raw.installed_patches.map((p) => ({
          description: p.description || 'N/A',
          type: p.type || 'N/A',
          status: p.status || 'N/A',
          publishedDate: formatDate(p.published_date)
        }))
      : []
  };
};

/**
 * Builds the summary tags for the Polarity overlay header.
 *
 * @param {Array} vulns - Transformed vulnerability objects
 * @param {string} entityType - 'cve' | 'hostname' | 'crowdstrikeAid'
 */
const buildSummary = (vulns, entityType) => {
  const tags = [];
  if (!vulns || vulns.length === 0) return ['No exposure data'];

  if (entityType === 'cve') {
    // For CVE lookups: show ExPRT rating (CS native), CVSS score, and exposed host count
    const first = vulns[0];
    if (first.exprtRating && first.exprtRating !== 'N/A') tags.push(first.exprtRating);
    if (first.baseScore !== 'N/A') tags.push(`CVSS: ${first.baseScore}`);
    if (first.isCisaKev) tags.push('CISA KEV');
    tags.push(`${vulns.length} Host${vulns.length !== 1 ? 's' : ''} Exposed`);
  } else {
    // For hostname/AID lookups: show count of open vulns and highest severity
    const openVulns = vulns.filter((v) => v.status === 'open');
    const severityOrder = ['Critical', 'High', 'Medium', 'Low'];
    const highestSeverity = severityOrder.find((s) =>
      vulns.some((v) => v.exprtRating === s || v.severity === s)
    );
    if (highestSeverity) tags.push(highestSeverity);
    tags.push(`${openVulns.length} Open CVE${openVulns.length !== 1 ? 's' : ''}`);
    if (vulns.length > openVulns.length) tags.push(`${vulns.length} Total`);
  }

  return tags;
};

module.exports = {
  transformVulnerability,
  transformPatch,
  buildSummary,
  formatDate,
  normalizeSeverity
};
