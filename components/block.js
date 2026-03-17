polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),

  // ── Entity type helpers ───────────────────────────────────────────────
  isCveLookup: Ember.computed('details.entityType', function () {
    return this.get('details.entityType') === 'cve';
  }),

  isHostLookup: Ember.computed('details.entityType', function () {
    const t = this.get('details.entityType');
    return t === 'hostname' || t === 'crowdstrikeAid';
  }),

  // ── List guards ───────────────────────────────────────────────────────
  hasVulns: Ember.computed('details.vulns', function () {
    const v = this.get('details.vulns');
    return v && v.length > 0;
  }),

  hasPatches: Ember.computed('details.patches', function () {
    const p = this.get('details.patches');
    return p && p.length > 0;
  }),

  // ── First vuln shortcut (for CVE lookups — CVE metadata is identical across rows) ──
  firstVuln: Ember.computed('details.vulns', function () {
    const v = this.get('details.vulns');
    return v && v.length > 0 ? v[0] : null;
  }),

  // ── Severity class ────────────────────────────────────────────────────
  severityClass: Ember.computed('firstVuln.severity', function () {
    const s = this.get('firstVuln.severity') || '';
    return 'csem-severity-' + s.toLowerCase();
  }),

  // ── Status class ──────────────────────────────────────────────────────
  statusClass: Ember.computed('firstVuln.status', function () {
    const s = this.get('firstVuln.status') || '';
    return 'csem-status-' + s.toLowerCase().replace(/\s+/g, '-');
  }),

  // ── CISA KEV class (isCisaKev is now a boolean) ──────────────────────
  kevClass: Ember.computed('firstVuln.isCisaKev', function () {
    return this.get('firstVuln.isCisaKev') === true ? 'csem-kev-yes' : 'csem-kev-no';
  }),

  kevLabel: Ember.computed('firstVuln.isCisaKev', function () {
    return this.get('firstVuln.isCisaKev') === true ? 'CISA KEV' : 'Not KEV';
  }),

  // ── Deep links ────────────────────────────────────────────────────────
  deepLinkCve: Ember.computed('firstVuln.deepLinks.cve', function () {
    return this.get('firstVuln.deepLinks.cve');
  }),

  deepLinkHost: Ember.computed('firstVuln.deepLinks.host', function () {
    return this.get('firstVuln.deepLinks.host');
  }),

  // ── List guards ─────────────────────────────────────────────────────
  hasGroups: Ember.computed('firstVuln.groups', function () {
    const g = this.get('firstVuln.groups');
    return g && g.length > 0;
  }),

  hasCwes: Ember.computed('firstVuln.cwes', function () {
    const c = this.get('firstVuln.cwes');
    return c && c.length > 0;
  }),

  hasRemediations: Ember.computed('firstVuln.remediations', function () {
    const r = this.get('firstVuln.remediations');
    return r && r.length > 0;
  }),

  hasEvalLogic: Ember.computed('firstVuln.evaluationLogic', function () {
    const e = this.get('firstVuln.evaluationLogic');
    return e && e.length > 0;
  }),

  // ── Collapsible section initialization ───────────────────────────────
  init() {
    this._super(...arguments);
    if (!this.get('block._state')) {
      this.set('block._state', {
        showHosts: false,
        showCves: false,
        showRemediation: false,
        showEvalLogic: false,
        showPatches: false
      });
    }
  },

  actions: {
    toggleSection(section) {
      const key = `block._state.show${section}`;
      this.set(key, !this.get(key));
    }
  }
});
