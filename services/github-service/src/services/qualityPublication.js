const release = require('../quality-release.json');

function remediationPublicationReady() {
  return release.schema_version === 'v1' && release.remediation_release_verified === true;
}

function assertRemediationPublicationReady() {
  if (!remediationPublicationReady()) {
    const error = new Error('Remediation publication requires independently verified release evidence');
    error.statusCode = 422;
    error.code = 'REMEDIATION_RELEASE_EVIDENCE_MISSING';
    throw error;
  }
}

function assertReviewBodyReady(body) {
  const text = String(body || '');
  const suggestion = /```suggestion(?:\s|$)/i.test(text);
  // A model-generated Tier 3 snippet is advisory. Only the remediation pipeline
  // may call the dedicated publishFindingFixSections operation after per-candidate
  // sandbox verification. Generic review/comment operations never carry suggestion
  // blocks, even if untrusted text spoofs a candidate marker. Keep this invariant
  // at the final GitHub write boundary so a broad release flag cannot promote prose.
  if (suggestion) {
    const error = new Error('GitHub suggestions require a sandbox-verified remediation candidate');
    error.statusCode = 422;
    error.code = 'UNVERIFIED_SUGGESTION_PROHIBITED';
    throw error;
  }
  if (/(?:<!--\s*mitig8it-fix:|\*\*(?:Recommended|Suggested) fix)/i.test(text)) {
    assertRemediationPublicationReady();
  }
}

module.exports = { remediationPublicationReady, assertRemediationPublicationReady, assertReviewBodyReady };
