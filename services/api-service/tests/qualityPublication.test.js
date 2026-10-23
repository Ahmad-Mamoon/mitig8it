const policy = require('../src/services/remediationPolicy');

test('feature and development flags cannot enable publication without release evidence', () => {
  const flags = {
    REMEDIATION_ENABLED: 'true', REMEDIATION_GENERATE_ENABLED: 'true', REMEDIATION_PUBLISH_ENABLED: 'true',
    REMEDIATION_SERVICE_URL: 'http://repair', REMEDIATION_SERVICE_INTERNAL_SECRET: 'fixture',
    GITHUB_SERVICE_URL: 'http://github', GITHUB_SERVICE_INTERNAL_SECRET: 'fixture',
    REMEDIATION_SANDBOX_IMAGE_DIGEST: 'sha256:fixture', REMEDIATION_INPUT_USD_PER_MILLION_TOKENS: '1',
    REMEDIATION_OUTPUT_USD_PER_MILLION_TOKENS: '1', REMEDIATION_ALLOW_DEVELOPMENT_VERIFICATION: 'true',
    REMEDIATION_ALLOW_STATIC_ASSERTION_VERIFICATION: 'true', REMEDIATION_ALLOW_ISOLATED_JOB_VERIFICATION: 'true',
  };
  const saved = Object.fromEntries(Object.keys(flags).map((key) => [key, process.env[key]]));
  try {
    Object.assign(process.env, flags);
    expect(policy.getPolicy().repair_service_configured).toBe(true);
    expect(policy.capabilities()).toEqual({ generate: true, publish: false, auto_generate: false });
    expect(policy.capabilityReport().publish).toEqual({ enabled: false, reason: 'release_evidence_missing' });
    expect(policy.capabilityReport().release_evidence_ready).toBe(false);
    expect(() => policy.assertPublishEnabled()).toThrow(/not enabled/);
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
});
