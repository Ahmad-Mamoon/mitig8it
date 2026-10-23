const {
  selectFilesToFetch,
  buildDeterministicProfile,
  detectLanguages,
  detectFramework,
  detectSecurityLibs,
  parseDependencies,
  validateInterpretation,
  interpretWithLLM,
  redactRepositoryContent,
  llmProfilingEnabled,
  FILE_MAX_RESPONSE_BYTES,
  TREE_MAX_RESPONSE_BYTES,
  GITHUB_RATE_LIMIT_WARN_THRESHOLD,
} = require('../src/services/repoProfiler');

describe('repoProfiler — file selection', () => {
  const makeTree = (paths) => paths.map((p) => ({ path: p, type: 'blob' }));

  test('always fetches package.json', () => {
    const tree = makeTree(['package.json', 'src/index.js']);
    const selected = selectFilesToFetch(tree);
    expect(selected.map((f) => f.path)).toContain('package.json');
  });

  test('always fetches requirements.txt', () => {
    const tree = makeTree(['requirements.txt', 'app.py']);
    const selected = selectFilesToFetch(tree);
    expect(selected.map((f) => f.path)).toContain('requirements.txt');
  });

  test('fetches security-relevant files', () => {
    const tree = makeTree(['package.json', 'middleware/auth.js', 'src/index.js', 'db/queries.js']);
    const selected = selectFilesToFetch(tree);
    const paths = selected.map((f) => f.path);
    expect(paths).toContain('middleware/auth.js');
    expect(paths).toContain('db/queries.js');
  });

  test('ignores node_modules', () => {
    const tree = makeTree(['node_modules/express/package.json', 'package.json']);
    const selected = selectFilesToFetch(tree);
    expect(selected.map((f) => f.path)).not.toContain('node_modules/express/package.json');
  });

  test('ignores dist and build directories', () => {
    const tree = makeTree(['dist/bundle.js', 'build/output.js', 'src/index.js']);
    const selected = selectFilesToFetch(tree);
    expect(selected.map((f) => f.path)).not.toContain('dist/bundle.js');
    expect(selected.map((f) => f.path)).not.toContain('build/output.js');
  });

  test('caps at 15 files', () => {
    const paths = Array.from({ length: 30 }, (_, i) => `middleware/handler${i}.js`);
    paths.push('package.json');
    const tree = makeTree(paths);
    const selected = selectFilesToFetch(tree);
    expect(selected.length).toBeLessThanOrEqual(15);
  });

  test('skips non-blob entries', () => {
    const tree = [
      { path: 'src', type: 'tree' },
      { path: 'src/index.js', type: 'blob' },
    ];
    const selected = selectFilesToFetch(tree);
    expect(selected).toHaveLength(0); // index.js doesn't match any fetch pattern
  });
});

describe('repoProfiler — language detection', () => {
  const makeTree = (paths) => paths.map((p) => ({ path: p, type: 'blob' }));

  test('detects javascript and typescript', () => {
    const tree = makeTree(['src/app.js', 'src/utils.ts', 'src/component.tsx']);
    const langs = detectLanguages(tree);
    expect(langs).toContain('javascript');
    expect(langs).toContain('typescript');
  });

  test('detects python', () => {
    const tree = makeTree(['app.py', 'utils.py', 'tests/test_app.py']);
    const langs = detectLanguages(tree);
    expect(langs[0]).toBe('python');
  });

  test('sorts by frequency', () => {
    const tree = makeTree(['a.py', 'b.py', 'c.py', 'd.js']);
    const langs = detectLanguages(tree);
    expect(langs[0]).toBe('python');
    expect(langs[1]).toBe('javascript');
  });
});

describe('repoProfiler — dependency parsing', () => {
  test('parses package.json dependencies', () => {
    const content = JSON.stringify({
      dependencies: { express: '^4.18.0', pg: '^8.11.0' },
      devDependencies: { jest: '^29.0.0' },
    });
    const { deps, devDeps } = parseDependencies('package.json', content);
    expect(deps.express).toBe('^4.18.0');
    expect(deps.pg).toBe('^8.11.0');
    expect(devDeps).toContain('jest');
  });

  test('parses requirements.txt', () => {
    const content = 'flask==2.3.0\nrequests>=2.28\nsqlalchemy';
    const { deps } = parseDependencies('requirements.txt', content);
    expect(deps.flask).toBe('*');
    expect(deps.requests).toBe('*');
    expect(deps.sqlalchemy).toBe('*');
  });

  test('parses go.mod', () => {
    const content = 'module example.com/app\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n)';
    const { deps } = parseDependencies('go.mod', content);
    expect(deps['github.com/gin-gonic/gin']).toBe('*');
  });

  test('handles malformed package.json', () => {
    const { deps } = parseDependencies('package.json', 'not json');
    expect(deps).toEqual({});
  });

  test('returns empty for unknown file', () => {
    const { deps } = parseDependencies('Makefile', 'stuff');
    expect(deps).toEqual({});
  });
});

describe('repoProfiler — framework detection', () => {
  test('detects express', () => {
    expect(detectFramework({ express: '^4.18.0' })).toBe('express');
  });

  test('detects flask', () => {
    expect(detectFramework({ flask: '*' })).toBe('flask');
  });

  test('detects django', () => {
    expect(detectFramework({ django: '*' })).toBe('django');
  });

  test('returns null for unknown', () => {
    expect(detectFramework({ lodash: '*' })).toBeNull();
  });
});

describe('repoProfiler — security library detection', () => {
  test('detects helmet and bcrypt', () => {
    const libs = detectSecurityLibs({ helmet: '^7.0.0', bcrypt: '^5.0.0', lodash: '^4.17.0' });
    expect(libs).toHaveLength(2);
    expect(libs.map((l) => l.library)).toContain('helmet');
    expect(libs.map((l) => l.library)).toContain('bcrypt');
  });

  test('returns empty when no security libs', () => {
    const libs = detectSecurityLibs({ lodash: '*', moment: '*' });
    expect(libs).toHaveLength(0);
  });
});

describe('repoProfiler — deterministic profile', () => {
  const makeTree = (paths) => paths.map((p) => ({ path: p, type: 'blob' }));

  test('builds complete profile from package.json', () => {
    const tree = makeTree(['package.json', 'src/index.js', 'middleware/auth.js', 'package-lock.json']);
    const fileContents = {
      'package.json': JSON.stringify({
        dependencies: { express: '^4.18.0', pg: '^8.11.0', helmet: '^7.0.0', jsonwebtoken: '^9.0.0' },
      }),
    };
    const profile = buildDeterministicProfile(tree, fileContents);

    expect(profile.framework).toBe('express');
    expect(profile.database.driver).toBe('pg');
    expect(profile.package_manager).toBe('npm');
    expect(profile.has_lockfile).toBe(true);
    expect(profile.security_libraries.map((l) => l.library)).toContain('helmet');
    expect(profile.security_libraries.map((l) => l.library)).toContain('jsonwebtoken');
    expect(profile.languages).toContain('javascript');
  });
});

describe('repoProfiler — LLM validation', () => {
  const originalEnv = Object.fromEntries([
    'REPO_PROFILER_LLM_ENABLED', 'REPO_PROFILER_ALLOW_SOURCE_EXPORT',
    'REPO_PROFILER_LLM_MODEL', 'OPENAI_API_KEY',
  ].map((key) => [key, process.env[key]]));

  afterEach(() => {
    for (const [key, value] of Object.entries(originalEnv)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  test('an API key alone cannot export repository source', async () => {
    process.env.OPENAI_API_KEY = 'test-only-key';
    const result = await interpretWithLLM({ languages: [], security_libraries: [], directory_structure: {} }, {
      'src/auth.js': 'const password = "must-not-leave";',
    });
    expect(result.interpretation).toBeNull();
    expect(result.reason).toMatch(/not explicitly enabled/);
  });

  test('explicit source consent still requires an explicit model', async () => {
    process.env.OPENAI_API_KEY = 'test-only-key';
    process.env.REPO_PROFILER_LLM_ENABLED = 'true';
    process.env.REPO_PROFILER_ALLOW_SOURCE_EXPORT = 'true';
    const result = await interpretWithLLM({ languages: [], security_libraries: [], directory_structure: {} }, {});
    expect(result.interpretation).toBeNull();
    expect(result.reason).toMatch(/MODEL not set/);
  });

  test('repository source export requires two explicit opt-ins', () => {
    process.env.REPO_PROFILER_LLM_ENABLED = 'true';
    expect(llmProfilingEnabled()).toBe(false);
    process.env.REPO_PROFILER_ALLOW_SOURCE_EXPORT = 'true';
    expect(llmProfilingEnabled()).toBe(true);
  });

  test('redacts credentials without mutating the input or changing line count', () => {
    const source = [
      'api_key = "sk-examplecredential123456"',
      'Authorization: Bearer bearer-value-12345',
      'DATABASE_URL="postgres://user:database-password@example.test/db"',
      'const password = `super-secret-password`;',
    ].join('\n');
    const redacted = redactRepositoryContent(source);
    expect(redacted).not.toContain('examplecredential123456');
    expect(redacted).not.toContain('bearer-value-12345');
    expect(redacted).not.toContain('database-password');
    expect(redacted).not.toContain('super-secret-password');
    expect(redacted).toContain('[REDACTED_SECRET]');
    expect(redacted.split('\n')).toHaveLength(source.split('\n').length);
    expect(source).toContain('super-secret-password');
  });

  test('redacts multiline private keys while preserving line structure', () => {
    const source = 'before\n-----BEGIN PRIVATE KEY-----\nabc123\ndef456\n-----END PRIVATE KEY-----\nafter';
    const redacted = redactRepositoryContent(source);
    expect(redacted).not.toContain('abc123');
    expect(redacted).not.toContain('def456');
    expect(redacted.split('\n')).toHaveLength(source.split('\n').length);
  });

  test('passes through valid interpretation', () => {
    const deterministic = {
      security_libraries: [{ library: 'helmet', purpose: 'security headers' }],
    };
    const interpreted = {
      auth_strategy: 'jwt_middleware',
      database_pattern: 'parameterized',
      security_posture: ['helmet headers', 'parameterized queries'],
      risk_areas: ['db/legacy.js'],
    };
    const result = validateInterpretation(deterministic, interpreted);
    expect(result.auth_strategy).toBe('jwt_middleware');
    expect(result.security_posture).toHaveLength(2);
  });

  test('returns null for null interpretation', () => {
    expect(validateInterpretation({}, null)).toBeNull();
  });

  test('ensures arrays exist even if missing', () => {
    const result = validateInterpretation({ security_libraries: [] }, { auth_strategy: 'unknown' });
    expect(Array.isArray(result.security_posture)).toBe(true);
    expect(Array.isArray(result.risk_areas)).toBe(true);
  });
});

describe('repoProfiler — response limits', () => {
  test('uses a larger cap for repository tree fetches than file fetches', () => {
    expect(TREE_MAX_RESPONSE_BYTES).toBeGreaterThan(FILE_MAX_RESPONSE_BYTES);
  });

  test('warn threshold is lower than the old hard failure threshold', () => {
    expect(GITHUB_RATE_LIMIT_WARN_THRESHOLD).toBeLessThan(100);
    expect(GITHUB_RATE_LIMIT_WARN_THRESHOLD).toBeGreaterThan(0);
  });
});
