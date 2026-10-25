const request = require('supertest');

const mockAnalysisHealthCheck = jest.fn();
const mockGithubHealthCheck = jest.fn();
const mockAnalysisClose = jest.fn();
const mockGithubClose = jest.fn();

jest.mock('../src/clients/analysisGrpcClient', () => ({
  AnalysisGrpcClient: jest.fn().mockImplementation(() => ({
    healthCheck: mockAnalysisHealthCheck,
    client: { close: mockAnalysisClose },
  })),
}));

jest.mock('../src/clients/githubGrpcClient', () => ({
  GitHubGrpcClient: jest.fn().mockImplementation(() => ({
    healthCheck: mockGithubHealthCheck,
    client: { close: mockGithubClose },
  })),
}));

const { createApp } = require('../src/app');

describe('internal dependency readiness', () => {
  const originalSecret = process.env.GITHUB_SERVICE_INTERNAL_SECRET;

  beforeEach(() => {
    jest.clearAllMocks();
    process.env.GITHUB_SERVICE_INTERNAL_SECRET = 'test-internal-secret';
    mockAnalysisHealthCheck.mockResolvedValue({ status: 'ok', service: 'analysis-service' });
    mockGithubHealthCheck.mockResolvedValue({ status: 'ok', service: 'github-service' });
  });

  afterAll(() => {
    if (originalSecret === undefined) delete process.env.GITHUB_SERVICE_INTERNAL_SECRET;
    else process.env.GITHUB_SERVICE_INTERNAL_SECRET = originalSecret;
  });

  test('requires internal authentication before probing dependencies', async () => {
    const response = await request(createApp()).get('/internal/dependencies');

    expect(response.status).toBe(401);
    expect(mockAnalysisHealthCheck).not.toHaveBeenCalled();
    expect(mockGithubHealthCheck).not.toHaveBeenCalled();
  });

  test('reports ready only after both authenticated application RPCs pass', async () => {
    const response = await request(createApp())
      .get('/internal/dependencies')
      .set('x-internal-secret', 'test-internal-secret');

    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      status: 'ok',
      service: 'mitig8it-api',
      checks: { analysis: 'ok', github: 'ok' },
    });
    expect(mockAnalysisClose).toHaveBeenCalledTimes(1);
    expect(mockGithubClose).toHaveBeenCalledTimes(1);
  });

  test('fails closed without leaking a dependency error', async () => {
    mockAnalysisHealthCheck.mockRejectedValueOnce(new Error('secret or provider detail'));

    const response = await request(createApp())
      .get('/internal/dependencies')
      .set('x-internal-secret', 'test-internal-secret');

    expect(response.status).toBe(503);
    expect(response.body).toEqual({
      status: 'error',
      service: 'mitig8it-api',
      checks: { analysis: 'error', github: 'ok' },
    });
    expect(JSON.stringify(response.body)).not.toContain('secret or provider detail');
  });
});
