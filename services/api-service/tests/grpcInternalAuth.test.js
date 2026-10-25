const grpc = require('@grpc/grpc-js');
const { AnalysisGrpcClient } = require('../src/clients/analysisGrpcClient');
const { GitHubGrpcClient } = require('../src/clients/githubGrpcClient');
const { AnalysisServiceService } = require('../src/grpc/generated/analysis_grpc_pb');
const { GitHubServiceService } = require('../src/grpc/generated/github_grpc_pb');
const requestContext = require('../src/utils/requestContext');

const originalEnv = {};
const envKeys = ['GITHUB_SERVICE_INTERNAL_SECRET', 'ANALYSIS_SERVICE_INTERNAL_SECRET', 'GRPC_TRANSPORT_TLS'];
const received = [];
let server;
let analysis;
let github;

beforeAll(async () => {
  for (const name of envKeys) originalEnv[name] = process.env[name];
  process.env.GRPC_TRANSPORT_TLS = 'false';
  server = new grpc.Server();
  for (const service of [AnalysisServiceService, GitHubServiceService]) {
    server.addService(service, Object.fromEntries(Object.entries(service).map(([method, definition]) => [
      method,
      (call, callback) => {
        received.push({ method, metadata: call.metadata });
        callback(null, definition.responseDeserialize(Buffer.alloc(0)));
      },
    ])));
  }
  const port = await new Promise((resolve, reject) => {
    server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (error, boundPort) => {
      if (error) reject(error);
      else resolve(boundPort);
    });
  });
  analysis = new AnalysisGrpcClient(`127.0.0.1:${port}`);
  github = new GitHubGrpcClient(`127.0.0.1:${port}`);
});

beforeEach(() => {
  received.length = 0;
  process.env.GITHUB_SERVICE_INTERNAL_SECRET = 'github-secret';
  process.env.ANALYSIS_SERVICE_INTERNAL_SECRET = 'analysis-secret';
});

afterAll(async () => {
  for (const name of envKeys) {
    if (originalEnv[name] === undefined) delete process.env[name];
    else process.env[name] = originalEnv[name];
  }
  analysis?.client.close();
  github?.client.close();
  if (server) await new Promise((resolve) => server.tryShutdown(resolve));
});

test.each(['analyzePullRequest', 'analyzeTier1', 'analyzeTier2', 'triageFindings', 'healthCheck'])(
  'analysis %s sends its secret and correlation over the wire', async (method) => {
    await requestContext.runWith({ delivery_id: 'client-delivery' }, () => analysis[method]({}));
    expect(received).toHaveLength(1);
    expect(received[0].metadata.get('x-internal-secret')).toEqual(['analysis-secret']);
    expect(received[0].metadata.get('x-github-delivery')).toEqual(['client-delivery']);
  }
);

test.each(['fetchPullRequestFiles', 'fetchFileContents', 'submitPullRequestReview', 'postInlineComment',
  'retireInlineComments', 'createCheckRun', 'snapshotRemediation', 'createRemediationCheckRun',
  'publishRemediationComment', 'publishFindingFixSections', 'healthCheck'])(
  'github %s sends the shared secret over the wire', async (method) => {
    await github[method]({});
    expect(received).toHaveLength(1);
    expect(received[0].metadata.get('x-internal-secret')).toEqual(['github-secret']);
  }
);

test('analysis falls back to the shared secret when its override is absent', async () => {
  delete process.env.ANALYSIS_SERVICE_INTERNAL_SECRET;
  await analysis.analyzeTier1({});
  expect(received[0].metadata.get('x-internal-secret')).toEqual(['github-secret']);
});

test('a missing analysis credential rejects locally before making a request', async () => {
  delete process.env.ANALYSIS_SERVICE_INTERNAL_SECRET;
  delete process.env.GITHUB_SERVICE_INTERNAL_SECRET;
  await expect(analysis.analyzeTier1({})).rejects.toThrow('Internal service auth is not configured');
  expect(received).toHaveLength(0);
});

test('a missing GitHub credential rejects locally before making a request', async () => {
  delete process.env.GITHUB_SERVICE_INTERNAL_SECRET;
  await expect(github.fetchPullRequestFiles({})).rejects.toThrow('Internal service auth is not configured');
  expect(received).toHaveLength(0);
});

test.each(['secret-with-newline\n', 'non-ascii-secret-\u00e9'])(
  'invalid metadata credentials fail without exposing the value', async (value) => {
    process.env.GITHUB_SERVICE_INTERNAL_SECRET = value;
    await expect(github.fetchPullRequestFiles({})).rejects.toThrow(
      'Internal service auth must use printable ASCII characters'
    );
    expect(received).toHaveLength(0);
  }
);
