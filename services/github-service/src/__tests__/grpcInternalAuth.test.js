const grpc = require('@grpc/grpc-js');

jest.mock('../services/githubInternalOperations', () => ({
  fetchPullRequestFiles: jest.fn(async () => ({ files: [] })),
}));

const operations = require('../services/githubInternalOperations');
const { createServer } = require('../github_grpc_server');
const { GitHubServiceClient, GitHubServiceService } = require('../grpc/generated/github_grpc_pb');
const requestContext = require('../utils/requestContext');

const secret = 'grpc-internal-test-secret';
let server;
let client;
let originalSecret;
let port;

function call(method, metadata = new grpc.Metadata()) {
  const request = GitHubServiceService[method].requestDeserialize(Buffer.alloc(0));
  return new Promise((resolve, reject) => {
    client[method](request, metadata, { deadline: Date.now() + 3000 }, (error, response) => {
      if (error) reject(error);
      else resolve(response);
    });
  });
}

beforeAll(async () => {
  originalSecret = process.env.GITHUB_SERVICE_INTERNAL_SECRET;
  server = createServer();
  port = await new Promise((resolve, reject) => {
    server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (error, boundPort) => {
      if (error) reject(error);
      else resolve(boundPort);
    });
  });
  client = new GitHubServiceClient(`127.0.0.1:${port}`, grpc.credentials.createInsecure());
});

beforeEach(() => {
  jest.clearAllMocks();
  process.env.GITHUB_SERVICE_INTERNAL_SECRET = secret;
});

afterAll(async () => {
  if (originalSecret === undefined) delete process.env.GITHUB_SERVICE_INTERNAL_SECRET;
  else process.env.GITHUB_SERVICE_INTERNAL_SECRET = originalSecret;
  client?.close();
  if (server) await new Promise((resolve) => server.tryShutdown(resolve));
});

test.each(Object.keys(GitHubServiceService))('%s denies a caller without the secret', async (method) => {
  await expect(call(method)).rejects.toMatchObject({ code: grpc.status.UNAUTHENTICATED });
  expect(operations.fetchPullRequestFiles).not.toHaveBeenCalled();
});

test.each(['wrong-secret', secret.slice(0, -1), `${secret}x`])('rejects invalid secret %s', async (value) => {
  const metadata = new grpc.Metadata();
  metadata.set('x-internal-secret', value);
  await expect(call('fetchPullRequestFiles', metadata)).rejects.toMatchObject({
    code: grpc.status.UNAUTHENTICATED,
  });
  expect(operations.fetchPullRequestFiles).not.toHaveBeenCalled();
});

test('duplicate secrets are rejected rather than choosing a credential', async () => {
  const metadata = new grpc.Metadata();
  metadata.add('x-internal-secret', secret);
  metadata.add('x-internal-secret', secret);
  await expect(call('fetchPullRequestFiles', metadata)).rejects.toMatchObject({
    code: grpc.status.UNAUTHENTICATED,
  });
  expect(operations.fetchPullRequestFiles).not.toHaveBeenCalled();
});

test('Cloud Run identity metadata alone does not authorize an application call', async () => {
  const metadata = new grpc.Metadata();
  metadata.set('x-serverless-authorization', 'Bearer ingress-token');
  await expect(call('fetchPullRequestFiles', metadata)).rejects.toMatchObject({
    code: grpc.status.UNAUTHENTICATED,
  });
});

test('a matching secret reaches the operation and preserves correlation', async () => {
  const metadata = new grpc.Metadata();
  metadata.set('x-internal-secret', secret);
  metadata.set('x-github-delivery', 'auth-delivery');
  operations.fetchPullRequestFiles.mockImplementationOnce(async () => {
    expect(requestContext.current()).toEqual({ delivery_id: 'auth-delivery' });
    return { files: [] };
  });
  const response = await call('fetchPullRequestFiles', metadata);
  expect(response.getFilesList()).toEqual([]);
  expect(operations.fetchPullRequestFiles).toHaveBeenCalledTimes(1);
});

test('an unconfigured server fails closed even for an otherwise valid credential', async () => {
  delete process.env.GITHUB_SERVICE_INTERNAL_SECRET;
  const metadata = new grpc.Metadata();
  metadata.set('x-internal-secret', secret);
  await expect(call('fetchPullRequestFiles', metadata)).rejects.toMatchObject({
    code: grpc.status.UNAVAILABLE,
  });
  expect(operations.fetchPullRequestFiles).not.toHaveBeenCalled();
});

test('the standard Cloud Run health probe remains available without a secret', async () => {
  delete process.env.GITHUB_SERVICE_INTERNAL_SECRET;
  const healthClient = new grpc.Client(`127.0.0.1:${port}`, grpc.credentials.createInsecure());
  try {
    const response = await new Promise((resolve, reject) => {
      healthClient.makeUnaryRequest('/grpc.health.v1.Health/Check', () => Buffer.alloc(0),
        (bytes) => bytes, {}, { deadline: Date.now() + 3000 }, (error, result) => {
          if (error) reject(error);
          else resolve(result);
        });
    });
    expect(response).toEqual(Buffer.from([0x08, 0x01]));
  } finally {
    healthClient.close();
  }
});
