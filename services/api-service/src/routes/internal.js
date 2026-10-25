const crypto = require('crypto');
const express = require('express');
const analysisRunsDb = require('../db/analysisRuns');
const { notifyAnalysisQueued } = require('../services/prAnalysisOrchestrator');
const { AnalysisGrpcClient } = require('../clients/analysisGrpcClient');
const { GitHubGrpcClient } = require('../clients/githubGrpcClient');

const router = express.Router();

function ensureInternalAuth(req, res, next) {
  const expected = process.env.GITHUB_SERVICE_INTERNAL_SECRET;
  if (!expected) {
    return res.status(500).json({ error: 'Internal secret is not configured' });
  }

  const provided = req.get('x-internal-secret') || '';
  const expectedBuf = Buffer.from(expected);
  const providedBuf = Buffer.from(provided);

  if (expectedBuf.length !== providedBuf.length || !crypto.timingSafeEqual(expectedBuf, providedBuf)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  next();
}

router.use(ensureInternalAuth);

router.post('/analysis-queue/tick', async (_req, res, next) => {
  try {
    notifyAnalysisQueued();
    const queue = await analysisRunsDb.getQueueStats();
    res.json({ ok: true, queued: true, queue });
  } catch (error) {
    next(error);
  }
});

async function authenticatedHealthCheck(Client) {
  const dependency = new Client();
  try {
    const response = await dependency.healthCheck();
    if (response.status !== 'ok') {
      throw new Error('Dependency did not report ok');
    }
    return 'ok';
  } finally {
    dependency.client?.close?.();
  }
}

router.get('/dependencies', async (_req, res) => {
  const [analysis, github] = await Promise.allSettled([
    authenticatedHealthCheck(AnalysisGrpcClient),
    authenticatedHealthCheck(GitHubGrpcClient),
  ]);
  const checks = {
    analysis: analysis.status === 'fulfilled' ? analysis.value : 'error',
    github: github.status === 'fulfilled' ? github.value : 'error',
  };
  const ok = Object.values(checks).every((status) => status === 'ok');

  res.status(ok ? 200 : 503).json({
    status: ok ? 'ok' : 'error',
    service: 'mitig8it-api',
    checks,
  });
});

module.exports = router;
