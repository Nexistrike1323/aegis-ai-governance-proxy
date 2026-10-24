import Fastify from 'fastify';
import { request } from 'undici';
import { AhoCorasickScanner } from './scanner/ahoCorasick.js';
import { verifyIdentityToken, evaluatePolicy } from './policy/opaClient.js';
import { SSERedactionTransform } from './proxy/sseTransform.js';
import { startMockUpstream } from './proxy/mockUpstream.js';
import { TamperEvidentAuditPipeline } from './audit/hashChainAudit.js';
import { renderDashboardHtml } from './ui/dashboard.js';

const FORBIDDEN_ENTERPRISE_KEYWORDS = [
  'project-titan-source',
  'internal-db-password',
  'drop table patients',
  'ignore previous instructions',
];

export async function buildProxyServer(upstreamUrl = 'http://127.0.0.1:4001') {
  const app = Fastify({ logger: false });
  const scanner = new AhoCorasickScanner(FORBIDDEN_ENTERPRISE_KEYWORDS);
  const auditPipeline = new TamperEvidentAuditPipeline();

  // 1. Health & Status
  app.get('/healthz', async () => ({ status: 'ok', service: 'aegis-ai-governance-proxy' }));

  // 2. Control Plane UI Dashboard
  app.get('/dashboard', async (_req, reply) => {
    reply.type('text/html').send(renderDashboardHtml());
  });

  // 3. Audit Stream API for Dashboard & Compliance Verification
  app.get('/v1/audit/stream', async () => {
    return {
      metrics: auditPipeline.getMetrics(),
      logs: auditPipeline.getRecentLogs(50),
    };
  });

  app.get('/v1/audit/verify', async () => {
    return auditPipeline.verifyIntegrity();
  });

  // 4. Main AI Governance Proxy Route
  app.post('/v1/chat/completions', async (req, reply) => {
    let identity;
    try {
      identity = await verifyIdentityToken(req.headers.authorization);
    } catch (err) {
      return reply.code(401).send({
        error: 'UNAUTHORIZED',
        message: (err as Error).message,
      });
    }

    const body = req.body as {
      model?: string;
      messages?: Array<{ role: string; content: string }>;
      stream?: boolean;
    };

    const model = body?.model ?? 'gpt-4o-mini';
    const rawPrompt = (body?.messages ?? []).map((m) => m.content).join('\n');

    // Run O(N) Aho-Corasick + PII Scanner
    const scanResult = scanner.scanAndRedact(rawPrompt, true);
    const categories = Array.from(new Set(scanResult.findings.map((f) => f.category)));

    // Query OPA / Embedded Policy Engine
    const targetTenantHeader = req.headers['x-tenant-id'] as string | undefined;
    const decision = await evaluatePolicy({
      identity,
      model,
      findingsCategories: categories,
      targetTenantHeader,
    });

    // Record immutable audit event into SHA-256 Hash Chain
    auditPipeline.append({
      tenantId: identity.tenantId,
      actor: identity.sub,
      role: identity.role,
      model,
      action: decision.action,
      reason: decision.reason,
      findingsCategories: categories,
      scanDurationMs: scanResult.scanDurationMs,
      promptText: rawPrompt,
    });

    // Attach governance telemetry headers
    reply.header('X-Aegis-Policy-Action', decision.action);
    reply.header('X-Aegis-Scan-Latency-Ms', String(scanResult.scanDurationMs));
    reply.header('X-Aegis-Evaluated-By', decision.evaluatedBy);
    reply.header('X-Aegis-Findings-Count', String(scanResult.findings.length));

    if (!decision.allow) {
      return reply.code(403).send({
        error: 'POLICY_VIOLATION',
        action: decision.action,
        reason: decision.reason,
        findings: scanResult.findings.map((f) => f.category),
        scanDurationMs: scanResult.scanDurationMs,
      });
    }

    // If REDACT_AND_ALLOW, redact prompt messages before forwarding to LLM
    const outboundMessages = (body.messages ?? []).map((msg) => ({
      ...msg,
      content:
        decision.action === 'REDACT_AND_ALLOW'
          ? scanner.scanAndRedact(msg.content, true).redactedText
          : msg.content,
    }));

    const upstreamResponse = await request(`${upstreamUrl}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        ...body,
        messages: outboundMessages,
      }),
    });

    // Handle real-time SSE stream interception
    if (body.stream) {
      reply.raw.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
        'X-Aegis-Policy-Action': decision.action,
        'X-Aegis-Scan-Latency-Ms': String(scanResult.scanDurationMs),
      });

      const sseRedactor = new SSERedactionTransform(scanner);
      upstreamResponse.body.pipe(sseRedactor).pipe(reply.raw);
      return reply;
    }

    const upstreamJson = await upstreamResponse.body.json();
    return reply.code(200).send(upstreamJson);
  });

  return app;
}

// Start standalone if invoked directly
if (import.meta.url === `file://${process.argv[1].replace(/\\/g, '/')}`) {
  await startMockUpstream(4001);
  const proxy = await buildProxyServer('http://127.0.0.1:4001');
  await proxy.listen({ port: 4000, host: '127.0.0.1' });
  console.log('Aegis Governance Proxy listening on http://127.0.0.1:4000');
  console.log('Control Plane Dashboard: http://127.0.0.1:4000/dashboard');
}