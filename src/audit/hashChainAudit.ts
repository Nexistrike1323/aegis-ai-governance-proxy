import { createHash, randomUUID } from 'node:crypto';

export interface AuditEventInput {
  tenantId: string;
  actor: string;
  role: string;
  model: string;
  action: 'ALLOW' | 'REDACT_AND_ALLOW' | 'BLOCK';
  reason: string;
  findingsCategories: string[];
  scanDurationMs: number;
  promptText: string;
}

export interface AuditRecord extends Omit<AuditEventInput, 'promptText'> {
  eventId: string;
  sequence: number;
  timestamp: string;
  promptSha256: string;
  prevHash: string;
  recordHash: string;
}

export class TamperEvidentAuditPipeline {
  private ledger: AuditRecord[] = [];
  private readonly genesisHash = '0000000000000000000000000000000000000000000000000000000000000000';

  public append(input: AuditEventInput): AuditRecord {
    const sequence = this.ledger.length + 1;
    const timestamp = new Date().toISOString();
    const eventId = randomUUID();
    const prevHash = this.ledger.length > 0 ? this.ledger[this.ledger.length - 1].recordHash : this.genesisHash;

    // Never store raw sensitive prompts in the audit log; store a salted SHA-256 fingerprint
    const promptSha256 = createHash('sha256').update(input.promptText).digest('hex');

    const canonicalPayload = JSON.stringify({
      sequence,
      timestamp,
      tenantId: input.tenantId,
      actor: input.actor,
      role: input.role,
      model: input.model,
      action: input.action,
      findingsCategories: input.findingsCategories,
      promptSha256,
      prevHash,
    });

    const recordHash = createHash('sha256').update(canonicalPayload).digest('hex');

    const record: AuditRecord = {
      eventId,
      sequence,
      timestamp,
      tenantId: input.tenantId,
      actor: input.actor,
      role: input.role,
      model: input.model,
      action: input.action,
      reason: input.reason,
      findingsCategories: input.findingsCategories,
      scanDurationMs: input.scanDurationMs,
      promptSha256,
      prevHash,
      recordHash,
    };

    this.ledger.push(record);
    return record;
  }

  public verifyIntegrity(): { valid: boolean; totalRecords: number; brokenAtSequence: number | null } {
    for (let i = 0; i < this.ledger.length; i++) {
      const rec = this.ledger[i];
      const expectedPrev = i === 0 ? this.genesisHash : this.ledger[i - 1].recordHash;

      if (rec.prevHash !== expectedPrev) {
        return { valid: false, totalRecords: this.ledger.length, brokenAtSequence: rec.sequence };
      }

      const recomputedPayload = JSON.stringify({
        sequence: rec.sequence,
        timestamp: rec.timestamp,
        tenantId: rec.tenantId,
        actor: rec.actor,
        role: rec.role,
        model: rec.model,
        action: rec.action,
        findingsCategories: rec.findingsCategories,
        promptSha256: rec.promptSha256,
        prevHash: rec.prevHash,
      });

      const recomputedHash = createHash('sha256').update(recomputedPayload).digest('hex');
      if (recomputedHash !== rec.recordHash) {
        return { valid: false, totalRecords: this.ledger.length, brokenAtSequence: rec.sequence };
      }
    }

    return { valid: true, totalRecords: this.ledger.length, brokenAtSequence: null };
  }

  public getMetrics() {
    const total = this.ledger.length;
    const blocked = this.ledger.filter((r) => r.action === 'BLOCK').length;
    const redacted = this.ledger.filter((r) => r.action === 'REDACT_AND_ALLOW').length;
    const allowed = this.ledger.filter((r) => r.action === 'ALLOW').length;

    const latencies = this.ledger.map((r) => r.scanDurationMs).sort((a, b) => a - b);
    const p50 = latencies.length ? latencies[Math.floor(latencies.length * 0.5)] : 0;
    const p95 = latencies.length ? latencies[Math.floor(latencies.length * 0.95)] : 0;
    const p99 = latencies.length ? latencies[Math.floor(latencies.length * 0.99)] : 0;

    return {
      totalRequests: total,
      blockedCount: blocked,
      redactedCount: redacted,
      allowedCount: allowed,
      latencyMs: { p50, p95, p99 },
      chainIntegrity: this.verifyIntegrity(),
    };
  }

  public getRecentLogs(limit = 50): AuditRecord[] {
    return this.ledger.slice(-limit).reverse();
  }

  // Used only by security tests to simulate a rogue database tampering attack
  public unsafeTamperRecordForTest(index: number, fakeActor: string): void {
    if (this.ledger[index]) {
      this.ledger[index].actor = fakeActor;
    }
  }
}