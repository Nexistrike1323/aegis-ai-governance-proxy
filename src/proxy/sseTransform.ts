import { Transform, TransformCallback } from 'node:stream';
import { AhoCorasickScanner } from '../scanner/ahoCorasick.js';

export class SSERedactionTransform extends Transform {
  private scanner: AhoCorasickScanner;
  private buffer = '';
  private tokenHoldback = '';
  // Hold back enough characters so multi-chunk patterns (like 14-char IDs or 36-char API keys)
  // are never sliced in half across SSE chunk boundaries.
  private readonly holdbackThreshold = 64;
  private readonly tailRetention = 40;

  constructor(scanner: AhoCorasickScanner) {
    super();
    this.scanner = scanner;
  }

  override _transform(chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback): void {
    this.buffer += chunk.toString('utf8');
    const lines = this.buffer.split('\n');
    this.buffer = lines.pop() ?? '';

    for (const line of lines) {
      if (!line.startsWith('data: ')) {
        this.push(line + '\n');
        continue;
      }

      const payload = line.slice(6).trim();
      if (payload === '[DONE]') {
        if (this.tokenHoldback.length > 0) {
          const finalScan = this.scanner.scanAndRedact(this.tokenHoldback, true);
          this.push(this.buildSSEChunk(finalScan.redactedText));
          this.tokenHoldback = '';
        }
        this.push('data: [DONE]\n\n');
        continue;
      }

      try {
        const parsed = JSON.parse(payload);
        const deltaContent: string | undefined = parsed?.choices?.[0]?.delta?.content;

        if (typeof deltaContent === 'string') {
          this.tokenHoldback += deltaContent;
          // Scan the accumulated sliding window immediately
          const scanResult = this.scanner.scanAndRedact(this.tokenHoldback, true);
          this.tokenHoldback = scanResult.redactedText;

          if (this.tokenHoldback.length > this.holdbackThreshold) {
            const flushCut = this.tokenHoldback.length - this.tailRetention;
            if (flushCut > 0) {
              const safeToEmit = this.tokenHoldback.slice(0, flushCut);
              this.tokenHoldback = this.tokenHoldback.slice(flushCut);
              parsed.choices[0].delta.content = safeToEmit;
              this.push(`data: ${JSON.stringify(parsed)}\n\n`);
            }
          }
        } else {
          this.push(line + '\n');
        }
      } catch {
        this.push(line + '\n');
      }
    }
    callback();
  }

  override _flush(callback: TransformCallback): void {
    if (this.tokenHoldback.length > 0) {
      const finalScan = this.scanner.scanAndRedact(this.tokenHoldback, true);
      this.push(this.buildSSEChunk(finalScan.redactedText));
      this.tokenHoldback = '';
    }
    if (this.buffer.length > 0) {
      this.push(this.buffer);
    }
    callback();
  }

  private buildSSEChunk(content: string): string {
    return `data: ${JSON.stringify({
      id: 'chatcmpl-aegis-stream',
      object: 'chat.completion.chunk',
      choices: [{ index: 0, delta: { content }, finish_reason: null }],
    })}\n\n`;
  }
}