import { performance } from 'node:perf_hooks';

export interface Finding {
  category: 'FORBIDDEN_KEYWORD' | 'PII_EMAIL' | 'PII_INDIAN_AADHAAR' | 'PII_SSN' | 'SECRET_API_KEY';
  matchedText: string;
  startIndex: number;
  endIndex: number;
}

export interface ScanResult {
  originalLength: number;
  redactedText: string;
  findings: Finding[];
  scanDurationMs: number;
}

class TrieNode {
  children: Map<string, TrieNode> = new Map();
  fail: TrieNode | null = null;
  outputs: string[] = [];
}

export class AhoCorasickScanner {
  private root: TrieNode = new TrieNode();
  private compiled = false;

  constructor(keywords: string[] = []) {
    for (const kw of keywords) {
      this.addKeyword(kw);
    }
    this.buildFailureLinks();
  }

  public addKeyword(keyword: string): void {
    const clean = keyword.trim().toLowerCase();
    if (!clean) return;
    let node = this.root;
    for (const char of clean) {
      if (!node.children.has(char)) {
        node.children.set(char, new TrieNode());
      }
      node = node.children.get(char)!;
    }
    if (!node.outputs.includes(clean)) {
      node.outputs.push(clean);
    }
    this.compiled = false;
  }

  public buildFailureLinks(): void {
    const queue: TrieNode[] = [];
    for (const child of this.root.children.values()) {
      child.fail = this.root;
      queue.push(child);
    }

    while (queue.length > 0) {
      const current = queue.shift()!;
      for (const [char, child] of current.children.entries()) {
        queue.push(child);
        let fallback = current.fail;
        while (fallback !== null && !fallback.children.has(char)) {
          fallback = fallback.fail;
        }
        child.fail = fallback ? fallback.children.get(char)! : this.root;
        if (child.fail && child.fail.outputs.length > 0) {
          child.outputs.push(...child.fail.outputs);
        }
      }
    }
    this.compiled = true;
  }

  public scanAndRedact(input: string, redact = true): ScanResult {
    const start = performance.now();
    if (!this.compiled) this.buildFailureLinks();

    const findings: Finding[] = [];
    const lowerInput = input.toLowerCase();

    // 1. Single-pass O(N) Aho-Corasick Trie traversal
    let node = this.root;
    for (let i = 0; i < lowerInput.length; i++) {
      const char = lowerInput[i];
      while (node !== this.root && !node.children.has(char)) {
        node = node.fail!;
      }
      node = node.children.get(char) || this.root;

      for (const pattern of node.outputs) {
        const startIndex = i - pattern.length + 1;
        const endIndex = i + 1;
        findings.push({
          category: 'FORBIDDEN_KEYWORD',
          matchedText: input.slice(startIndex, endIndex),
          startIndex,
          endIndex,
        });
      }
    }

    // 2. Structured PII & High-Entropy Secret Detectors
    const patterns: Array<{ category: Finding['category']; regex: RegExp }> = [
      { category: 'PII_EMAIL', regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
      { category: 'PII_INDIAN_AADHAAR', regex: /\b[2-9]{1}[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b/g },
      { category: 'PII_SSN', regex: /\b\d{3}-\d{2}-\d{4}\b/g },
      { category: 'SECRET_API_KEY', regex: /\b(?:sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36})\b/g },
    ];

    for (const { category, regex } of patterns) {
      let match: RegExpExecArray | null;
      while ((match = regex.exec(input)) !== null) {
        findings.push({
          category,
          matchedText: match[0],
          startIndex: match.index,
          endIndex: match.index + match[0].length,
        });
      }
    }

    // Sort findings & merge overlaps for clean replacement
    findings.sort((a, b) => a.startIndex - b.startIndex || b.endIndex - a.endIndex);

    let redactedText = input;
    if (redact && findings.length > 0) {
      const merged: Finding[] = [];
      for (const f of findings) {
        if (merged.length === 0 || f.startIndex >= merged[merged.length - 1].endIndex) {
          merged.push({ ...f });
        } else {
          const prev = merged[merged.length - 1];
          if (f.endIndex > prev.endIndex) {
            prev.endIndex = f.endIndex;
          }
        }
      }

      let cursor = 0;
      const chunks: string[] = [];
      for (const m of merged) {
        chunks.push(input.slice(cursor, m.startIndex));
        chunks.push(`[REDACTED:${m.category}]`);
        cursor = m.endIndex;
      }
      chunks.push(input.slice(cursor));
      redactedText = chunks.join('');
    }

    const scanDurationMs = Number((performance.now() - start).toFixed(3));
    return {
      originalLength: input.length,
      redactedText,
      findings,
      scanDurationMs,
    };
  }
}
