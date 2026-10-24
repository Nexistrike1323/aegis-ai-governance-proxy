# Aegis AI Governance Proxy

A production-grade, zero-trust infrastructure proxy designed to govern Large Language Model (LLM) requests in real time. Aegis sits between enterprise applications and upstream AI providers (such as OpenAI, Anthropic, or custom endpoints), enforcing sub-millisecond data security, data loss prevention (DLP), policy compliance, and immutable cryptographic auditing.

---

## Why This Project Was Built

As enterprises rapidly adopt Large Language Models, they face significant operational and security risks:
- **Data Leaks:** Employees or automated systems accidentally sending sensitive Personally Identifiable Information (PII) or API credentials to external LLM endpoints.
- **Unauthorized Access:** Junior staff or unverified tenants invoking restricted, high-cost frontier models (e.g., GPT-4o) without proper authorization.
- **Compliance Failures:** Regulatory frameworks (like HIPAA, GDPR, or financial data standards) requiring tamper-evident, verifiable audit trails of every single AI interaction.
- **Latency Overhead:** Existing security middleware adds unacceptable latency penalties, breaking real-time application responsiveness and streaming token delivery.

Aegis was built to solve these enterprise challenges at the network proxy layer—ensuring strict security and compliance without degrading application performance.

---

## Core Architecture & Components

```text
[ Client Application ] --(Bearer JWT + x-tenant-id)--> [ Aegis Reverse Proxy ]
                                                              │
         ┌────────────────────────────────────────────────────┼────────────────────────────────────────────────────┐
         ▼                                                    ▼                                                    ▼
[1. O(N) Aho-Corasick Automaton]            [2. Open Policy Agent (OPA) Engine]          [3. SHA-256 Merkle Audit Pipeline]
- Single-pass multi-pattern matching        - Identity and role-based access control     - Immutable append-only audit ledger
- Inline PII and credential detection       - Tenant isolation & IDOR prevention         - Cryptographic hash-chain verification
- Streaming Server-Sent Events redactor     - Dynamic governance rule enforcement        - Real-time p50/p95/p99 latency tracking



## Detailed Technical Implementation

### 1. Deterministic O(N) Multi-Pattern Trie Scanner
Rather than using slow regular expression loops or expensive API calls to check for thousands of sensitive keywords, Aegis implements an **Aho-Corasick Automaton** (a Trie data structure with precomputed BFS failure links) in TypeScript.
- **Performance:** Scans raw prompt text against large enterprise deny-lists in a single $O(N)$ pass.
- **Latency:** Execution time remains flat between $0.02\text{ ms}$ and $0.3\text{ ms}$, ensuring zero noticeable impact on application throughput.

### 2. Real-Time Streaming SSE Lookahead Redactor
When applications stream LLM responses using Server-Sent Events (SSE), standard redactors fail because sensitive patterns (such as segmented identification numbers or long keys) often get split across multiple data chunks.
- **Mechanism:** Aegis uses a sliding-window lookahead buffer (`SSERedactionTransform`) that retains a small tail retention window. It inspects tokens mid-stream, redacts matched patterns on the fly, and flushes safe tokens downstream without breaking Time-To-First-Token (TTFT).

### 3. Zero-Trust OPA Policy Engine & JWT Verification
Every incoming request must present a valid cryptographic JSON Web Token (`jose`).
- **Authorization:** The proxy extracts tenant identifiers and user roles (`doctor`, `intern`, `admin`) and queries an integrated **Open Policy Agent (OPA)** policy evaluation engine running Rego logic.
- **Mitigation:** Instantly blocks cross-tenant IDOR (Insecure Direct Object Reference) spoofing attempts, unauthorized model tiers, and prompt injection attempts before they ever hit the upstream LLM provider.

### 4. Tamper-Evident SHA-256 Audit Pipeline
Regulatory compliance demands proof that audit logs have not been modified or deleted.
- **Mechanism:** Every allowed, redacted, or blocked request appends an immutable record to a **SHA-256 Cryptographic Hash-Chain** (`prevHash + payload + timestamp + salt`).
- **Verification:** An administrative endpoint (`/v1/audit/verify`) mathematically recalculates and verifies the integrity of the entire ledger. Any unauthorized data tampering instantly invalidates the chain.

### 5. Production Kubernetes Helm Packaging
Designed for cloud-native deployment, Aegis is packaged as a complete **Kubernetes Helm Chart** (`helm/aegis-proxy`).
- **Multi-Container Pods:** Deploys the Node.js governance proxy alongside an official OPA sidecar container (`openpolicyagent/opa`) sharing a local loopback network and a mounted ConfigMap containing governance Rego policies.
- **Ingress & TLS:** Configured with production-ready NGINX Ingress rules, TLS termination secrets, and Cert-Manager annotations.

---

## Verification & Usage

### Running the Automated Test Suite
The verification suite executes comprehensive integration tests covering doctor PII redaction, intern model restrictions, API key exfiltration attempts, cross-tenant IDOR attacks, and SSE stream split-token redaction:
```powershell
npm run verify

