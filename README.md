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



# Aegis Architecture: Codebase File Mapping (Modules 1 - 5)

## Module 1: Deterministic O(N) Multi-Pattern Trie Scanner
- **Core Implementation File:** `src/scanner/ahoCorasick.ts`
- **Streaming Redaction Transform File:** `src/proxy/sseTransform.ts`
- **What it does:** Implements the Aho-Corasick automaton for single-pass multi-pattern matching and the sliding-window lookahead buffer that inspects Server-Sent Events (SSE) mid-stream without breaking Time-To-First-Token.

## Module 2: Zero-Trust OPA Policy Engine & JWT Verification
- **Core Implementation File:** `src/policy/opaClient.ts`
- **Policy Definition File:** `policies/ai_governance.rego`
- **What it does:** Decodes and verifies cryptographic JSON Web Tokens (`jose`) and queries the embedded Open Policy Agent (OPA) / Rego policy engine to enforce role-based access control and prevent cross-tenant IDOR attacks.

## Module 3: Tamper-Evident SHA-256 Audit Pipeline
- **Core Implementation File:** `src/audit/hashChainAudit.ts`
- **What it does:** Appends every allowed, redacted, or blocked request into an immutable SHA-256 cryptographic hash-chain (`prevHash + payload + timestamp + salt`) and exposes mathematical chain verification.

## Module 4: Live Control Plane Dashboard UI
- **Core Implementation File:** `src/ui/dashboard.ts`
- **Main Server Binding:** `src/server.ts`
- **What it does:** Serves a dark-mode engineering control plane at `http://127.0.0.1:4000/dashboard` featuring live $p50, p95, p99$ latency metrics, threat counters, chain integrity badges, and an immutable audit stream table.

## Module 5: Production Kubernetes Helm Packaging
- **Helm Chart Directory:** `helm/aegis-proxy/`
  - `Chart.yaml` (Metadata)
  - `values.yaml` (Default configuration values)
  - `templates/deployment.yaml` (Multi-container pod: Node.js proxy + OPA sidecar)
  - `templates/service.yaml` (ClusterIP service)
  - `templates/ingress.yaml` (NGINX Ingress with TLS & cert-manager annotations)
  - `templates/configmap.yaml` (Dynamically injects Rego governance policies)
- **What it does:** Packages the entire platform into a production-ready Kubernetes Helm chart for cluster-native deployment.

Verification & Usage Guide

npm run verify


npm run dev
