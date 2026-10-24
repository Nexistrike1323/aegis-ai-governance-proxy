export function renderDashboardHtml() {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Aegis AI Governance Control Plane</title>
  <style>
    body { background: #0f172a; color: #f8fafc; font-family: ui-sans-serif, system-ui, sans-serif; margin: 0; padding: 2rem; }
    .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 1rem; margin-bottom: 2rem; }
    .badge { background: #0284c7; color: white; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.875rem; font-weight: 600; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 0.5rem; padding: 1.5rem; }
    .card h3 { margin: 0 0 0.5rem 0; font-size: 0.875rem; color: #94a3b8; text-transform: uppercase; }
    .card .value { font-size: 1.875rem; font-weight: 700; color: #38bdf8; }
    table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 0.5rem; overflow: hidden; }
    th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #334155; font-size: 0.875rem; }
    th { background: #334155; color: #cbd5e1; }
    .tag-block { color: #f43f5e; font-weight: 600; }
    .tag-redact { color: #fbbf24; font-weight: 600; }
    .tag-allow { color: #34d399; font-weight: 600; }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <h1 style="margin:0; font-size: 1.5rem;">🛡️ Aegis AI Governance Control Plane</h1>
      <p style="margin:0.25rem 0 0 0; color: #94a3b8; font-size: 0.875rem;">Real-time Policy Enforcement & Tamper-Evident Audit Ledger</p>
    </div>
    <div class="badge" id="chain-status">Chain Integrity: Verified ✓</div>
  </div>

  <div class="grid">
    <div class="card">
      <h3>Total Requests</h3>
      <div class="value" id="m-total">0</div>
    </div>
    <div class="card">
      <h3>Blocked Threats</h3>
      <div class="value" id="m-blocked" style="color: #f43f5e;">0</div>
    </div>
    <div class="card">
      <h3>Redacted PII</h3>
      <div class="value" id="m-redacted" style="color: #fbbf24;">0</div>
    </div>
    <div class="card">
      <h3>p95 Latency</h3>
      <div class="value" id="m-p95">0 ms</div>
    </div>
  </div>

  <h2 style="font-size: 1.25rem; margin-bottom: 1rem;">Immutable Audit Stream</h2>
  <table>
    <thead>
      <tr>
        <th>Sequence</th>
        <th>Timestamp</th>
        <th>Tenant</th>
        <th>Actor / Role</th>
        <th>Action</th>
        <th>Reason</th>
        <th>Record Hash (SHA-256)</th>
      </tr>
    ></thead>
    <tbody id="audit-rows">
      <tr><td colspan="7" style="text-align:center; color:#94a3b8;">Loading ledger...</td></tr>
    </tbody>
  </table>

  <script>
    async function refreshData() {
      try {
        const res = await fetch('/v1/audit/stream');
        const data = await res.json();
        
        document.getElementById('m-total').innerText = data.metrics.totalRequests;
        document.getElementById('m-blocked').innerText = data.metrics.blockedCount;
        document.getElementById('m-redacted').innerText = data.metrics.redactedCount;
        document.getElementById('m-p95').innerText = (data.metrics.latencyMs.p95 ?? 0) + ' ms';
        
        const statusEl = document.getElementById('chain-status');
        if (data.metrics.chainIntegrity.valid) {
          statusEl.innerText = 'Chain Integrity: Verified ✓';
          statusEl.style.background = '#059669';
        } else {
          statusEl.innerText = 'TAMPER DETECTED ⚠️';
          statusEl.style.background = '#dc2626';
        }

        const tbody = document.getElementById('audit-rows');
        if (data.logs.length === 0) {
          tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:#94a3b8;">No audit events recorded yet. Run verification test!</td></tr>';
          return;
        }

        tbody.innerHTML = data.logs.map(r => \`
          <tr>
            <td>#\${r.sequence}</td>
            <td style="color:#94a3b8;">\${new Date(r.timestamp).toLocaleTimeString()}</td>
            <td>\${r.tenantId}</td>
            <td>\${r.actor}<br><small style="color:#94a3b8;">\${r.role}</small></td>
            <td><span class="tag-\${r.action.toLowerCase().includes('block') ? 'block' : r.action.toLowerCase().includes('redact') ? 'redact' : 'allow'}">\${r.action}</span></td>
            <td>\${r.reason}</td>
            <td><code style="font-size:0.75rem; color:#94a3b8;">\${r.recordHash.slice(0, 16)}...</code></td>
          </tr>
        \`).join('');
      } catch (err) {
        console.error(err);
      }
    }
    refreshData();
    setInterval(refreshData, 2000);
  </script>
</body>
</html>`;
}
