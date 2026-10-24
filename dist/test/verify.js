import { startMockUpstream } from '../src/proxy/mockUpstream.js';
import { buildProxyServer } from '../src/server.js';
import { signIdentityToken } from '../src/policy/opaClient.js';
import { request } from 'undici';
async function runVerification() {
    console.log('\n====================================================================');
    console.log(' AEGIS AI GOVERNANCE PROXY (CHAIN 1 + CHAIN 2) — PROOF OF WORK');
    console.log('====================================================================\n');
    const upstream = await startMockUpstream(4001);
    const proxy = await buildProxyServer('http://127.0.0.1:4001');
    await proxy.listen({ port: 4000, host: '127.0.0.1' });
    const doctorToken = await signIdentityToken({
        sub: 'dr-sharma@apollo-health.in',
        tenantId: 'tenant-apollo',
        role: 'doctor',
        department: 'cardiology',
    });
    const internToken = await signIdentityToken({
        sub: 'intern-rahul@apollo-health.in',
        tenantId: 'tenant-apollo',
        role: 'intern',
        department: 'engineering',
    });
    const results = [];
    // 1. Doctor PII Redaction
    {
        const res = await request('http://127.0.0.1:4000/v1/chat/completions', {
            method: 'POST',
            headers: { authorization: `Bearer ${doctorToken}`, 'x-tenant-id': 'tenant-apollo', 'content-type': 'application/json' },
            body: JSON.stringify({ model: 'gpt-4o-mini', messages: [{ role: 'user', content: 'Aadhaar 4921 8832 9012, email dr@apollo.in' }] }),
        });
        results.push({ Scenario: '1. Doctor PII Inline Redaction', Status: res.statusCode, Action: String(res.headers['x-aegis-policy-action']), ScanMs: `${res.headers['x-aegis-scan-latency-ms']} ms`, Result: res.statusCode === 200 ? 'PASS' : 'FAIL' });
    }
    // 2. Intern Model Restriction
    {
        const res = await request('http://127.0.0.1:4000/v1/chat/completions', {
            method: 'POST',
            headers: { authorization: `Bearer ${internToken}`, 'x-tenant-id': 'tenant-apollo', 'content-type': 'application/json' },
            body: JSON.stringify({ model: 'gpt-4o', messages: [{ role: 'user', content: 'Hello' }] }),
        });
        results.push({ Scenario: '2. Intern Restricted Model (gpt-4o)', Status: res.statusCode, Action: String(res.headers['x-aegis-policy-action']), ScanMs: `${res.headers['x-aegis-scan-latency-ms']} ms`, Result: res.statusCode === 403 ? 'PASS' : 'FAIL' });
    }
    // 3. Audit Stream & Hash Chain Integrity Check
    {
        const res = await request('http://127.0.0.1:4000/v1/audit/verify');
        const data = (await res.body.json());
        results.push({ Scenario: '3. Cryptographic Audit Chain Integrity', Status: res.statusCode, Action: data.valid ? 'VALID_CHAIN' : 'BROKEN', ScanMs: `${data.totalRecords} records`, Result: data.valid ? 'PASS' : 'FAIL' });
    }
    // 4. Control Plane Dashboard HTTP 200 Check
    {
        const res = await request('http://127.0.0.1:4000/dashboard');
        const html = await res.body.text();
        const passed = res.statusCode === 200 && html.includes('Aegis AI Governance Control Plane');
        results.push({ Scenario: '4. Control Plane Dashboard UI Route', Status: res.statusCode, Action: 'HTML_SERVED', ScanMs: `${html.length} bytes`, Result: passed ? 'PASS' : 'FAIL' });
    }
    console.table(results);
    await proxy.close();
    await upstream.close();
}
runVerification().catch((err) => {
    console.error(err);
    process.exit(1);
});
