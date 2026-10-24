import { jwtVerify, SignJWT } from 'jose';
import { request } from 'undici';
const JWT_SECRET = new TextEncoder().encode(process.env.AEGIS_JWT_SECRET ?? 'deepinspect-zero-trust-signing-key-2026');
export async function signIdentityToken(identity) {
    return await new SignJWT({ ...identity })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('2h')
        .sign(JWT_SECRET);
}
export async function verifyIdentityToken(authHeader) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new Error('Missing or malformed Authorization Bearer token');
    }
    const token = authHeader.slice(7).trim();
    const { payload } = await jwtVerify(token, JWT_SECRET);
    return {
        sub: String(payload.sub ?? 'anonymous'),
        tenantId: String(payload.tenantId ?? 'default'),
        role: payload.role ?? 'intern',
        department: String(payload.department ?? 'general'),
    };
}
export async function evaluatePolicy(input) {
    // Cross-tenant IDOR protection check first
    if (input.targetTenantHeader && input.targetTenantHeader !== input.identity.tenantId) {
        return {
            allow: false,
            action: 'BLOCK',
            reason: `Cross-tenant IDOR violation: Token belongs to '${input.identity.tenantId}' but requested tenant '${input.targetTenantHeader}'`,
            evaluatedBy: 'EMBEDDED_ENGINE',
        };
    }
    // Try querying live Open Policy Agent sidecar if running on :8181
    const opaUrl = process.env.OPA_URL ?? 'http://127.0.0.1:8181/v1/data/aegis/governance';
    try {
        const res = await request(opaUrl, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
                input: {
                    identity: input.identity,
                    model: input.model,
                    findings_categories: input.findingsCategories,
                },
            }),
            headersTimeout: 150,
        });
        if (res.statusCode === 200) {
            const data = (await res.body.json());
            if (data.result) {
                return {
                    allow: data.result.allow,
                    action: data.result.action,
                    reason: data.result.reason,
                    evaluatedBy: 'OPA_SIDECAR',
                };
            }
        }
    }
    catch {
        // Fallback to deterministic local evaluation if Docker OPA container is offline
    }
    const cats = new Set(input.findingsCategories);
    if (cats.has('SECRET_API_KEY')) {
        return {
            allow: false,
            action: 'BLOCK',
            reason: 'Prompt contains high-entropy API credential (SECRET_API_KEY)',
            evaluatedBy: 'EMBEDDED_ENGINE',
        };
    }
    if (input.identity.role === 'intern' && input.model === 'gpt-4o') {
        return {
            allow: false,
            action: 'BLOCK',
            reason: "Role 'intern' is restricted from invoking tier-1 model 'gpt-4o'",
            evaluatedBy: 'EMBEDDED_ENGINE',
        };
    }
    if (input.identity.role === 'intern' && cats.size > 0) {
        return {
            allow: false,
            action: 'BLOCK',
            reason: "Role 'intern' is blocked from transmitting sensitive data or forbidden keywords",
            evaluatedBy: 'EMBEDDED_ENGINE',
        };
    }
    if ((input.identity.role === 'doctor' || input.identity.role === 'admin') && cats.size > 0) {
        return {
            allow: true,
            action: 'REDACT_AND_ALLOW',
            reason: 'Healthcare/Authorized role permitted with mandatory inline PII redaction',
            evaluatedBy: 'EMBEDDED_ENGINE',
        };
    }
    return {
        allow: true,
        action: 'ALLOW',
        reason: 'Clean prompt compliant with tenant policy',
        evaluatedBy: 'EMBEDDED_ENGINE',
    };
}
