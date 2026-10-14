import http from 'node:http';
import { createHash, createHmac } from 'node:crypto';
import { Environment, SignedDataVerifier } from '@apple/app-store-server-library';

const env = process.env;
const PORT = Number(env.PORT || 10000);
const MAX_BODY = 220_000;
const requireEnv = key => { if (!env[key]) throw new Error(`Missing ${key}`); return env[key]; };
const json = (res, status, body) => {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
};
async function readBody(req) {
  const chunks = []; let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw new Error('body_too_large');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
function verifier(environment) {
  const roots = requireEnv('APPLE_ROOT_CA_CERTS_BASE64').split(',').map(x => Buffer.from(x.trim(), 'base64'));
  if (!roots.length || roots.some(x => !x.length)) throw new Error('invalid_apple_roots');
  return new SignedDataVerifier(roots, true, environment, requireEnv('APPLE_BUNDLE_ID'),
    environment === Environment.PRODUCTION ? Number(requireEnv('APPLE_APP_ID')) : undefined);
}
async function forwardVerified(signedPayload, verified, environment) {
  const body = JSON.stringify({
    environment: environment === Environment.SANDBOX ? 'Sandbox' : 'Production',
    notificationUUID: verified.notificationUUID,
    notificationType: verified.notificationType,
    subtype: verified.subtype ?? null,
    signedDate: verified.signedDate ?? null,
    signedPayload
  });
  const signature = createHmac('sha256', requireEnv('SCIPIC_INGEST_SHARED_SECRET')).update(body).digest('hex');
  const response = await fetch(requireEnv('SCIPIC_VERIFIED_INGEST_URL'), {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-scipic-signature': signature },
    body, signal: AbortSignal.timeout(12000)
  });
  if (!response.ok) throw new Error(`ingest_http_${response.status}`);
}
const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') return json(res, 200, { ok: true });
  if (req.method !== 'POST' || req.url !== '/apple/notifications') return json(res, 404, { error: 'not_found' });
  try {
    for (const key of ['APPLE_BUNDLE_ID','APPLE_APP_ID','APPLE_ROOT_CA_CERTS_BASE64','SCIPIC_INGEST_SHARED_SECRET','SCIPIC_VERIFIED_INGEST_URL']) { if (!env[key]) return json(res, 503, { error: 'not_configured' }); }
    const body = await readBody(req);
    if (typeof body?.signedPayload !== 'string' || body.signedPayload.length > 200000)
      return json(res, 400, { error: 'invalid_payload' });
    let verified, environment;
    for (const candidate of [Environment.PRODUCTION, Environment.SANDBOX]) {
      try {
        verified = await verifier(candidate).verifyAndDecodeNotification(body.signedPayload);
        environment = candidate; break;
      } catch { /* Fail closed. */ }
    }
    if (!verified?.notificationUUID) return json(res, 401, { error: 'unverified_notification' });
    await forwardVerified(body.signedPayload, verified, environment);
    console.info('apple_notification_forwarded', {
      environment: environment === Environment.SANDBOX ? 'Sandbox' : 'Production',
      notificationType: verified.notificationType,
      notificationHash: createHash('sha256').update(verified.notificationUUID).digest('hex').slice(0, 16)
    });
    return json(res, 200, { ok: true });
  } catch (e) {
    console.error('apple_notification_processing_failed', String(e?.message ?? 'unknown').slice(0, 100));
    return json(res, 503, { error: 'processing_unavailable' });
  }
});
// Start in fail-closed setup mode. /health remains available, but notification
// verification cannot succeed until every required environment secret is set.
server.listen(PORT, '0.0.0.0', () => console.log('scipic_apple_verifier_listening', PORT));
