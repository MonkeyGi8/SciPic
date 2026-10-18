import http from 'node:http';
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { Environment, SignedDataVerifier, AppStoreServerAPIClient } from '@apple/app-store-server-library';

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

// Internal, read-only status lookup. The request must be HMAC authenticated and
// timestamped; no Apple transaction data or shared secrets are logged.
async function subscriptionStatus(req, res) {
  if (!['APPLE_PRIVATE_KEY','APPLE_KEY_ID','APPLE_ISSUER_ID','APPLE_BUNDLE_ID','APPLE_APP_ID','APPLE_ROOT_CA_CERTS_BASE64','SCIPIC_INGEST_SHARED_SECRET'].every(k => env[k]))
    return json(res, 503, { error: 'not_configured' });
  const chunks = []; let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 4096) return json(res, 413, { error: 'body_too_large' });
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks);
  const timestamp = req.headers['x-scipic-timestamp'];
  const supplied = req.headers['x-scipic-signature'];
  if (typeof timestamp !== 'string' || !/^\d{13}$/.test(timestamp) ||
      Math.abs(Date.now() - Number(timestamp)) > 60000 ||
      typeof supplied !== 'string' || !/^[a-f0-9]{64}$/.test(supplied))
    return json(res, 401, { error: 'unauthorized' });
  const expected = createHmac('sha256', requireEnv('SCIPIC_INGEST_SHARED_SECRET'))
    .update(timestamp).update('.').update(raw).digest();
  if (!timingSafeEqual(expected, Buffer.from(supplied, 'hex')))
    return json(res, 401, { error: 'unauthorized' });
  let input;
  try { input = JSON.parse(raw.toString('utf8')); }
  catch { return json(res, 400, { error: 'invalid_json' }); }
  const { environment: requestedEnvironment, originalTransactionId } = input ?? {};
  if (!['Sandbox','Production'].includes(requestedEnvironment) ||
      typeof originalTransactionId !== 'string' || !/^\d{5,40}$/.test(originalTransactionId))
    return json(res, 400, { error: 'invalid_request' });
  const appleEnvironment = requestedEnvironment === 'Production' ? Environment.PRODUCTION : Environment.SANDBOX;
  try {
    const api = new AppStoreServerAPIClient(
      requireEnv('APPLE_PRIVATE_KEY').replace(/\\\\n/g, '\\n'),
      requireEnv('APPLE_KEY_ID'), requireEnv('APPLE_ISSUER_ID'),
      requireEnv('APPLE_BUNDLE_ID'), appleEnvironment
    );
    const result = await api.getAllSubscriptionStatuses(originalTransactionId);
    if (result.bundleId !== requireEnv('APPLE_BUNDLE_ID') ||
        result.environment !== requestedEnvironment ||
        (requestedEnvironment === 'Production' && Number(result.appAppleId) !== Number(requireEnv('APPLE_APP_ID'))))
      throw new Error('apple_status_identity_mismatch');
    const verify = verifier(appleEnvironment);
    const transactions = [];
    for (const group of result.data ?? []) {
      for (const item of group.lastTransactions ?? []) {
        if (!item.signedTransactionInfo) continue;
        const t = await verify.verifyAndDecodeTransaction(item.signedTransactionInfo);
        if (t.environment !== requestedEnvironment || t.bundleId !== requireEnv('APPLE_BUNDLE_ID') ||
            t.originalTransactionId !== originalTransactionId ||
            !['scipic.premium.monthly','scipic.premium.annual'].includes(t.productId))
          throw new Error('apple_transaction_identity_mismatch');
        const renewal = item.signedRenewalInfo
          ? await verify.verifyAndDecodeRenewalInfo(item.signedRenewalInfo) : null;
        transactions.push({
          transactionId: t.transactionId, originalTransactionId: t.originalTransactionId,
          productId: t.productId, status: Number(item.status),
          purchaseDate: t.purchaseDate ?? null, signedDate: t.signedDate ?? null, expiresDate: t.expiresDate ?? null,
          revocationDate: t.revocationDate ?? null,
          appAccountToken: t.appAccountToken ?? null,
          autoRenewStatus: renewal?.autoRenewStatus ?? null
        });
      }
    }
    if (!transactions.length) throw new Error('no_verified_transactions');
    return json(res, 200, { ok: true, environment: requestedEnvironment, transactions });
  } catch (error) {
    console.error('apple_subscription_status_failed', String(error?.message ?? 'unknown').slice(0, 120));
    return json(res, 503, { error: 'apple_status_unavailable' });
  }
}

const server = http.createServer(async (req, res) => {
  const pathname = new URL(req.url ?? '/', 'http://localhost').pathname;
  if (req.method === 'GET' && pathname === '/health') return json(res, 200, { ok: true });
  if (req.method === 'POST' && pathname === '/internal/apple/subscription-status') return subscriptionStatus(req, res);
  if (req.method !== 'POST' || pathname !== '/apple/notifications') return json(res, 404, { error: 'not_found' });
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
