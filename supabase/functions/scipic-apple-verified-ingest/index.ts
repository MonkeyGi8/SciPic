// Supabase Edge Function: scipic-apple-verified-ingest
// Authenticates the Node verifier's HMAC over the EXACT request body.
// The Node service MUST verify Apple's signedPayload cryptographically before forwarding.
// This endpoint records only notification metadata, and NEVER grants Premium.
import { createClient } from "npm:@supabase/supabase-js@2";

const encoder = new TextEncoder();
const json = (status: number, value: unknown) =>
  new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const hex = (buf: ArrayBuffer) => Array.from(new Uint8Array(buf)).map(x => x.toString(16).padStart(2, "0")).join("");
const constantTimeEqual = (a: string, b: string) => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
};

Deno.serve(async request => {
  if (request.method !== "POST") return json(405, { error: "method_not_allowed" });
  const secret = Deno.env.get("SCIPIC_INGEST_SHARED_SECRET");
  if (!secret || secret.length < 32) return json(503, { error: "not_configured" });
  const signature = request.headers.get("x-scipic-signature") ?? "";
  if (!/^[a-f0-9]{64}$/.test(signature)) return json(401, { error: "unauthorized" });

  // Limit by UTF-8 bytes, not JS string length.
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.byteLength > 250000) return json(413, { error: "too_large" });
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const computed = hex(await crypto.subtle.sign("HMAC", key, bytes));
  if (!constantTimeEqual(signature, computed)) return json(401, { error: "unauthorized" });

  let body: Record<string, unknown>;
  try { body = JSON.parse(new TextDecoder().decode(bytes)); }
  catch { return json(400, { error: "invalid_json" }); }
  const { environment, notificationUUID, notificationType, signedPayload, subtype, signedDate } = body;
  if ((environment !== "Production" && environment !== "Sandbox") ||
      typeof notificationUUID !== "string" || !/^[0-9a-fA-F-]{36}$/.test(notificationUUID) ||
      typeof notificationType !== "string" || !notificationType || notificationType.length > 80 ||
      typeof signedPayload !== "string" || signedPayload.length > 200000)
    return json(400, { error: "invalid_notification" });

  const url = Deno.env.get("SUPABASE_URL");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !serviceKey) return json(503, { error: "database_not_configured" });
  const db = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } });
  const digest = hex(await crypto.subtle.digest("SHA-256", encoder.encode(signedPayload)));
  const { data: existing, error: lookupError } = await db.from("apple_notification_events")
    .select("signed_payload_sha256").eq("environment", environment)
    .eq("notification_uuid", notificationUUID).maybeSingle();
  if (lookupError) return json(503, { error: "storage_unavailable" });
  if (existing) return existing.signed_payload_sha256 === digest
    ? json(200, { ok: true, duplicate: true })
    : json(409, { error: "notification_conflict" });

  const timestamp = typeof signedDate === "number" && Number.isFinite(signedDate)
    && signedDate > 0 && signedDate < 8640000000000000 ? new Date(signedDate).toISOString() : null;
  const { error } = await db.from("apple_notification_events").insert({
    environment, notification_uuid: notificationUUID, notification_type: notificationType,
    subtype: typeof subtype === "string" ? subtype.slice(0, 80) : null,
    signed_payload_sha256: digest, signed_at: timestamp, processing_status: "pending"
  });
  if (error?.code === "23505") return json(200, { ok: true, duplicate: true });
  if (error) return json(503, { error: "storage_unavailable" });
  return json(200, { ok: true, queued: true });
});
