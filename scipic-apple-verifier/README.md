# SciPic Apple notification verifier (draft)

Node.js service for verifying Apple App Store Server Notifications V2 using Apple's official library.

## Status
**Draft, not production-ready.** Do not point Apple notifications here until the downstream Supabase HMAC-authenticated ingest endpoint is deployed, replay/idempotency protection is tested, and Apple Sandbox delivery passes.

## Configuration
- APPLE_BUNDLE_ID
- APPLE_APP_ID
- APPLE_ROOT_CA_CERTS_BASE64: comma-separated base64-encoded DER root certificates
- SCIPIC_INGEST_SHARED_SECRET: random secret shared only with the Supabase ingest function
- SCIPIC_VERIFIED_INGEST_URL: authenticated ingest function URL
- PORT: optional (Render provides it)

Do not commit credentials. Render deploy settings: root directory `scipic-apple-verifier`, build `npm install`, start `npm start`.

The service accepts POST /apple/notifications and GET /health. The receiving Supabase function must validate the HMAC against the **exact raw request body**, use timing-safe comparison, and enforce notification UUID replay protection. It must not blindly grant Premium based on client-supplied claims.
