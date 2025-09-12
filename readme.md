Full, end-to-end design — account creation, login, logout, add/remove device, delete account, account recovery, heartbeat, kill connection, connect with a service, and maintain a session while using a service — explained in incredible detail

I’ll walk you through each flow as if you’re building SLQRPDF for real. For every flow I’ll list: purpose, actors, preconditions, step-by-step messages (with example JSON), cryptography used, server state changes, security checks, failure handling, logging/audit, and UX notes. I’ll also give concrete recommendations (nonce sizes, TTLs, algorithms) and explain trade-offs. This is long — but it’s meant to be a single reference you can use for implementation and for your science-fair documentation.

High-level security model (ground rules that apply everywhere)

Private secrets never leave the device.

SecretD = device private key / secret. Stored in Secure Enclave / Keystore when possible; otherwise encrypted and access-controlled by biometrics.

Server stores only public verifiers or encrypted blobs.

SecretK on server is stored either as a public key or as PQC/KEM-encrypted ciphertext (see prior Kyber discussion).

Transport: TLS 1.3 everywhere, certificate pinning or mTLS for highest assurance.

Signing & verification: Use hybrid approach: hardware signature (Ed25519/ECDSA) + PQC (Dilithium) if you need PQC readiness.

AEAD: use AES-GCM or XChaCha20-Poly1305 for symmetric encryption at rest and in transit for application payloads.

Nonces & replay protection: Server issues cryptographically random nonces (≥ 32 bytes) and marks them used.

Rate limiting & anomaly detection: throttling at endpoints and behavioral scoring.

Audit logs: append-only audit of critical events (enroll, login, revoke) with signed digests.

Key management: master keys live in KMS/HSM. Rotate keys and maintain versioning.

1 — Account creation (registration / first device enrollment)

Purpose: Create a new user identity on the server and bind at least one device (the user’s initial device) so it can authenticate later.

Actors: Device (client app or browser+native helper), Server (SLQRPDF backend), optionally an HSM/KMS.

Preconditions: TLS connection established; server has KMS/HSM access; device has a secure storage primitive (Secure Enclave/Keystore) or at least can generate and store keys locally.

Step-by-step (high detail)

User action: "Create account" in app/UI.

Server: generates user_id = "u--" + UUID() and creates a user record in DB with status = pending.

DB fields: user_id, created_at, status, devices (empty list), encrypted_blob_path (optional), audit_log_id.

Device (local) — generate device identity:

Generate device private key(s):

priv_HW (hardware-backed key) using platform APIs (Secure Enclave / Android Keystore) — non-exportable.

Optionally priv_PQ (PQC signature key like Dilithium) generated in software, then wrapped with a symmetric key protected by the platform keystore.

Compute public keys:

pub_HW, pub_PQ.

Create a device_handle (server-visible) such as d--<uuid> (for demo). For production, device_handle is assigned by server on enroll response.

Device — attestation (strongly recommended):

On enrollment, request attestation from platform:

Android Key Attestation → returns cert chain and attestation fields.

iOS App Attest / DeviceCheck flow → returns attest token.

This ties the key to hardware and can be required by server policy.

Device → Server: POST /enroll

{
"user_id": "u--xxx",
"device_display_name": "Harry's iPhone",
"pub_hw": "<base64 or PEM>",
"pub_pq": "<base64>",
"attestation": "<attestation_blob>",
"client_metadata": {
"app_version": "1.0.0",
"os": "iOS 18.0"
}
}


Transport: TLS + ephemeral client nonce.

Server — verify attestation + policy

Validate certificate chain (Android) or App Attest with Apple service (iOS). Enforce key_origin == hardware if required.

Create device DB entry:

device_id: d--uuid
user_id: u--uuid
pub_hw, pub_pq
attestation_result
status: active
created_at, last_seen
policy_flags (strongbox, has_attestation, etc.)


Produce short-lived enroll_token if further steps needed (e.g., for out-of-band verification).

Server — create initial secrets and write encrypted user file (optional)

Option A: server generates user file skeleton and encrypts it with a server-side master KMS key (AEAD), storing path in DB.

Option B (recommended): keep minimal server state (user row, device public keys) and let secrets reside on device (preferred for privacy).

Server → Device response:

{
"status": "ok",
"user_id": "u--uuid",
"device_id": "d--uuid",
"session_token": "<JWT or opaque token>",
"refresh_token": "<opaque refresh token, optional>"
}


session_token is device-bound (claims include device_id, user_id, token_id, issued_at, exp).

Device — store local metadata:

Store device_id, user_id, and local secrets (priv_HW, wrapped priv_PQ, TOTP seeds) in secure store.

Server — audit log entry: sign and append: ENROLL,user_id,device_id,timestamp,client_ip,....

Security checks / validations:

Attestation result must match policy (hardware-backed, OS patch level, app build hash).

Rate limit enroll attempts per IP.

If registration requires out-of-band confirmation (email, SMS), combine with enroll token flow.

Failure cases:

Attestation fails → server returns error and user retries.

Device cannot generate hardware keys → allow soft enrollment but mark lower trust.

UX notes:

Show clear instructions about biometric prompts and that private keys never leave device.

Offer multi-device enrollment during setup (register backup device).

2 — Login (authenticate)

Purpose: Prove to server that the device (and therefore the user sitting at that device) holds the private key bound to the account.

Actors: Device (client), Server.

Preconditions: Device is enrolled (server has pub_HW/pub_PQ), TLS established.

High-level alternatives

Passwordless/Passkeys (WebAuthn style): device signs server challenge with private key.

TOTP fallback: if passkey unavailable, server accepts TOTP codes derived from stored seed (less secure).

Hybrid: require both hardware signature + OTP for very high-security flows.

Step-by-step (primary flow: challenge-response using device key)

Client → Server: POST /auth/challenge

{ "user_id": "u--uuid", "device_id": "d--uuid", "requested_scope": ["login"] }


Server:

Validate user_id and device_id.

Generate nonce = random(32 bytes) (cryptographically random).

Store nonce record: {nonce, user_id, device_id, expires_at = now + 30s, used=false}.

Optionally include challenge_context (timestamp, server_sign) to prevent replay if challenge is proxied.

Server → Client:

{ "nonce": "<base64>", "expires_in": 30, "server_info": { "timestamp": "..." } }


Client (device) — sign the nonce:

Optionally compute to_sign = HMAC_SHA256(nonce || session_info) or canonical message format (WebAuthn uses CBOR & clientData).

sig_HW = Sign(priv_HW, to_sign) — Secure Enclave prompts biometrics if required.

Optionally sig_PQ = Sign(priv_PQ, to_sign) (if using hybrid).

Package any local attestation or device fingerprint.

Client → Server: POST /auth/verify

{
"user_id":"u--uuid",
"device_id":"d--uuid",
"nonce":"<base64>",
"sig_hw":"<base64>",
"sig_pq":"<base64 optional>",
"client_metadata":{ "app_version":"", "geo":"approx" }
}


Server verification steps:

Look up nonce, ensure used==false and not expired. Mark as used immediately (atomic).

Load device.pub_hw (and pub_pq).

Verify sig_hw using pub_hw over the expected message format.

If hybrid policy requires sig_pq, verify it with pub_pq.

Check device status: not revoked.

Perform anti-replay/anti-reproxy checks: confirm client_metadata plausible (IP geolocation vs last_seen, UA string).

On success, create a session record and issue tokens.

Server → Client (success):

{
"session_token": "<JWT or opaque>",
"expires_in": 900,
"refresh_token": "<opaque>",
"device_policy": { "session_bound_to_device": true }
}


Session token design (recommendation):

Use short-lived access token (e.g., 15 min) containing:

sub = user_id

device = device_id

session_id = s--uuid

iat, exp

token_type = access

Use refresh token (longer TTL: 7–30 days) stored server-side or as a rotating opaque token; bind refresh to device ID.

Server state changes:

Create session record: session_id, user_id, device_id, issued_at, expires_at, status.

Update device last_seen.

Audit log: LOGIN_SUCCESS with risk score, geolocation, app build.

Failure handling:

Bad signature → 401 Unauthorized, increment failed auth counters, anti-brute force measures.

Nonce expired/reused → require new challenge.

Device revoked → 403 Forbidden.

Security notes:

Always mark nonces used atomically to prevent replay.

Use a canonical message to sign (include origin, challenge, server domain) to avoid signature being reused in different contexts.

3 — Logout

Purpose: Invalidate a session so it can no longer be used.

Actors: Client requesting logout, Server.

Steps

Client → Server: POST /session/logout

{ "session_token": "<bearer>" }


Server:

Authenticate token (if JWT: verify signature and check claims).

Mark session record status = logged_out and set expires_at = now.

Add session_id to revocation list/cache until token expiry.

Optionally push a notification to the device (if connected) acknowledging logout.

Audit log: LOGOUT.

Client cleanup:

Erase local in-memory access token, optionally clear refresh token and local caches.

Notes:

If sessions are stateless JWTs, maintain a server revocation set (cache) for immediate invalidation.

If using opaque tokens, server can just destroy the refresh token and session entry.

4 — Adding a device (multi-device support / replace device)

Goal: Allow a user to register an additional device for the same user account while keeping SecretD device-bound and manageable.

Challenges: Device IDs may change often; users may not be physically co-located.

Common secure approaches (choose based on security/usability tradeoff)
A) QR + existing device approval (best UX & secure)

User is logged in on device A and wants to add device B.

Device B shows a QR with a one-time ephemeral enrollment code (or generates code after contacting server).

Device A scans QR and approves enrollment via a signature with priv_HW.

Server links device B to user if Device A approves.

Flow (QR approval):

Device B → Server: POST /enroll_request { device_info } → Server returns ephemeral_code (e.g., 128-bit), code_expires.

Device B shows QR with ephemeral_code.

Device A scans QR; Device A → Server POST /approve_enroll { user_id, ephemeral_code } and signs approval using priv_HW.

Server verifies signature, links Device B (generates device_id_b), returns enrollment confirmation to B.

Device B fetches POST /enroll_confirm?code=... to retrieve final device id.

B) Out-of-band email + second factor (less secure)

Server emails a one-time link to account email; the new device opens link and completes attestation. Useful as fallback.

C) Recovery codes or trusted devices (if no logged device)

Use previously issued one-time recovery codes (printed and stored offline) to authorize new device.

Device ID rotation handling

Do not rely on raw OS UUIDs (they can change or be unavailable). Use hardware key binding:

On enrollment, server stores pub_HW and device_handle.

Device ID becomes device_handle assigned by server (stable from server perspective even if OS IDs change internally).

If device OS regenerates ephemeral IDs, the private key still exists and signs enrollment proofs, so device remains valid.

Server DB changes:

Add new device row: store pub_hw, pub_pq, device_display_name, created_at, status.

Audit log: DEVICE_ADD.

5 — Removing a device (revoke device)

Purpose: Remove a device’s ability to authenticate (e.g., device lost).

Actors: User (via UI), Server, optionally an admin.

Steps

Authorization: User must re-authenticate (strongly) to remove a device. If user lost access to all devices, use account recovery flow.

Client → Server: POST /device/revoke

{ "user_id":"u--uuid", "device_id":"d--uuid", "reason":"lost", "auth_proof":"<signature>" }


Server actions:

Verify auth proof (user must sign a challenge).

Mark device.status = revoked.

Invalidate all sessions associated with device_id (mark session status revoked; add to revocation cache).

Optionally mark pub_hw as blacklisted.

Notify user via email and other devices.

Audit log: DEVICE_REVOKE.

Security notes:

If device compromise suspected, rotate server-side keys (if symmetric) and re-issue new tokens for remaining devices.

For very high-security apps, push push notifications to remaining devices to alert of revocation.

6 — Delete account

Purpose: Remove all personal data, keys, and revoke access. Must consider legal and audit requirements.

Steps (secure deletion)

Authenticate: Only allow deletion if user authenticates strongly (current device sign + biometric).

Server pre-checks: warn user about irreversible actions, provide recovery window option.

Server actions:

Mark user.status = deleting and set deletion_scheduled_at = now + grace_period (optional).

Revoke all associated devices: status = revoked.

Expire and remove sessions and refresh tokens.

Zeroize secrets:

Delete pub_keys or mark them as deleted.

Delete encrypted blobs from storage (encrypted_data/users/u--uuid.json.enc) — overwrite if possible.

Remove PII according to policy (or move to pseudonymous archive if needed for audit).

Append audit record of deletion (signed digest) and optionally keep an audit hash for legal/accounting reasons but not PII.

Confirmation: Send user a deletion confirmation email.

Compliance:

Respect GDPR / local laws for data deletion and record retention. Provide a record of deletion if required.

7 — Account recovery (lost device / passwordless user)

Problem: Device had SecretD and was lost. How does user regain account access without creating a backdoor?

Principles: Recovery is the toughest security/usability tradeoff. The more convenient the recovery, the lower the security.

Practical recovery options (ordered by security)

Multi-device recovery (best):

Encourage users to register a second device during setup.

To recover: use second trusted device to re-enroll new device.

Recovery codes (good if stored offline):

Generate N one-time recovery codes at enrollment (store locally or print).

Each code is a high-entropy secret (≥ 20 chars) used to authenticate a new device.

Codes are single-use; store only hash on server.

Social / trustee recovery (Shamir-style):

Split recovery key into M shares given to trusted persons (or devices).

Reconstruct key only when threshold reached.

KYC / manual support (highest friction but secure):

Use identity verification (photo ID, video call) to re-establish account.

After verification, admin issues a recovery token.

Email/SMS fallback (weak):

Send a recovery link to account email; requires additional checks (e.g., past device fingerprint, IP) for moderate security.

Example recovery flow using recovery codes

User selects "recover account" → provides user_id.

Server following rate limiting: prompt for recovery_code.

Client submits recovery_code. Server checks hashed code against stored hashes and if unused.

Server issues ephemeral recovery_token valid for short time, user uses it on new device to enroll (flows similar to add device but with recovery_token).

Server invalidates used recovery code and logs event.

Security recommendations:

Make recovery a multi-step process (recovery code + email confirmation + phone).

Force re-enrollment of new device keys and rotate server hyperlinks.

8 — Heartbeat system (continuous verification / session liveness)

Purpose: Continuously confirm the active device still controls privD and session has not been hijacked. Useful for preventing mid-session takeover and ensuring rotating QR/PDF417 not misused.

Design choices:

Frequency is security vs battery usage tradeoff. For high-security apps you may use 3–10s; for normal apps 30s–60s is reasonable.

Each heartbeat is a signed ping including a monotonic counter and timestamp to prevent replay.

Heartbeat message (example)

Client → Server (heartbeat):

{
"session_id":"s--uuid",
"device_id":"d--uuid",
"ts":"2025-09-11T14:00:00Z",
"seq": 1234,
"nonce": "<random 32b>",
"sig": "<Sign(priv_HW, H(session_id||ts||seq||nonce))>"
}


Server checks:

Verify session_id exists and bound device_id matches.

Verify signature using stored pub_hw.

Ensure ts is within allowed skew (e.g., ±30s) and seq is monotonic (or store last seq and ensure increment).

Check nonce not used (or accept monotonic seq to avoid storing many nonces).

Update session.last_heartbeat and device.last_seen.

If heartbeat missing for N intervals → mark session as suspended or require reauth.

Server → Client response: small ACK, optionally with server nonce to challenge client on next heartbeat.

Failure modes:

Missing heartbeat beyond threshold → automatically pause session (freeze tokens), require reauth.

Reused seq or nonce → possible replay/fraud → kill session and alert.

Resource considerations:

Use lightweight transport (WebSocket or low-overhead HTTP POSTs). Consider binary, compressed heartbeat payloads.

For large deployments, aggregate heartbeats in a fast in-memory store (Redis) rather than DB writes per heartbeat.

9 — Kill connection (emergency revoke)

Purpose: Immediately terminate a session / device access.

Triggers: User revokes device; server detects compromise; admin action, anomaly detection.

Steps

Server marks session(s)/device(s) revoked in DB (atomic).

Server pushes revoke to connected clients:

If device has WebSocket or push channel, send KILL message containing token_id or session_id.

Otherwise, revoke tokens server-side (put in revocation cache) so further API calls fail.

Server invalidates refresh tokens and clears any long-lived keys.

Audit & alert: create KILL_SESSION audit log and send user notifications (email/SMS/other).

Optional: force password reset / reverify on other devices.

Client handling:

On receiving KILL, zeroize all secrets, present UI to user "Session terminated. Reauthenticate to continue."

Hard kill: For critical actions, server-side verification must always check revocation cache, not rely only on client signals.

10 — Connect with a third-party service (OAuth 2.0 style / service delegation)

Purpose: Let SLQRPDF authenticate the user to external services (e.g., a bank) or let services accept SLQRPDF as an identity provider.

Approach: Use standard protocols: OAuth 2.0 / OIDC with strong client authentication (mTLS or mutual DPoP) and token binding to device.

Flow (Authorization Code w/ PKCE + device binding)

User initiates connect to Service S via SLQRPDF UI.

SLQRPDF → Service: create authorization request with client_id, redirect_uri, scope, state, code_challenge (PKCE).

Service → User: shows consent page and issues auth_code to SLQRPDF via redirect_uri (or the server proxies it).

SLQRPDF server exchanges auth_code with Service’s token endpoint, using either:

Confidential client credentials (mTLS) plus proof of possession bound to device (DPoP) — or

A token minted by SLQRPDF that encapsulates device identity and is vouched by SLQRPDF.

Token binding: SLQRPDF attaches device binding info inside token (e.g., claim device_id and sign with server key). Optionally require Service to enforce signature or mTLS.

Service uses token to call SLQRPDF to validate device on each request (token introspection).

Security notes:

For high-security delegation, use mTLS between SLQRPDF and Service or JWT assertions signed by SLQRPDF’s HSM keys.

Bind tokens to device by including device_id in claims and requiring client to present a proof-of-possession (signature by device) when using token.

Example: SLQRPDF as identity provider (OIDC):

User logs into SLQRPDF on a device and consents to share identity with Service S.

SLQRPDF returns OIDC ID token + access token to S. ID token includes device_id and auth_time.

S can optionally call SLQRPDF to verify that device is alive (heartbeat) before allowing certain actions.

11 — Maintain a login while using a service (session continuity & re-auth)

Goal: Keep the user logged in while they use a third-party service, preserving strong device binding and preventing session theft.

Core mechanisms

Short access tokens + refresh tokens:

Access tokens: 5–15 min.

Refresh tokens: 7–30 days, rotation on each use (ROTATING refresh token).

Bind tokens to device (device_id claim).

Proof-of-possession (PoP):

Require client present PoP for access tokens: on each request sign a server nonce with privD (or use DPoP header) so bearer token alone is insufficient.

Periodic re-evidence:

For very long sessions, require a signature renewal every N minutes (device signs a small server nonce silently via keystore to avoid UX prompts).

On missing renewal, degrade privileges.

Continuous heartbeat + anomaly detection:

Heartbeats check device liveness. If device jumps geos/IPs rapidly or fails attestation checks, require re-auth.

Example API call with PoP (DPoP style):

Client HTTP request:

GET /service/data
Authorization: Bearer <access_token>
DPoP: <JWT_signed_by_privD_containing_http_method_and_url_and_ts_and_nonce>


Server verifies access token, then verifies DPoP JWT signature using pub_hw bound to the token. The DPoP token includes nonce issued for this call to prevent replay.

When to require fresh re-auth

Sensitive actions (transfer of funds, profile changes) — require interactive biometric re-auth.

Long inactivity or heartbeat failure — require re-auth.

12 — Logging, auditing, monitoring

What to log (append-only, secure):

Enrollment events (ENROLL, device info, attestation result).

Login attempts (success/fail, device_id, location, risk score).

Device add/remove/revoke.

Key rotation events.

Heartbeat misses and kills.

Account deletion and recovery events.

How to store logs:

Signed append-only logs (Merkle tree or chained HMACs).

Store logs in immutable storage; limit retention for compliance.

Access to logs gated by role-based access control.

Alerting:

High rate of failed logins for a user/device.

Attestation failures or downgrade.

New device enroll in different country within impossible travel window.

13 — Database schema (suggested minimal)

users table

user_id (PK)

created_at, status, primary_email_hash

recovery_hashes

encrypted_meta_blob_path (optional)

devices table

device_id (PK)

user_id (FK)

pub_hw (PEM/base64)

pub_pq (PEM/base64)

attestation_json

status (active/revoked)

created_at, last_seen, last_attested_at

name, platform, app_version

sessions table

session_id (PK)

user_id, device_id

issued_at, expires_at, status

last_heartbeat

token_hash (if storing refreshs)

nonces table

nonce (PK)

user_id, device_id, expires_at, used (bool)

audit_log table

id, user_id, device_id, event_type, payload, timestamp, signature

14 — Concrete cryptography choices & parameters (recommended)

Nonce: 32 bytes random (crypto/rand).

Signature primitive: ed25519 (fast) + optional Dilithium for PQC hybrid.

AEAD: XChaCha20-Poly1305 or AES-GCM with 256-bit key (preferred: XChaCha for nonce convenience).

KDF: HKDF-SHA256 or HKDF-SHA3-512.

TOTP: base32 seed 160 bits for RFC algorithm; prefer device bound passkey instead of TOTP.

Session tokens: short JWTs signed by HSM using RSASSA-PSS or EdDSA with key id. For PQC, include dual signature in header if hybrid.

Master keys: stored in KMS/HSM; rotate annually or on suspicion.

15 — Performance & scale considerations

Avoid DB writes on every heartbeat — aggregate or write to in-memory store (Redis) and flush periodically.

Cache public keys and attestation verification results in memory for speed.

Use a distributed revocation cache (Redis) for fast token checks.

WebSocket or push channels can be used for quick kill notifications.

16 — UX & human considerations

Show clear messages when biometric prompt is required.

Provide fallback flows and recovery but make them rigorous.

For science fair, provide a visible log of every step (enroll → login → heartbeat → revoke) to demonstrate properties.

17 — Example JSON endpoints summary (quick reference)

POST /enroll — enroll device (pub keys + attestation). Returns device_id.

POST /auth/challenge — server returns nonce.

POST /auth/verify — client posts signatures + nonce, server issues session_token.

POST /session/logout — invalidate session.

POST /device/revoke — revoke device.

POST /device/add-request — create QR code for adding device.

POST /device/approve-add — approve add from existing device.

POST /account/delete — request deletion (requires reauth).

POST /recover — begin recovery using recovery code / recovery token.

POST /heartbeat — signed ping to demonstrate liveness.

POST /kill — admin action to kill session (internal).

GET /introspect — introspect a token (internal/security service).

18 — Threats you still must design for

Local device compromise: root/jailbreak may allow key extraction; mitigate via secure enclave, attestation checks, and root/jailbreak detection.

Supply chain: malicious app builds; use signed builds & reproducible builds.

Server compromise: attacker could change policies or issue tokens; KMS/HSM and threshold signing can reduce risk.

Phishing and social engineering: attacker trick user into approving enrollment; reduce via out-of-band confirmations and clear UI.

Quantum era: use hybrid signatures (classical + PQC).

Final practical checklist for implementation (step-by-step)

Implement secure key generation on devices (hardware keys + optional wrapped PQC keys).

Build server endpoints for enroll/challenge/verify with nonce and attestation verification.

Issue short access tokens + rotating refresh tokens; bind tokens to device_id.

Implement heartbeat system using signed, monotonic messages; maintain in-memory fast store for liveness.

Implement device add / QR approval flow (scan & approve).

Implement device revoke + session kill with immediate revocation cache checks.

Implement recovery options (multi-device + recovery codes + support KYC fallback).

Add robust logging & auditing; integrate monitoring & anomaly detection.

Perform threat modeling and a small security review (professor / local club) before demo.

Prepare UI screens to explain each step to users during demo (enroll, approve, revoke, recover).