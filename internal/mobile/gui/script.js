document.addEventListener('DOMContentLoaded', function() {
  const form = document.getElementById('createForm');
  const status = document.getElementById('status');
  const passkeySection = document.getElementById('passkeySection');
  const passkeyDisplay = document.getElementById('passkeyDisplay');
  const copyBtn = document.getElementById('copyPasskey');

  form.addEventListener('submit', async function(e) {
    e.preventDefault();
    status.textContent = 'Creating account and generating passkey (WebAuthn)...';
    passkeySection.style.display = 'none';
    try {
      // 1. Get registration options from backend
      const optResp = await fetch('/api/webauthn/register/options', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      const options = await optResp.json();
      // 2. Convert options to proper format for WebAuthn
      options.challenge = base64ToArrayBuffer(options.challenge);
      options.user.id = base64ToArrayBuffer(options.user.id);
      // 3. Call WebAuthn API
      const cred = await navigator.credentials.create({ publicKey: options });
      // 4. Prepare attestation for backend
      const attestation = {
        id: cred.id,
        rawId: arrayBufferToBase64(cred.rawId),
        type: cred.type,
        response: {
          clientDataJSON: arrayBufferToBase64(cred.response.clientDataJSON),
          attestationObject: arrayBufferToBase64(cred.response.attestationObject)
        }
      };
      // 5. Send attestation to backend for verification
      const verifyResp = await fetch('/api/webauthn/register/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(attestation)
      });
      const verifyData = await verifyResp.json();
      if (verifyResp.ok && verifyData.status === 'ok') {
        status.textContent = 'Account created! Passkey registered.';
        passkeyDisplay.textContent = cred.id;
        passkeySection.style.display = 'block';
      } else {
        status.textContent = verifyData.error || 'Failed to verify passkey.';
      }
    } catch (err) {
      status.textContent = 'Error: ' + err;
    }
  });

  copyBtn.addEventListener('click', function() {
    navigator.clipboard.writeText(passkeyDisplay.textContent);
    status.textContent = 'Passkey ID copied to clipboard!';
  });

  // Helper functions for base64url <-> ArrayBuffer
  function base64ToArrayBuffer(base64) {
    base64 = base64.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4;
    if (pad) base64 += '='.repeat(4 - pad);
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }
  function arrayBufferToBase64(buf) {
    const bytes = new Uint8Array(buf);
    let str = '';
    for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
});
