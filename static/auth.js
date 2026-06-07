// Browser-side WebAuthn helpers for registration and login.
//
// webauthn-rs emits/consumes base64url for every binary field, so we convert
// between base64url strings and ArrayBuffers around navigator.credentials.

function b64urlToBuf(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4 ? "=".repeat(4 - (s.length % 4)) : "";
  const bin = atob(s + pad);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

function bufToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Convert the JSON `publicKey` options from the server into the binary form
// navigator.credentials expects.
function decodeCreationOptions(opts) {
  opts.challenge = b64urlToBuf(opts.challenge);
  opts.user.id = b64urlToBuf(opts.user.id);
  if (opts.excludeCredentials) {
    opts.excludeCredentials = opts.excludeCredentials.map((c) => ({
      ...c,
      id: b64urlToBuf(c.id),
    }));
  }
  return opts;
}

function decodeRequestOptions(opts) {
  opts.challenge = b64urlToBuf(opts.challenge);
  if (opts.allowCredentials) {
    opts.allowCredentials = opts.allowCredentials.map((c) => ({
      ...c,
      id: b64urlToBuf(c.id),
    }));
  }
  return opts;
}

function encodeAttestation(cred) {
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64url(cred.response.clientDataJSON),
      attestationObject: bufToB64url(cred.response.attestationObject),
    },
    // webauthn-rs tolerates an empty extensions object.
    extensions: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
  };
}

function encodeAssertion(cred) {
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64url(cred.response.clientDataJSON),
      authenticatorData: bufToB64url(cred.response.authenticatorData),
      signature: bufToB64url(cred.response.signature),
      userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : null,
    },
    extensions: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
  };
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    credentials: "same-origin",
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `request failed (${res.status})`);
  return data;
}

async function doRegister(handle, displayName) {
  const challenge = await postJson("/auth/register/start", {
    handle,
    display_name: displayName,
  });
  const publicKey = decodeCreationOptions(challenge.publicKey);
  const cred = await navigator.credentials.create({ publicKey });
  const result = await postJson("/auth/register/finish", encodeAttestation(cred));
  window.location.href = result.redirect || "/";
}

async function doLogin(handle) {
  const challenge = await postJson("/auth/login/start", { handle });
  const publicKey = decodeRequestOptions(challenge.publicKey);
  const cred = await navigator.credentials.get({ publicKey });
  const result = await postJson("/auth/login/finish", encodeAssertion(cred));
  window.location.href = result.redirect || "/";
}

function wire() {
  const reg = document.getElementById("register-form");
  if (reg) {
    reg.addEventListener("submit", async (e) => {
      e.preventDefault();
      const err = document.getElementById("register-error");
      err.textContent = "";
      try {
        await doRegister(
          document.getElementById("reg-handle").value.trim(),
          document.getElementById("reg-display").value.trim()
        );
      } catch (e) {
        err.textContent = e.message;
      }
    });
  }
  const login = document.getElementById("login-form");
  if (login) {
    login.addEventListener("submit", async (e) => {
      e.preventDefault();
      const err = document.getElementById("login-error");
      err.textContent = "";
      try {
        await doLogin(document.getElementById("login-handle").value.trim());
      } catch (e) {
        err.textContent = e.message;
      }
    });
  }
  // Confirm-before-submit for forms marked with data-confirm (replaces the
  // inline onsubmit handlers that a strict CSP would block).
  document.querySelectorAll("form[data-confirm]").forEach((f) => {
    f.addEventListener("submit", (e) => {
      if (!window.confirm(f.getAttribute("data-confirm"))) e.preventDefault();
    });
  });
}

document.addEventListener("DOMContentLoaded", wire);
