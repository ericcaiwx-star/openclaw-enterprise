import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { oidcLoginConfiguration } from "../../apps/controller/src/auth/oidc.ts";
import { providerJSON } from "../../apps/controller/src/auth/provider-transport.ts";

// Real Keycloak, prepared by scripts/ci/prepare.mjs for the keycloak-oidc lane
// (docs/testing/keycloak.md): it imports tests/fixtures/keycloak/realm-oce.json and serves
// https://keycloak.oce.localhost on 127.0.0.1:443 under a per-run CA that this process
// trusts through NODE_EXTRA_CA_CERTS. Nothing here is stubbed.
const issuer = process.env.OCC_TEST_KEYCLOAK_ISSUER;
const secretsFile = process.env.OCC_TEST_KEYCLOAK_SECRETS_FILE;
const missing = !issuer || !secretsFile || !process.env.NODE_EXTRA_CA_CERTS;
// The lane fails on a skip; outside it, this names what is missing.
const requiresKeycloak = missing
  ? "requires the keycloak-oidc lane's prepared Keycloak (docs/testing/keycloak.md)"
  : false;

function modulusBits(n) {
  const bytes = Buffer.from(n, "base64url");
  let leading = 0;
  while (leading < bytes.length && bytes[leading] === 0) {
    leading += 1;
  }
  const top = bytes[leading] ?? 0;
  return (bytes.length - leading - 1) * 8 + (32 - Math.clz32(top));
}

test(
  "Keycloak discovery matches the configured endpoints and its JWKS offers an RS256 key of 2,048 bits or more",
  { skip: requiresKeycloak },
  async () => {
    const secrets = JSON.parse(await readFile(secretsFile, "utf8"));
    const response = await fetch(`${issuer}/.well-known/openid-configuration`, {
      signal: AbortSignal.timeout(10_000),
    });
    assert.equal(response.status, 200);
    const discovery = await response.json();

    // OCE does no runtime discovery: an operator copies these four values into its
    // configuration. Production parsing must accept them as Keycloak publishes them, which
    // is the endpoint rule (HTTPS, port 443, one DNS host, issuer without a port).
    const config = oidcLoginConfiguration({
      OCC_AUTH_OIDC_ISSUER: discovery.issuer,
      OCC_AUTH_OIDC_AUTHORIZATION_URL: discovery.authorization_endpoint,
      OCC_AUTH_OIDC_TOKEN_URL: discovery.token_endpoint,
      OCC_AUTH_OIDC_JWKS_URL: discovery.jwks_uri,
      OCC_AUTH_OIDC_CLIENT_ID: secrets.clientId,
      OCC_AUTH_OIDC_CLIENT_SECRET: secrets.clientSecret,
    });
    // `iss` is compared with the configured string, so it must be the lane's exact issuer.
    assert.equal(config.issuer, issuer);
    assert.equal(config.authorizationUrl, `${issuer}/protocol/openid-connect/auth`);
    assert.equal(config.tokenUrl, `${issuer}/protocol/openid-connect/token`);
    assert.equal(config.jwksUrl, `${issuer}/protocol/openid-connect/certs`);
    assert.ok(discovery.code_challenge_methods_supported.includes("S256"));
    assert.ok(discovery.id_token_signing_alg_values_supported.includes("RS256"));
    for (const method of ["client_secret_post", "client_secret_basic"]) {
      assert.ok(discovery.token_endpoint_auth_methods_supported.includes(method), method);
    }

    // The controller's own bounded transport reads the JWKS, as it does at each callback.
    const jwks = await providerJSON(config.jwksUrl, {}, AbortSignal.timeout(10_000), "jwks");
    const signing = jwks.keys.filter((key) => key.use === "sig" && key.alg === "RS256");
    assert.ok(signing.length > 0, "the realm offers an RS256 signing key");
    for (const key of signing) {
      assert.equal(key.kty, "RSA");
      assert.equal(typeof key.kid, "string");
      assert.ok(key.kid.length > 0);
      assert.ok(modulusBits(key.n) >= 2048, `RS256 key ${key.kid} is at least 2,048 bits`);
    }
  },
);
