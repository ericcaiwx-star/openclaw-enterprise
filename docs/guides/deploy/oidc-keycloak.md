# Use Keycloak for OIDC sign-in

Keycloak is the identity provider (IdP) that OpenClaw Enterprise (OCE) checks
[OIDC sign-in](oidc-sign-in.md) against in CI. This page sets up a Keycloak realm
and client that OCE accepts and lists the flows CI verifies. Configure the chart,
attach identities and plan rotation with the [OIDC sign-in guide](oidc-sign-in.md).

## Supported version

Keycloak **26** is supported. CI pins one 26.x image by digest in
[`tests/fixtures/keycloak/image.json`](../../../tests/fixtures/keycloak/image.json)
and moves to a newer 26.x release by changing that pin. Other major versions are not
verified.

CI runs Keycloak with `start-dev` and its development file database. That is a test
setup, not a production one: run production Keycloak with `start`, a real database and
your own TLS, as the Keycloak server guides describe. The OCE requirements below are
the same for both.

## Requirements

OCE refuses an IdP that breaks its endpoint and token rules. For Keycloak, that means:

- **One HTTPS host on port 443.** The issuer, authorization, token and JWKS URLs share
  one DNS host name, written without a port, served over HTTPS on 443 with a
  certificate the API trusts. For a private CA, set `NODE_EXTRA_CA_CERTS` on the API.
  Keycloak can serve HTTPS itself or sit behind a TLS proxy on 443.
- **A fixed hostname.** Set `KC_HOSTNAME` (or `--hostname`) to the issuer's origin,
  for example `https://sso.example.com`, with no port and no path. Keycloak then
  publishes the issuer `${KC_HOSTNAME}/realms/<realm>`, which must equal
  `auth.oidc.issuer` character for character. Without a fixed hostname, Keycloak
  builds URLs from each request's host, and the token's `iss` can differ from the
  configured issuer.
- **No `.localhost` name when the API runs in a Pod.** The controller image resolves
  every `*.localhost` name to loopback, so the API cannot reach such a Keycloak. CI
  uses `keycloak.oce.localhost` only because its API runs as a host process.
- **An RS256 key of at least 2,048 bits.** The API accepts only RS256 ID tokens signed
  by an RSA key of 2,048 bits or more, named by its `kid` in the JWKS. Keycloak's
  default `rsa-generated` realm key meets this; keep the client's ID token signature
  algorithm at RS256 (the default).
- **No audience mapper.** A Keycloak ID token's `aud` is the client ID by default. The
  API refuses a token whose audience names anything else, so add no audience mapper
  to the client or its scopes.

API Pod egress to the Keycloak host is covered by the chart's OIDC NetworkPolicy. A
Keycloak that runs in the same cluster may need an
[extra egress policy](oidc-sign-in.md#configure-the-chart).

## Create the realm

These admin-console steps produce the realm that CI imports from
[`tests/fixtures/keycloak/realm-oce.json`](../../../tests/fixtures/keycloak/realm-oce.json).
Names are the ones CI uses; choose your own.

1. **Create realm:** realm name `oce`, enabled.
2. **Realm settings → General:** **Require SSL** `External requests`.
3. **Realm settings → Login:** turn off **User registration**, **Forgot password**,
   **Remember me** and **Login with email**. Leave **Duplicate emails** off.
4. **Clients → Create client:**
   - **General settings:** client type `OpenID Connect`, client ID `oce-console`,
     name `OCE Console`.
   - **Capability config:** **Client authentication** on. Under authentication flow,
     keep **Standard flow** and clear **Direct access grants**, **Implicit flow**,
     **Service accounts roles**, **Standard Token Exchange**, **OAuth 2.0 Device
     Authorization Grant** and **OIDC CIBA Grant**.
   - **Login settings:** one **Valid redirect URI**, `OCC_AUTH_BASE_URL` followed by
     `/api/auth/providers/oidc/callback`, for example
     `https://occ.example.com/api/auth/providers/oidc/callback`. Leave **Web origins**
     empty.
5. **The client's Settings tab → Logout settings:** turn off **Front channel logout**
   and **Backchannel logout session required**. OCE implements neither.
6. **The client's Advanced tab → Advanced settings:** set **Proof Key for Code Exchange
   Code Challenge Method** to `S256`.
7. **The client's Credentials tab:** keep **Client Id and Secret** as the client
   authenticator, which accepts both `client_secret_post` and `client_secret_basic`.
   Copy the client secret into the file you give the chart's Secret.
8. **Users → Add user** for each person: username, email with **Email verified**, first
   and last name. On the user's **Credentials** tab, set a password with **Temporary**
   off.

Leave the client scopes and mappers at their defaults. OCE requests only `openid` and
reads no email or profile claims.

To import the realm file instead, start Keycloak with `--import-realm` and the file in
`/opt/keycloak/data/import`. Set every `${VAR}` placeholder in its environment first:
`OCE_KEYCLOAK_CLIENT_SECRET`, `OCE_KEYCLOAK_REDIRECT_URI`,
`OCE_KEYCLOAK_ALICE_PASSWORD` and `OCE_KEYCLOAK_CAROL_PASSWORD`. Keycloak imports an
unset placeholder as its literal text, so an unset secret becomes a guessable one.
Import runs only when the realm does not exist yet.

## Find a person's subject

OCE attaches a person by the ID token's `sub`, which for Keycloak is the user's ID.

- **Admin console:** **Users →** the user **→ Details**, the **ID** field (a UUID).
- **Admin API:** `GET /admin/realms/<realm>/users?username=<name>&exact=true` returns
  it as `id`.

The admin console assigns random IDs. Only an import fixes them: the realm file gives
`alice` the ID `6f1c1e9a-3d4b-4c55-9a2e-0a11ce000001`. Attach the subject as the
[OIDC sign-in guide](oidc-sign-in.md#attach-and-detach) describes.

## Chart values

For realm `oce` on `https://sso.example.com`, copy these from
`https://sso.example.com/realms/oce/.well-known/openid-configuration`:

```yaml
auth:
  oidc:
    issuer: https://sso.example.com/realms/oce
    authorizationUrl: https://sso.example.com/realms/oce/protocol/openid-connect/auth
    tokenUrl: https://sso.example.com/realms/oce/protocol/openid-connect/token
    jwksUrl: https://sso.example.com/realms/oce/protocol/openid-connect/certs
    tokenAuth: client_secret_post # client_secret_basic is verified too
```

Set the client ID `oce-console`, the secret, `auth.recoveryUserId` and the other values
from [Configure the chart](oidc-sign-in.md#configure-the-chart).

## Verified flows

The `keycloak-oidc` CI lane signs in through the pinned Keycloak, the realm file and a
real browser, with the production API and its unmodified HTTPS transport. Each row is
one named test in
[`keycloak-oidc-sign-in.test.mjs`](../../../tests/integration/keycloak-oidc-sign-in.test.mjs).
The lane runs in full-mode pull request CI and on pushes to `main`. It is not
yet a dependency of `CI Required`; documentation-only and test-only CI modes
do not run it.

| Test                                                                                                                                                                        | What it shows for operators                                                                                                |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Keycloak discovery matches the configured endpoints and its JWKS offers an RS256 key of 2,048 bits or more                                                                  | The four values copied from discovery pass the API's endpoint rules, and the default realm key is accepted.                |
| attached alice signs in through Keycloak with client_secret_post                                                                                                            | An attached person signs in through Keycloak's own login form and lands in the Console.                                    |
| attached alice signs in through Keycloak with client_secret_basic                                                                                                           | The other `tokenAuth` setting works with the default client authenticator.                                                 |
| a higher-priority Keycloak realm key changes the signing kid and the next sign-in succeeds without a controller restart                                                     | Realm key rotation needs no OCE restart.                                                                                   |
| unattached carol is refused after Keycloak sign-in, audited and given no account                                                                                            | A valid Keycloak user without an attached OCE account is refused, audited as `EXTERNAL_IDENTITY_REJECTED`.                 |
| Console sign-out ends alice's OCE session, one click signs her in again while her Keycloak session lives, and disabling her keeps that session but refuses her next sign-in | Sign-out is local to OCE; disabling a user in Keycloak stops new sign-ins but not a live OCE session. Offboard in OCE too. |

Not verified: Keycloak behind a TLS proxy, Keycloak in the same cluster as the API,
and other major versions. To run the lane, read the [Keycloak OIDC lane](../../testing/keycloak.md).

## Related

- [Enable OIDC sign-in](oidc-sign-in.md)
- [External sign-in reference](../../reference/authentication/external-sign-in.md)
- [Keycloak OIDC lane](../../testing/keycloak.md)
