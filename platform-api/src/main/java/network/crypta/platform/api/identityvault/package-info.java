/**
 * Host/operator Platform API routes for managing vault identities and app-bound grants.
 *
 * <p>The package backs {@code /api/v1/identity-vault}, which is the management side of the app
 * secret and identity vault. These routes are intentionally separate from app-facing vault routes:
 * app processes and browser sessions cannot call them through the capability contract, and the
 * router requires the trusted local host/operator principal before dispatch.
 *
 * <p>Management responses expose public identity metadata, grant status, scopes, expiry, and review
 * annotations so the Web Shell can grant, revoke, and inspect access. They do not expose raw
 * private key material, app secret values, local filesystem paths, browser-session tokens, process
 * tokens, or wrapping keys. Operator actions still flow through the vault service so revocation,
 * audit, and app-update cleanup all use the same durable records.
 */
package network.crypta.platform.api.identityvault;
