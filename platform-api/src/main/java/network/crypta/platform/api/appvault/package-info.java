/**
 * App-principal Platform API routes for the app secret and identity vault.
 *
 * <p>The package contains the request-to-service adapter for {@code /api/v1/app-vault}. It assumes
 * the router has already authenticated either an app process token or an app browser session and
 * has checked the capability contract. The authenticated app id, not a request parameter, is the
 * authority for every vault operation.
 *
 * <p>The route family keeps browser-safe workflows separate from process-only material access.
 * Static app UI can list identity metadata, create app-owned identities, submit token-free grant
 * requests for operator review, and request bounded profile-document, trust-statement, or
 * social-message signing for identities the app can use. Secret reads, secret writes, and generic
 * identity use remain process-only in the contract so private material and arbitrary signing are
 * not exposed to browser JavaScript by accident.
 *
 * <p>Responses from this package are designed for public Platform API JSON. They omit raw private
 * keys, wrapping keys, local filesystem paths, process tokens, browser-session tokens, and secret
 * values in list or status views. When a route legitimately returns a secret value, it is scoped to
 * the calling app process and encoded under an explicit value field rather than hidden inside
 * metadata.
 */
package network.crypta.platform.api.appvault;
