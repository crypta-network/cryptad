/**
 * Platform-managed storage and authorization for app secrets and vault identities.
 *
 * <p>The app vault is transport-neutral. It stores encrypted local envelopes, redacted public
 * metadata, app-owned identity private material, operator-created identities, app-id-bound grants,
 * uninstall access blocks, and recent value-free audit events. HTTP, Web Shell, SDK, and CLI layers
 * remain responsible for route authentication, presentation, and developer workflow.
 *
 * <p>The package separates responsibilities deliberately. {@link
 * network.crypta.platform.appvault.AppVaultService} enforces app access, grant checks, lifecycle
 * cleanup, signing operations, and audit events. {@link
 * network.crypta.platform.appvault.AppVaultStore} owns the file layout and durable metadata. {@link
 * network.crypta.platform.appvault.AppVaultEnvelope} and {@link
 * network.crypta.platform.appvault.AppVaultKeyProvider} provide the local AES-GCM envelope
 * boundary.
 *
 * <p>The v1 implementation is intentionally conservative. It supports app-owned secrets and a real
 * local Ed25519 signing identity kind, while modeling future publisher and external-reference
 * identity kinds without exposing raw protocol keys or changing wire semantics.
 */
package network.crypta.platform.appvault;
