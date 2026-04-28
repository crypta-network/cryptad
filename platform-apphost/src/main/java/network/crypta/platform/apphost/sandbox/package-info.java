/**
 * Sandbox policy, launch planning, and status reporting for AppHost child processes.
 *
 * <p>This package defines the PR-206 sandbox runtime abstraction. The v1 providers expose requested
 * manifest policy and conservative launch-time status without claiming hard operating-system
 * containment unless a provider can actually enforce it.
 *
 * <p>The package has three responsibilities:
 *
 * <ul>
 *   <li>Represent the signed manifest request with {@link
 *       network.crypta.platform.apphost.sandbox.AppSandboxPolicy AppSandboxPolicy} and {@link
 *       network.crypta.platform.apphost.sandbox.AppSandboxRequirement AppSandboxRequirement}.
 *   <li>Give AppHost a provider SPI through {@link
 *       network.crypta.platform.apphost.sandbox.AppSandboxProvider AppSandboxProvider}, {@link
 *       network.crypta.platform.apphost.sandbox.AppSandboxLaunchContext AppSandboxLaunchContext},
 *       and {@link network.crypta.platform.apphost.sandbox.AppSandboxLaunchPlan
 *       AppSandboxLaunchPlan}.
 *   <li>Expose token-free runtime and inventory status through {@link
 *       network.crypta.platform.apphost.sandbox.AppSandboxStatus AppSandboxStatus} and {@link
 *       network.crypta.platform.apphost.sandbox.AppSandboxSupportLevel AppSandboxSupportLevel}.
 * </ul>
 *
 * <p>Provider implementations must treat launch contexts as sensitive. They contain the child
 * process environment, including the per-start app token, and host-owned filesystem paths. Public
 * status objects in this package are the safe boundary for Platform API and Web Shell display: they
 * should report requested mode, provider name, support level, and warnings without exposing command
 * lines, environment values, browser session tokens, or private paths.
 *
 * <p>The default providers intentionally distinguish current behavior from future hardening. {@link
 * network.crypta.platform.apphost.sandbox.NoSandboxProvider NoSandboxProvider} preserves the
 * existing local process launch path and reports no active sandbox isolation. {@link
 * network.crypta.platform.apphost.sandbox.RestrictedProcessSandboxProvider
 * RestrictedProcessSandboxProvider} reports best-effort AppHost launch hygiene only. Future
 * providers can add enforced OS or WASM isolation while reusing the same manifest and status
 * contracts.
 */
package network.crypta.platform.apphost.sandbox;
