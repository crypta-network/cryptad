/**
 * Host/operator beta dashboard and support-bundle helpers for Platform API v1.
 *
 * <p>The package builds redacted local-management summaries from existing app-platform services.
 * {@link network.crypta.platform.api.operator.OperatorBetaDashboardService} assembles the
 * dashboard, support bundle, health warnings, and recovery actions that the local Web Shell can
 * render for beta operators. {@link network.crypta.platform.api.operator.OperatorSupportRedactor}
 * performs the final structural and pattern-based scrub before support evidence is exported.
 *
 * <p>This package is intentionally outside the app-facing Platform API compatibility contract.
 * Routes that use these helpers must require the host/operator principal and must not grant app
 * origins cross-app visibility or management rights. Dashboard payloads may include safe counts,
 * stable status strings, bounded digests, and route references, but they must not expose app
 * tokens, browser sessions, private insert URIs, raw content bodies, raw diagnostics, command
 * lines, or local filesystem paths.
 */
package network.crypta.platform.api.operator;
