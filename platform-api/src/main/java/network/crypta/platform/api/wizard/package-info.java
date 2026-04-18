/**
 * First-time-wizard Platform API handlers.
 *
 * <p>This package owns the detached wizard snapshot and submission endpoints introduced for
 * Platform API v1. Its purpose is to make the most important onboarding and reset flows reachable
 * from the Web Shell without redesigning the wizard domain model or bypassing the existing daemon
 * seams.
 *
 * <p>The package keeps the request model intentionally close to the legacy form flow. Callers send
 * checkbox-style booleans and raw text fields, the API layer validates only the transport-neutral
 * contract, and the daemon-backed wizard port still owns the actual onboarding side effects. That
 * split keeps the shell-native control plane practical while preserving the legacy wizard as a
 * fallback for flows that remain more specialized or password-heavy.
 */
package network.crypta.platform.api.wizard;
