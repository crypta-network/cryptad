/**
 * Host/operator-only RC recovery models and dispatcher for Platform API operator routes.
 *
 * <p>The package exposes a closed action-id allowlist, metadata-only plan/result envelopes, and a
 * bounded redacted audit list. It never dispatches arbitrary routes, shell commands, or
 * server-provided paths. Mutating actions call existing app-platform services so catalog
 * signatures, bundle digests, review trust, security advisory gates, migration gates, app-service
 * grant checks, and network budgets remain authoritative.
 *
 * <p>The recovery workflow is designed for the local operator Web Shell and support-bundle
 * evidence. Clients must plan an action first, execute with the matching one-use plan token, and
 * supply explicit confirmation for destructive operations. Read-only export actions can return
 * redacted summaries, while app-data backup payloads are restricted to explicit sensitive backup
 * responses.
 *
 * <p>This package does not implement remote support upload, arbitrary command execution, global Web
 * of Trust behavior, moderation, routing policy, legacy plugin runtime restoration, or FProxy
 * browse removal. Trust Graph recovery remains local operator-curated metadata only.
 */
package network.crypta.platform.api.operator.recovery;
