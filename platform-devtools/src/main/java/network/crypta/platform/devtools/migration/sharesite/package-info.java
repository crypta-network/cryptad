/**
 * Offline, bounded, read-only conversion of selected Sharesite pastebin snapshots.
 *
 * <p>The decoder implements the pinned binary map format without loading legacy plugin classes.
 * Inspection and conversion outputs remain private user data, including their source and fidelity
 * bindings. The command tree requires a consistent stopped-writer snapshot and an owner-only output
 * workspace. This package grants no app permissions, performs no app-data commit, and never queues
 * network publication; those operations belong to the separately authenticated target application.
 */
package network.crypta.platform.devtools.migration.sharesite;
