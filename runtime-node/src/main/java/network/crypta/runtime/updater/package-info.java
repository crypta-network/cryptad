/**
 * Package providing the runtime updater subsystem.
 *
 * <p>This package coordinates discovery, download, integrity verification, and handoff for
 * installing newer versions of the runtime. Recent builds migrate to a package-based update flow
 * for the core ("CoreUpdater"), replacing self-replacement of {@code cryptad.jar}. Core updates
 * fetch a descriptor (for example, {@code info/<N>} over the existing update USK), select an
 * installer that matches the current OS and architecture, download it under a versioned directory,
 * and offer a guided installation.
 *
 * <p>The package also follows a separately versioned {@code support-lifecycle} document beneath the
 * configured public update key. That descriptor is independent of immutable historical {@code
 * core-info.json} files: it records mutable support status without changing a published release
 * identity. Runtime validation enforces the descriptor schema, update-key scope, monotonically
 * increasing edition and predecessor digest, closed status vocabulary, immutable release metadata,
 * and one current Stable build. Exact accepted bytes are stored as last-known-good public metadata,
 * so transient fetch failures expose stale or unknown state instead of guessing. A lifecycle build
 * revocation is deliberately distinct from update-key revocation and never invokes key-blow
 * behavior. Disabling package updates leaves the read-only lifecycle subscriber active, while an
 * actual update-key compromise stops it because that key can no longer authenticate lifecycle
 * state.
 *
 * <p>At a high level the updater strives to be robust, explicit, and user-driven. Network and file
 * operations surface progress and errors clearly, so callers can present actionable status to users
 * and retry when appropriate. Artifacts are written to a staging area {@code
 * nodeDir/updates/core/<version>/} and integrity is verified before any installation step is
 * attempted. For core upgrades, the system disables JAR Update-over-Mandatory (UOM) and avoids
 * directly replacing a running {@code cryptad.jar}; instead, it prefers OS-native package tools or
 * interactive installers depending on platform capabilities.
 *
 * <p>The code in this package owns updater state, discovery, download coordination, and
 * installation policy. HTTP exposure of updater actions now lives in the adapter layer under {@code
 * network.crypta.clients.http.updater}, which keeps request handling out of runtime coordination
 * code.
 *
 * <p>Notable behaviors and responsibilities:
 *
 * <ul>
 *   <li>Discovers the platform (OS and CPU architecture) and available package managers before
 *       selecting an installer.
 *   <li>Downloads installers to a predictable, versioned location and reports progress when
 *       available.
 *   <li>Validates content by cryptographic checks; only verified artifacts proceed to the
 *       installation or deploy phase.
 *   <li>Handles core updates via external installers (for example, DEB/RPM/DMG/EXE).
 *   <li>Coordinates the updater state machine that the HTTP adapter layer renders and drives.
 *   <li>Publishes a detached, redacted lifecycle snapshot for operator and Platform API surfaces.
 * </ul>
 *
 * <p>Concurrency and state: update actions perform blocking I/O and file-system work and should be
 * executed off the UI thread. The package is designed so repeated attempts are safe: partial
 * downloads and failed installations can be retried without corrupting existing installations.
 * Callers should ensure only one core installation attempt runs at a time for a given target
 * version to avoid conflicting file operations.
 *
 * <p>Platform specifics: on Linux, when a desktop is detected, the updater prefers handing off to a
 * graphical tool (for example {@code gio} or {@code xdg-open}). In sandboxed environments such as
 * Flatpak, helper bridges may be used to reach host tools. On macOS and Windows, installation is
 * typically guided by native installers; user messaging highlights common security prompts (for
 * example, Gatekeeper or SmartScreen) and offers checksum verification tips when appropriate.
 */
package network.crypta.runtime.updater;
