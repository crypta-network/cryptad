/**
 * Package providing the node's update subsystem.
 *
 * <p>This package coordinates discovery, download, integrity verification, and handoff for
 * installing newer versions of the node. Recent builds migrate to a package-based update flow for
 * the core ("CoreUpdater"), replacing self-replacement of {@code cryptad.jar}. Core updates fetch a
 * descriptor (for example, {@code info/<N>} over the existing update USK), select an installer that
 * matches the current OS and architecture, download it under a versioned directory, and offer a
 * guided installation. Plugin updates continue to use JAR downloads and deploys without changing
 * the running core binary.
 *
 * <p>At a high level the updater strives to be robust, explicit, and user-driven. Network and file
 * operations surface progress and errors clearly so callers can present actionable status to users
 * and retry when appropriate. Artifacts are written to a staging area {@code
 * nodeDir/updates/core/<version>/} and integrity is verified before any installation step is
 * attempted. For core upgrades, the system disables JAR Update-over-Mandatory (UOM) and avoids
 * directly replacing a running {@code cryptad.jar}; instead, it prefers OS-native package tools or
 * interactive installers depending on platform capabilities.
 *
 * <p>Notable behaviors and responsibilities:
 *
 * <ul>
 *   <li>Discovers the platform (OS and CPU architecture) and available package managers before
 *       selecting an installer.
 *   <li>Downloads installers and plugin JARs to a predictable, versioned location and reports
 *       progress when available.
 *   <li>Validates content by cryptographic checks; only verified artifacts proceed to the install
 *       or deploy phase.
 *   <li>Handles core updates via external installers (for example DEB/RPM/DMG/EXE) and keeps plugin
 *       update logic unchanged.
 *   <li>Exposes HTTP actions such as {@code /core-update/?action=download|install|openStore} so
 *       user interfaces can drive the flow without embedding update logic.
 * </ul>
 *
 * <p>Concurrency and state: update actions perform blocking I/O and file-system work and should be
 * executed off the UI thread. The package is designed so repeated attempts are safe: partial
 * downloads and failed installations can be retried without corrupting existing installations.
 * Callers should ensure only one core install attempt runs at a time for a given target version to
 * avoid conflicting file operations.
 *
 * <p>Platform specifics: on Linux, when a desktop is detected, the updater prefers handing off to a
 * graphical tool (for example {@code gio} or {@code xdg-open}). In sandboxed environments such as
 * Flatpak, helper bridges may be used to reach host tools. On macOS and Windows, installation is
 * typically guided by native installers; user messaging highlights common security prompts (for
 * example Gatekeeper or SmartScreen) and offers checksum verification tips when appropriate.
 */
package network.crypta.node.updater;
