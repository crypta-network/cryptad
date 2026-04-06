/**
 * Local out-of-process app-host runtime support.
 *
 * <p>This package contains the concrete local runtime used by the AppHost core. It is responsible
 * for validating copied bundles at launch time, constructing the child-process command and
 * environment, capturing process output in the managed run directory, and tracking live process
 * state in memory.
 *
 * <p>The package intentionally stays below transport adapters and UI layers. Its job is to provide
 * a portable local lifecycle manager for installed apps, including shutdown escalation and
 * best-effort recovery for wrapper or daemonizing launchers, not to implement persistent
 * supervision or sandboxing.
 */
package network.crypta.platform.apphost.runtime;
