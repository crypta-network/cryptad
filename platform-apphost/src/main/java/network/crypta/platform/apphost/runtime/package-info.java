/**
 * Local out-of-process app-host runtime support.
 *
 * <p>This package contains the default host implementation used by the AppHost core. It launches
 * installed apps as child processes, injects the launch context, captures stdout/stderr in the app
 * run directory, and keeps only in-memory runtime state.
 */
package network.crypta.platform.apphost.runtime;
