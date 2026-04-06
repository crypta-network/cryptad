/**
 * Transport-neutral out-of-process AppHost core for locally installed applications.
 *
 * <p>This leaf owns the v1 app manifest, installed-app filesystem layout, and local process
 * lifecycle used to run applications outside the daemon process. It stays below future Web Shell
 * and transport/API layers, so code here avoids dependencies on adapters, runtime-node
 * implementation packages, and launcher code.
 */
package network.crypta.platform.apphost;
