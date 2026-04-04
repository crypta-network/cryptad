/**
 * Structured readiness-file helpers shared by the daemon runtime and the desktop launcher.
 *
 * <p>This package owns the tiny filesystem contract used for launcher startup coordination. The
 * daemon publishes a versioned readiness payload under the resolved runtime directory once the HTTP
 * shell is ready for normal use, and the launcher consumes that file instead of scraping
 * human-facing log lines as its primary signal.
 */
package network.crypta.fs.readiness;
