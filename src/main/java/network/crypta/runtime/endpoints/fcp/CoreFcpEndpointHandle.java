package network.crypta.runtime.endpoints.fcp;

import java.util.Objects;
import network.crypta.client.async.CacheFetchResult;
import network.crypta.client.async.ClientContext;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;

/**
 * Bridge-owned wrapper around the concrete {@link FCPServer}.
 *
 * <p>This adapter is the narrow implementation behind {@link FcpEndpointHandle}. It keeps the
 * concrete server type confined to the FCP bridge package while still exposing the same
 * download-cache lookups and lifecycle hooks that the higher-level runtime code expects.
 * Construction is intentionally simple: callers hand the wrapper a fully configured server, and
 * every operation delegates straight through without caching, policy changes, or queue-specific
 * interpretation. That preserves the current FCP startup and lookup behavior while giving the
 * runtime package a stable seam for later decoupling work.
 */
@SuppressWarnings({"ClassCanBeRecord", "java:S6206"})
final class CoreFcpEndpointHandle implements FcpEndpointHandle {
  /** Concrete FCP server that still owns queue state, startup, and cache lookups. */
  private final FCPServer server;

  /**
   * Creates a wrapper around the supplied concrete FCP server.
   *
   * <p>The wrapped server is retained for the lifetime of this handle and must already be fully
   * configured by the bridge package. The constructor performs only null-checking, so callers can
   * safely create the handle during endpoint bootstrap without changing any startup sequencing or
   * persistence behavior.
   *
   * @param server concrete FCP server instance to expose through the runtime-owned seam
   * @throws NullPointerException if {@code server} is {@code null}
   */
  CoreFcpEndpointHandle(FCPServer server) {
    this.server = Objects.requireNonNull(server, "server");
  }

  @Override
  public void load() {
    server.load();
  }

  @Override
  public void maybeStart() {
    server.maybeStart();
  }

  @Override
  public CacheFetchResult lookupInstant(
      FreenetURI key, boolean noFilter, boolean mustCopy, Bucket preferred) {
    return server.lookupInstant(key, noFilter, mustCopy, preferred);
  }

  @Override
  public CacheFetchResult lookup(
      FreenetURI key, boolean noFilter, ClientContext context, boolean mustCopy, Bucket preferred) {
    return server.lookup(key, noFilter, context, mustCopy, preferred);
  }

  /**
   * Returns the concrete server wrapped by this handle.
   *
   * <p>Bridge helpers use this accessor when legacy queue and admin code still need operations that
   * are intentionally not part of {@link FcpEndpointHandle}. Higher-level runtime code should keep
   * depending on the seam instead of calling this method directly.
   *
   * @return wrapped concrete FCP server instance
   */
  FCPServer server() {
    return server;
  }
}
