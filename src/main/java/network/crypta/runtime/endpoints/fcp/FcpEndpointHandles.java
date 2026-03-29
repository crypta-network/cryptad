package network.crypta.runtime.endpoints.fcp;

import java.util.Objects;
import network.crypta.clients.fcp.FCPServer;

/**
 * Helpers for wrapping and unwrapping runtime-owned FCP endpoint handles.
 *
 * <p>Top-level runtime packages should keep only {@link FcpEndpointHandle} references. Bridge code
 * under {@code network.crypta.runtime.endpoints.fcp} can recover the underlying {@link FCPServer}
 * through this utility when legacy queue and admin paths still need concrete FCP operations.
 *
 * <p>The utility is intentionally strict about provenance. Handles created through {@link
 * #wrap(FCPServer)} can later be unwrapped safely by bridge code, but ad hoc implementations of
 * {@link FcpEndpointHandle} are rejected so the seam does not silently mask incompatible state or
 * alternate lifecycle rules. In practice this means runtime wiring can stay narrow and bridge code
 * can still recover the legacy server only at the specific edges that continue to need
 * protocol-specific behavior.
 */
public final class FcpEndpointHandles {
  private FcpEndpointHandles() {}

  /**
   * Wraps a concrete FCP server in the runtime-owned endpoint-handle seam.
   *
   * <p>The returned handle exposes only the seam methods required by top-level runtime wiring and
   * by the {@link network.crypta.client.async.DownloadCache} contract. Callers should use this when
   * moving a concrete server instance from bridge bootstrap code into runtime code that must no
   * longer retain a direct {@link FCPServer} dependency.
   *
   * @param server concrete FCP server to expose behind the seam
   * @return runtime-owned handle that delegates directly to {@code server}
   */
  public static FcpEndpointHandle wrap(FCPServer server) {
    return new CoreFcpEndpointHandle(server);
  }

  /**
   * Returns the concrete FCP server behind the supplied handle.
   *
   * <p>This is the strict unwrapping path for bridge code that still needs full FCP access. It
   * accepts only handles created by this package, which keeps the seam honest and avoids silently
   * treating unrelated implementations as compatible with the current bridge assumptions.
   *
   * @param endpointHandle runtime-owned handle produced by this bridge package
   * @return wrapped concrete FCP server
   * @throws NullPointerException if {@code endpointHandle} is {@code null}
   * @throws IllegalArgumentException if the handle was not created by this bridge package
   */
  public static FCPServer unwrap(FcpEndpointHandle endpointHandle) {
    return requireCoreHandle(Objects.requireNonNull(endpointHandle, "endpointHandle")).server();
  }

  /**
   * Returns the wrapped FCP server when present, otherwise {@code null}.
   *
   * <p>Call this when the surrounding code already treats the endpoint as optional. The method
   * preserves that optionality while still validating that any non-null handle came from this
   * bridge package rather than from an unsupported implementation.
   *
   * @param endpointHandle runtime-owned handle, or {@code null}
   * @return wrapped FCP server, or {@code null} when no handle is available
   * @throws IllegalArgumentException if the handle was not created by this bridge package
   */
  public static FCPServer serverOrNull(FcpEndpointHandle endpointHandle) {
    return endpointHandle == null ? null : requireCoreHandle(endpointHandle).server();
  }

  /**
   * Returns the wrapped FCP server or throws when no handle is available.
   *
   * <p>Use this when the caller cannot proceed without a live FCP endpoint and wants a clear
   * failure instead of propagating a nullable server reference. The thrown exception preserves the
   * existing bridge expectation that queue and admin paths should fail fast when the endpoint is
   * unavailable.
   *
   * @param endpointHandle runtime-owned handle expected to wrap a live FCP server
   * @return wrapped concrete FCP server
   * @throws IllegalStateException if {@code endpointHandle} is {@code null}
   * @throws IllegalArgumentException if the handle was not created by this bridge package
   */
  @SuppressWarnings("unused")
  public static FCPServer requireServer(FcpEndpointHandle endpointHandle) {
    FCPServer server = serverOrNull(endpointHandle);
    if (server == null) {
      throw new IllegalStateException("FCP server unavailable");
    }
    return server;
  }

  private static CoreFcpEndpointHandle requireCoreHandle(FcpEndpointHandle endpointHandle) {
    if (endpointHandle instanceof CoreFcpEndpointHandle coreHandle) {
      return coreHandle;
    }
    throw new IllegalArgumentException(
        "Unsupported FcpEndpointHandle implementation: " + endpointHandle.getClass().getName());
  }
}
