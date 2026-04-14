package network.crypta.clients.fcp;

import java.io.InvalidObjectException;

/**
 * Loads the bridge-owned legacy insert adapter without widening the adapter's module dependencies.
 *
 * <p>The implementation class lives in {@code :bridge-fcp-runtime}. This loader keeps the adapter
 * decoupled at compile time while still allowing deserialization code in {@link ClientPutBase},
 * {@link ClientPut}, and {@link ClientPutDir} to restore older persisted insert contexts and putter
 * instances.
 *
 * <p>The reflection is intentional rather than incidental. Persistent-request deserialization runs
 * from the adapter module, but the concrete logic for adapting legacy runtime objects belongs in
 * the bridge module. Resolving the bridge through a well-known owner class and static accessor lets
 * the adapter recover old queue entries while keeping its direct compile-time dependencies narrow.
 */
final class LegacyInsertExecutionBridgeLoader {
  /** Fully qualified bridge owner class that exposes the legacy bridge accessor. */
  private static final String LEGACY_INSERT_EXECUTION_BRIDGE_OWNER =
      "network.crypta.clients.fcp.bridge.CoreFcpServerDependenciesFactory";

  /** Static accessor method used to retrieve the bridge singleton from the owner class. */
  private static final String LEGACY_INSERT_EXECUTION_BRIDGE_METHOD = "legacyInsertExecutionBridge";

  /** Utility class; callers use {@link #load()} instead of constructing instances. */
  private LegacyInsertExecutionBridgeLoader() {}

  /**
   * Loads the bridge-owned legacy insert adapter.
   *
   * <p>The method resolves the bridge owner class reflectively, invokes its accessor, and casts the
   * result to the narrow adapter-owned bridge interface. Any reflective, linkage, or type mismatch
   * problem is normalized into {@link InvalidObjectException} so deserialization callers receive a
   * persistence-focused failure type.
   *
   * @return bridge singleton used to adapt legacy insert contexts and putter objects
   * @throws InvalidObjectException if the bridge cannot be resolved or does not match the expected
   *     type
   */
  static FcpLegacyInsertExecutionBridge load() throws InvalidObjectException {
    try {
      Object bridge =
          Class.forName(LEGACY_INSERT_EXECUTION_BRIDGE_OWNER)
              .getMethod(LEGACY_INSERT_EXECUTION_BRIDGE_METHOD)
              .invoke(null);
      return (FcpLegacyInsertExecutionBridge) bridge;
    } catch (ReflectiveOperationException | ClassCastException | LinkageError e) {
      throw new InvalidObjectException(
          "Could not load legacy insert execution bridge: " + failureDetail(rootCause(e)));
    }
  }

  /**
   * Returns the deepest available cause for bridge-loading failures.
   *
   * @param failure top-level failure raised while resolving the bridge
   * @return nested cause when one exists; otherwise {@code failure} itself
   */
  private static Throwable rootCause(Throwable failure) {
    return failure.getCause() == null ? failure : failure.getCause();
  }

  /**
   * Formats a bridge-loading failure into a stable detail string.
   *
   * @param cause root cause chosen for reporting
   * @return failure detail string suitable for embedding in {@link InvalidObjectException}
   */
  private static String failureDetail(Throwable cause) {
    String message = cause.getMessage();
    return message == null
        ? cause.getClass().getName()
        : cause.getClass().getName() + ": " + message;
  }
}
