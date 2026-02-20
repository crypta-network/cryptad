package com.jthemedetecor;

import java.io.Closeable;
import java.io.IOException;
import java.util.Objects;
import java.util.function.Consumer;
import network.crypta.launcher.PortalThemeDetectorImpl;
import org.jetbrains.annotations.NotNull;

/**
 * Compatibility bridge that preserves the upstream {@link OsThemeDetector} API surface.
 *
 * <p>This type exists, so launcher code can instantiate a detector in the original {@code
 * com.jthemedetecor} package, where {@link OsThemeDetector} exposes package-restricted construction
 * details. The class is intentionally thin and delegates runtime behavior to {@link
 * network.crypta.launcher.PortalThemeDetectorImpl}, which owns platform interaction and listener
 * wiring. Keeping this facade in the upstream package avoids API churn for callers that already
 * depend on {@code PortalThemeDetector} while still allowing Cryptad to keep the concrete
 * implementation under its own namespace.
 *
 * <p>Notable behavior:
 *
 * <ul>
 *   <li>All theme state queries are forwarded directly to the delegate implementation.
 *   <li>Listener registration and removal follow the same lifecycle as the underlying detector.
 *   <li>{@link #close()} releases delegate resources when the backing detector is closeable.
 * </ul>
 *
 * @see network.crypta.launcher.PortalThemeDetectorImpl
 */
public class PortalThemeDetector extends OsThemeDetector implements Closeable {
  private final PortalThemeDetectorImpl impl;

  /**
   * Creates a detector bridge backed by the default launcher implementation.
   *
   * <p>Use this constructor when callers only need theme detection behavior and do not need to
   * control the delegate instance. It wires a fresh {@link
   * network.crypta.launcher.PortalThemeDetectorImpl}, which in turn discovers the platform detector
   * and manages any listener hooks. Construction is deterministic and has no externally visible
   * side effects beyond allocating the backing implementation.
   */
  public PortalThemeDetector() {
    this(new PortalThemeDetectorImpl());
  }

  /**
   * Creates a detector bridge that delegates to the supplied implementation.
   *
   * <p>This constructor is primarily useful for tests or integration points that need explicit
   * control over detector lifecycle and behavior. The provided implementation is stored as-is and
   * is used for all further calls to theme queries, listener operations, and close handling.
   * Passing {@code null} is rejected immediately to keep instance state valid after construction.
   *
   * @param impl non-null launcher-backed detector that performs all real theme detection work
   * @throws NullPointerException if {@code impl} is {@code null}
   */
  public PortalThemeDetector(PortalThemeDetectorImpl impl) {
    this.impl = Objects.requireNonNull(impl);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isDark() {
    return impl.isDark();
  }

  /** {@inheritDoc} */
  @Override
  public void registerListener(@NotNull Consumer<Boolean> darkThemeListener) {
    impl.registerListener(darkThemeListener);
  }

  /** {@inheritDoc} */
  @Override
  public void removeListener(Consumer<Boolean> darkThemeListener) {
    impl.removeListener(darkThemeListener);
  }

  /** {@inheritDoc} */
  @Override
  public void close() throws IOException {
    impl.close();
  }
}
