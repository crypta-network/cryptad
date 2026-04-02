package network.crypta.node.simulator;

import java.io.File;
import java.util.Objects;
import java.util.function.Consumer;
import network.crypta.crypt.RandomSource;
import network.crypta.runtime.bootstrap.NodeStarter.TestNodeParameters;
import network.crypta.support.PriorityAwareExecutor;

/**
 * Utility for constructing {@link TestNodeParameters} instances with shared defaults.
 *
 * <p>This factory centralizes the setup of simulator node parameters so tests and tools can
 * construct consistent configurations without repeating boilerplate. It creates a fresh {@link
 * TestNodeParameters} object, applies the required base directory and optional runtime
 * collaborators, and then delegates final tuning to a caller-provided customization callback.
 * Typical call patterns supply a temp directory, a deterministic or seeded {@link RandomSource},
 * and an executor used by the simulator to schedule tasks. The customizer can override or add any
 * remaining fields, including timeouts or feature toggles, before the instance is returned.
 *
 * <p>The returned object is mutable and intended for immediate use in a test setup phase. This
 * factory itself is stateless and thread-safe; any concurrency behavior is determined entirely by
 * the provided {@link PriorityAwareExecutor} and the {@link TestNodeParameters} instance that it is
 * stored in.
 *
 * <ul>
 *   <li>Creates a new parameter object on every call.
 *   <li>Requires a non-null base directory and customizer.
 *   <li>Applies the provided collaborators before customization runs.
 * </ul>
 */
public final class TestNodeParameterFactory {

  private TestNodeParameterFactory() {}

  /**
   * Creates and configures a new {@link TestNodeParameters} instance using the supplied inputs.
   *
   * <p>The factory sets the base directory, random source, and executor in that order, then calls
   * the provided customizer to allow the caller to finish configuration. This method performs no
   * validation beyond null checks for the base directory and customizer, so it is the caller's
   * responsibility to ensure the remaining fields are meaningful for the intended simulation. Each
   * invocation returns a fresh mutable object, so callers may safely update fields after this
   * method returns without affecting other configurations.
   *
   * <pre>{@code
   * TestNodeParameters params =
   *     TestNodeParameterFactory.create(dir, random, executor, p -> p.setTestMode(true));
   * }</pre>
   *
   * @param baseDirectory base directory for node storage; must be non-null.
   * @param random random source for deterministic test behavior; may be null.
   * @param executor executor used for task scheduling; may be null.
   * @param customizer callback invoked to finalize parameters; must be non-null.
   * @return a newly configured parameter object owned by the caller.
   * @throws NullPointerException if baseDirectory or customizer is null.
   */
  public static TestNodeParameters create(
      File baseDirectory,
      RandomSource random,
      PriorityAwareExecutor executor,
      Consumer<TestNodeParameters> customizer) {
    Objects.requireNonNull(baseDirectory, "baseDirectory");
    Objects.requireNonNull(customizer, "customizer");

    TestNodeParameters params = new TestNodeParameters();
    params.setBaseDirectory(baseDirectory);
    params.setRandom(random);
    params.setExecutor(executor);
    customizer.accept(params);
    return params;
  }
}
