package network.crypta.node.simulator;

import java.io.File;
import java.util.Objects;
import java.util.function.Consumer;
import network.crypta.crypt.RandomSource;
import network.crypta.node.NodeStarter.TestNodeParameters;
import network.crypta.support.PriorityAwareExecutor;

/** Utility for constructing {@link TestNodeParameters} instances with shared defaults. */
public final class TestNodeParameterFactory {

  private TestNodeParameterFactory() {}

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
