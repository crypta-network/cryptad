package network.crypta.node.simulator;

import java.io.File;
import java.util.function.Consumer;
import network.crypta.crypt.RandomSource;
import network.crypta.runtime.bootstrap.NodeStarter.TestNodeParameters;
import network.crypta.support.PriorityAwareExecutor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"java:S100"})
class TestNodeParameterFactoryTest {
  private static final String BASE_DIR = "base-dir";

  @Mock private RandomSource random;
  @Mock private PriorityAwareExecutor executor;

  @Test
  void create_whenValidInputs_setsFieldsAndInvokesCustomizer() {
    File baseDirectory = new File(BASE_DIR);
    @SuppressWarnings("unchecked")
    Consumer<TestNodeParameters> customizer = (Consumer<TestNodeParameters>) mock(Consumer.class);

    TestNodeParameters params =
        TestNodeParameterFactory.create(baseDirectory, random, executor, customizer);

    assertSame(baseDirectory, params.getBaseDirectory());
    assertSame(random, params.getRandom());
    assertSame(executor, params.getExecutor());
    verify(customizer).accept(params);
  }

  @Test
  void create_whenRandomAndExecutorNull_allowsNullsAndStillCallsCustomizer() {
    File baseDirectory = new File(BASE_DIR);
    TestNodeParameters[] observed = new TestNodeParameters[1];
    Consumer<TestNodeParameters> customizer = params -> observed[0] = params;

    TestNodeParameters params =
        TestNodeParameterFactory.create(baseDirectory, null, null, customizer);

    assertSame(baseDirectory, params.getBaseDirectory());
    assertSame(baseDirectory, observed[0].getBaseDirectory());
    assertNull(observed[0].getRandom());
    assertNull(observed[0].getExecutor());
  }

  @Test
  void create_whenBaseDirectoryNull_throwsNullPointerException() {
    Consumer<TestNodeParameters> customizer = params -> {};

    NullPointerException exception =
        assertThrows(
            NullPointerException.class,
            () -> TestNodeParameterFactory.create(null, random, executor, customizer));

    assertEquals("baseDirectory", exception.getMessage());
  }

  @Test
  void create_whenCustomizerNull_throwsNullPointerException() {
    File baseDirectory = new File(BASE_DIR);

    NullPointerException exception =
        assertThrows(
            NullPointerException.class,
            () -> TestNodeParameterFactory.create(baseDirectory, random, executor, null));

    assertEquals("customizer", exception.getMessage());
  }
}
