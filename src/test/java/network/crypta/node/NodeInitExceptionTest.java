package network.crypta.node;

import network.crypta.config.ConfigExitCodes;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100")
class NodeInitExceptionTest {

  @Test
  void constructor_whenUsingWrapperConfigExitCode_preservesCodeAndMessage() {
    // Arrange
    int exitCode = NodeInitException.EXIT_BROKE_WRAPPER_CONF;
    String message = "broken wrapper";

    // Act
    NodeInitException exception = new NodeInitException(exitCode, message);

    // Assert
    assertEquals(ConfigExitCodes.BROKE_WRAPPER_CONF, exitCode);
    assertEquals(exitCode, exception.exitCode);
    assertEquals("broken wrapper (" + exitCode + ')', exception.getMessage());
  }
}
