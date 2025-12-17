package network.crypta.pluginmanager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ForwardPortStatusTest {

  static Stream<Arguments> constructorArguments() {
    return Stream.of(
        Arguments.of(ForwardPortStatus.IN_PROGRESS, "", 0),
        Arguments.of(
            ForwardPortStatus.MAYBE_SUCCESS, "UPnP claims success; needs verification", 4242),
        Arguments.of(ForwardPortStatus.PROBABLE_FAILURE, "Router rejected mapping", 65535),
        Arguments.of(Integer.MIN_VALUE, "min status", Integer.MIN_VALUE),
        Arguments.of(Integer.MAX_VALUE, "max status", Integer.MAX_VALUE));
  }

  @ParameterizedTest
  @MethodSource("constructorArguments")
  void constructor_whenValuesProvided_expectFieldsMatch(
      int status, String reason, int externalPort) {
    // Arrange

    // Act
    ForwardPortStatus forwardPortStatus = new ForwardPortStatus(status, reason, externalPort);

    // Assert
    assertEquals(status, forwardPortStatus.status);
    assertEquals(reason, forwardPortStatus.reasonString);
    assertEquals(externalPort, forwardPortStatus.externalPort);
  }

  @Test
  void constructor_whenReasonIsNull_expectNullStored() {
    // Arrange
    int status = ForwardPortStatus.MAYBE_SUCCESS;
    int externalPort = 12345;

    // Act
    ForwardPortStatus forwardPortStatus = new ForwardPortStatus(status, null, externalPort);

    // Assert
    assertEquals(status, forwardPortStatus.status);
    assertNull(forwardPortStatus.reasonString);
    assertEquals(externalPort, forwardPortStatus.externalPort);
  }

  @Test
  @SuppressWarnings("ConstantValue")
  void constants_whenCompared_expectMonotonicOrderingAndSigns() {
    // Arrange

    // Act

    // Assert
    assertTrue(ForwardPortStatus.DEFINITE_SUCCESS > ForwardPortStatus.PROBABLE_SUCCESS);
    assertTrue(ForwardPortStatus.PROBABLE_SUCCESS > ForwardPortStatus.MAYBE_SUCCESS);
    assertTrue(ForwardPortStatus.MAYBE_SUCCESS > ForwardPortStatus.IN_PROGRESS);
    assertTrue(ForwardPortStatus.IN_PROGRESS > ForwardPortStatus.PROBABLE_FAILURE);
    assertTrue(ForwardPortStatus.PROBABLE_FAILURE > ForwardPortStatus.DEFINITE_FAILURE);

    assertTrue(ForwardPortStatus.DEFINITE_SUCCESS > 0);
    assertTrue(ForwardPortStatus.PROBABLE_SUCCESS > 0);
    assertTrue(ForwardPortStatus.MAYBE_SUCCESS > 0);
    assertEquals(0, ForwardPortStatus.IN_PROGRESS);
    assertTrue(ForwardPortStatus.PROBABLE_FAILURE < 0);
    assertTrue(ForwardPortStatus.DEFINITE_FAILURE < 0);
  }
}
