package network.crypta.clients.http.wizardsteps;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.stream.Stream;
import javax.naming.OperationNotSupportedException;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class WizardL10nTest {

  private static final String TRANSLATED = "translated";
  private static final String FIRST_TIME_WIZARD_KEY = "FirstTimeWizardToadlet.key";
  private static final String PATTERN = "pattern";
  private static final String VALUE = "value";

  static Stream<Arguments> l10nKeyAndExpectedPrefix() {
    return Stream.of(
        Arguments.of("welcome", "FirstTimeWizardToadlet.welcome"),
        Arguments.of("", "FirstTimeWizardToadlet."),
        Arguments.of(null, "FirstTimeWizardToadlet.null"));
  }

  static Stream<Arguments> l10nSecKeyAndExpectedPrefix() {
    return Stream.of(
        Arguments.of("high", "SecurityLevels.high"),
        Arguments.of("", "SecurityLevels."),
        Arguments.of(null, "SecurityLevels.null"));
  }

  @Test
  @SuppressWarnings("java:S3011")
  void constructor_whenInvokedViaReflection_throwsOperationNotSupportedException()
      throws Exception {
    // Arrange
    Constructor<WizardL10n> constructor = WizardL10n.class.getDeclaredConstructor();
    constructor.setAccessible(true);

    // Act
    InvocationTargetException exception =
        assertThrows(InvocationTargetException.class, constructor::newInstance);

    // Assert
    OperationNotSupportedException cause =
        assertInstanceOf(OperationNotSupportedException.class, exception.getCause());
    assertEquals("Cannot instantiate WizardL10n; it is a utility class.", cause.getMessage());
  }

  @ParameterizedTest
  @MethodSource("l10nKeyAndExpectedPrefix")
  void l10n_whenCalled_prefixesKeyAndDelegatesToBase(String key, String expectedPrefixedKey) {
    // Arrange
    BaseL10n base = mock(BaseL10n.class);
    when(base.getString(expectedPrefixedKey)).thenReturn(TRANSLATED);

    try (MockedStatic<NodeL10n> nodeL10n = mockStatic(NodeL10n.class)) {
      nodeL10n.when(NodeL10n::getBase).thenReturn(base);

      // Act
      String result = WizardL10n.l10n(key);

      // Assert
      assertEquals(TRANSLATED, result);
      verify(base).getString(expectedPrefixedKey);
    }
  }

  @Test
  void l10n_whenPatternAndValueProvided_prefixesKeyAndDelegatesToBase() {
    // Arrange
    BaseL10n base = mock(BaseL10n.class);
    when(base.getString(FIRST_TIME_WIZARD_KEY, PATTERN, VALUE)).thenReturn("ok");

    try (MockedStatic<NodeL10n> nodeL10n = mockStatic(NodeL10n.class)) {
      nodeL10n.when(NodeL10n::getBase).thenReturn(base);

      // Act
      String result = WizardL10n.l10n("key", PATTERN, VALUE);

      // Assert
      assertEquals("ok", result);
      verify(base).getString(FIRST_TIME_WIZARD_KEY, PATTERN, VALUE);
    }
  }

  @Test
  void l10n_whenPatternsAndValuesProvided_prefixesKeyAndDelegatesToBase() {
    // Arrange
    String[] patterns = {"a", "b"};
    String[] values = {"1", "2"};
    BaseL10n base = mock(BaseL10n.class);
    when(base.getString(FIRST_TIME_WIZARD_KEY, patterns, values)).thenReturn("ok");

    try (MockedStatic<NodeL10n> nodeL10n = mockStatic(NodeL10n.class)) {
      nodeL10n.when(NodeL10n::getBase).thenReturn(base);

      // Act
      String result = WizardL10n.l10n("key", patterns, values);

      // Assert
      assertEquals("ok", result);
      verify(base).getString(FIRST_TIME_WIZARD_KEY, patterns, values);
    }
  }

  @ParameterizedTest
  @MethodSource("l10nSecKeyAndExpectedPrefix")
  void l10nSec_whenCalled_prefixesKeyAndDelegatesToBase(String key, String expectedPrefixedKey) {
    // Arrange
    BaseL10n base = mock(BaseL10n.class);
    when(base.getString(expectedPrefixedKey)).thenReturn(TRANSLATED);

    try (MockedStatic<NodeL10n> nodeL10n = mockStatic(NodeL10n.class)) {
      nodeL10n.when(NodeL10n::getBase).thenReturn(base);

      // Act
      String result = WizardL10n.l10nSec(key);

      // Assert
      assertEquals(TRANSLATED, result);
      verify(base).getString(expectedPrefixedKey);
    }
  }
}
