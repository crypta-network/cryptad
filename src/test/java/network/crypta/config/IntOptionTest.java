package network.crypta.config;

import network.crypta.support.Fields;
import network.crypta.support.api.IntCallback;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class IntOptionTest {

  private SubConfig subConfig;

  @BeforeEach
  void setUp() {
    Config config = new Config();
    subConfig = new SubConfig("test", config);
  }

  @Test
  void constructor_withDisplayOrCanonicalString_parsesToSameValue() {
    // Arrange
    IntOption optDurationFromDisplay =
        new IntOption(
            null,
            "duration",
            "5m",
            new Option.Meta(0, false, false, "short", "long"),
            new NullIntCallback(),
            Dimension.DURATION);

    // Act: Build from a canonical string produced by toString (falls back via Dimension.NOT)
    IntOption optFromCanonical =
        new IntOption(
            null,
            "duration",
            optDurationFromDisplay.toString(optDurationFromDisplay.currentValue),
            new Option.Meta(0, false, false, "short", "long"),
            new NullIntCallback(),
            Dimension.DURATION);

    // Assert
    assertEquals(optDurationFromDisplay.currentValue, optFromCanonical.currentValue);

    // Act: Build from a display string produced by toDisplayString (e.g., "5m")
    IntOption optFromDisplay =
        new IntOption(
            null,
            "duration",
            optDurationFromDisplay.toDisplayString(optDurationFromDisplay.currentValue),
            new Option.Meta(0, false, false, "short", "long"),
            new NullIntCallback(),
            Dimension.DURATION);

    // Assert
    assertEquals(optDurationFromDisplay.currentValue, optFromDisplay.currentValue);
  }

  @Test
  void setValue_whenValid_updatesCurrentAndInvokesCallback() throws Exception {
    // Arrange
    int defaultValue = 0;

    // Use a new instance with a mocked callback to verify interactions
    IntOption optionWithMockCb =
        new IntOption(
            subConfig,
            "size",
            defaultValue,
            new Option.Meta(1, false, false, "short", "long"),
            mockCb,
            Dimension.SIZE);

    // Act
    optionWithMockCb.setValue("1KiB"); // 1024 bytes

    // Assert
    assertEquals(1024, optionWithMockCb.currentValue);
    assertEquals("1024", optionWithMockCb.getValueString()); // canonical string (Dimension.NOT)
    verify(mockCb, times(1)).set(1024);
  }

  @Mock private IntCallback mockCb;

  @Test
  void setValue_whenDurationString_updatesCurrentAndFormatsDisplay() throws Exception {
    // Arrange
    IntOption option =
        new IntOption(
            subConfig,
            "duration",
            0,
            new Option.Meta(1, false, false, "short", "long"),
            mockCb,
            Dimension.DURATION);

    // Act
    option.setValue("1m30s");

    // Assert
    assertEquals(90_000, option.currentValue);
    assertEquals(Fields.intToString(90_000, false), option.getValueString());
    assertEquals("1m30s", option.getValueDisplayString());
    verify(mockCb, times(1)).set(90_000);
  }

  @Test
  void setValue_whenDurationPlainInteger_fallsBackToDimensionlessParsing() throws Exception {
    // Arrange
    IntOption option =
        new IntOption(
            subConfig,
            "duration",
            0,
            new Option.Meta(1, false, false, "short", "long"),
            mockCb,
            Dimension.DURATION);

    // Act
    option.setValue("3000");

    // Assert
    assertEquals(3000, option.currentValue);
    assertEquals(Fields.intToString(3000, false), option.getValueString());
    assertEquals("3s", option.getValueDisplayString());
    verify(mockCb, times(1)).set(3000);
  }

  @Test
  void setValue_whenInvalidString_throwsInvalidConfigValueException() {
    // Arrange
    IntOption option =
        new IntOption(
            subConfig,
            "num",
            10,
            new Option.Meta(1, false, false, "short", "long"),
            mockCb,
            Dimension.NOT);

    // Act + Assert
    assertThrows(InvalidConfigValueException.class, () -> option.setValue("not_a_number"));
    // Callback isn't called on parse failure
    verifyNoInteractions(mockCb);
    // Current value remains unchanged (default)
    assertEquals(10, option.currentValue);
  }

  @Test
  void setInitialValue_whenInvalid_throwsInvalidConfigValueException_withoutCallback() {
    // Arrange
    IntOption option =
        new IntOption(
            subConfig,
            "num",
            7,
            new Option.Meta(1, false, false, "short", "long"),
            mockCb,
            Dimension.NOT);

    // Act + Assert
    assertThrows(InvalidConfigValueException.class, () -> option.setInitialValue("garbage"));
    verifyNoInteractions(mockCb);
    assertEquals(7, option.currentValue);
  }

  @Test
  void setValue_whenCallbackRejects_doesNotUpdateCurrentValue() throws Exception {
    // Arrange
    IntOption option =
        new IntOption(
            subConfig,
            "num",
            123,
            new Option.Meta(1, false, false, "short", "long"),
            mockCb,
            Dimension.NOT);
    // Callback throws a validation error
    org.mockito.Mockito.doThrow(new InvalidConfigValueException("bad")).when(mockCb).set(anyInt());

    // Act + Assert
    assertThrows(InvalidConfigValueException.class, () -> option.setValue("1024"));
    // Value should not change on InvalidConfigValueException
    assertEquals(123, option.currentValue);
  }

  @Test
  void setValue_whenCallbackRequestsRestart_updatesCurrentAndPropagates() throws Exception {
    // Arrange
    IntOption option =
        new IntOption(
            subConfig,
            "num",
            0,
            new Option.Meta(1, false, false, "short", "long"),
            mockCb,
            Dimension.SIZE);
    org.mockito.Mockito.doThrow(new NodeNeedRestartException("restart")).when(mockCb).set(1024);

    // Act + Assert
    NodeNeedRestartException ex =
        assertThrows(NodeNeedRestartException.class, () -> option.setValue("1KiB"));
    assertEquals("restart", ex.getMessage());
    // Even on restart-required, currentValue must be updated
    assertEquals(1024, option.currentValue);
    verify(mockCb, times(1)).set(1024);
  }

  @Test
  void getValue_whenFinishedInitialization_readsFromCallback() {
    // Arrange
    IntOption option =
        new IntOption(
            subConfig,
            "num",
            10,
            new Option.Meta(1, false, false, "short", "long"),
            mockCb,
            Dimension.NOT);
    when(mockCb.get()).thenReturn(42);
    subConfig.finishedInitialization();

    // Act
    int value = option.getValue();

    // Assert
    assertEquals(42, value);
    assertEquals(42, option.currentValue);
    verify(mockCb, times(1)).get();
  }

  @Test
  void getValue_whenNotFinishedInitialization_usesCachedValue() {
    // Arrange
    IntOption option =
        new IntOption(
            subConfig,
            "num",
            77,
            new Option.Meta(1, false, false, "short", "long"),
            mockCb,
            Dimension.NOT);

    // Act
    int value = option.getValue();

    // Assert
    assertEquals(77, value);
    verify(mockCb, never()).get();
  }

  @Test
  void formatting_whenSizeDimension_differsBetweenDisplayAndCanonical() {
    // Arrange
    IntOption sizeOption =
        new IntOption(
            subConfig,
            "size",
            1024,
            new Option.Meta(1, false, false, "short", "long"),
            new NullIntCallback(),
            Dimension.SIZE);

    // Act + Assert
    // For 2048, display uses IEC units while canonical remains plain
    assertEquals("2048", sizeOption.toString(2048));
    assertEquals("2KiB", sizeOption.toDisplayString(2048));

    // Also, sanity-check a SI multiple representation
    assertEquals("2k", sizeOption.toString(2000));
    assertEquals("2k", sizeOption.toDisplayString(2000));
  }
}
