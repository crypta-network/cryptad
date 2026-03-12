package network.crypta.config;

import network.crypta.support.api.LongCallback;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LongOptionTest {

  private SubConfig subConfig;

  @Mock private LongCallback cb;

  @BeforeEach
  void setup() {
    Config config = new Config();
    subConfig = new SubConfig("test", config);
  }

  private LongOption newOption(
      String name, long defaultValue, boolean isSize, LongCallback callback) {
    Option.Meta meta = new Option.Meta(10, false, false, "short.key", "long.key");
    return new LongOption(subConfig, name, defaultValue, meta, callback, isSize);
  }

  @Test
  @DisplayName("constructor(String) parses default and sets current")
  void constructorStringDefault_whenValid_expectDefaultAndCurrentSet() {
    // Arrange
    // "3M" uses IEC upper-case M => 3 * 2^20
    Option.Meta meta = new Option.Meta(10, false, false, "short.key", "long.key");
    LongOption opt = new LongOption(subConfig, "alpha", "3M", meta, cb, /* isSize */ false);

    // Act & Assert
    assertEquals(Option.DataType.NUMBER, opt.getDataType());
    // Not finished initialization -> currentValue equals parsed default
    assertEquals("3145728", opt.getValueString());
    assertEquals("3145728", opt.getValueDisplayString());
  }

  @Test
  @DisplayName("display formatting honors isSize (IEC units)")
  void displayFormatting_whenIsSizeTrue_usesIecSuffix() throws Exception {
    // Arrange
    LongOption opt = newOption("beta", 0L, /* isSize= */ true, cb);

    // Act: parse a human-size value and set as initial without invoking callback
    opt.setInitialValue("2048");

    // Assert: the display string uses IEC (KiB) while the value string stays raw
    assertEquals("2048", opt.getValueString());
    assertEquals("2KiB", opt.getValueDisplayString());
  }

  @Test
  @DisplayName("parse invalid value -> InvalidConfigValueException with l10n message")
  void parseString_whenInvalid_throwsInvalidConfigValueExceptionWithMessage() {
    // Arrange
    LongOption opt = newOption("gamma", 0L, /* isSize= */ false, cb);

    // Act
    InvalidConfigValueException ex =
        assertThrows(InvalidConfigValueException.class, () -> opt.setInitialValue("not a number"));

    // Assert: the message comes from l10n and contains the offending value
    String msg = ex.getMessage();
    assertNotNull(msg);
    assertTrue(msg.contains("64-bit integer"), msg);
    assertTrue(msg.contains("not a number"), msg);
  }

  @Test
  @DisplayName("setValue propagates NodeNeedRestartException but updates current value")
  void setValue_whenCallbackThrowsNodeNeedRestart_updatesValueAndRethrows() throws Exception {
    // Arrange
    LongOption opt = newOption("delta", 100L, /* isSize= */ false, cb);
    doThrow(new NodeNeedRestartException("restart")).when(cb).set(2048L);

    // Act
    NodeNeedRestartException ex =
        assertThrows(NodeNeedRestartException.class, () -> opt.setValue("2048"));

    // Assert: value applied to currentValue even though restart is required
    assertEquals("2048", opt.getValueString());
    verify(cb).set(2048L);
    assertEquals("restart", ex.getMessage());
  }

  @Test
  @DisplayName("setValue keeps old value on InvalidConfigValueException from callback")
  void setValue_whenCallbackThrowsInvalid_keepsOldValue() throws Exception {
    // Arrange
    LongOption opt = newOption("epsilon", 1000L, /* isSize= */ false, cb);
    // Make callback reject the new value
    doThrow(new InvalidConfigValueException("bad")).when(cb).set(2000L);

    // Act
    assertThrows(InvalidConfigValueException.class, () -> opt.setValue("2000"));

    // Assert: current value unchanged (1000)
    assertEquals("1000", opt.getValueString());
    verify(cb).set(2000L);
  }

  @Test
  @DisplayName("getValue reflects callback after finishedInitialization()")
  void getValue_whenFinishedInitialization_readsFromCallback() {
    // Arrange
    LongOption opt = newOption("zeta", 7L, /* isSize= */ false, cb);
    subConfig.finishedInitialization();
    when(cb.get()).thenReturn(12345L);

    // Act
    long val = opt.getValue();

    // Assert
    assertEquals(12345L, val);
    assertEquals("12345", opt.getValueString());
  }
}
