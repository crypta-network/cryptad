package network.crypta.config;

import network.crypta.l10n.NodeL10n;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ShortOptionTest {

  private static ShortOption newOption(
      SubConfig sc, ShortCallback cb, boolean isSize, short defaultValue) {
    return new ShortOption(
        sc,
        "test.short",
        defaultValue,
        new Option.Meta(
            42,
            true,
            false,
            "ShortOption.unrecognisedShort", // any key; not used in happy paths
            "ShortOption.unrecognisedShort"),
        cb,
        isSize);
  }

  @Test
  void setValue_whenValidNumber_expectCallbackSetAndValueUpdated(@Mock ShortCallback cb)
      throws Exception {
    // Arrange
    Config config = new Config();
    SubConfig sc = config.createSubConfig("core");
    ShortOption opt = newOption(sc, cb, false, (short) 5);

    // Act
    opt.setValue("123");

    // Assert
    verify(cb).set((short) 123);
    assertEquals((short) 123, opt.getValue());
    assertEquals("123", opt.getValueString()); // toString() does not use size units
  }

  @Test
  void setInitialValue_whenCalled_expectNoCallbackAndValueParsed(@Mock ShortCallback cb)
      throws Exception {
    // Arrange
    Config config = new Config();
    SubConfig sc = config.createSubConfig("core");
    ShortOption opt = newOption(sc, cb, false, (short) 7);

    // Act
    opt.setInitialValue("2000");

    // Assert
    verify(cb, never()).set((short) 2000);
    assertEquals((short) 2000, opt.getValue());
    assertEquals("2k", opt.getValueString()); // 2000 -> 2k for persistence/API form
  }

  @Test
  void setValue_whenInvalidNumber_expectInvalidConfigValueExceptionWithL10n(
      @Mock ShortCallback cb) {
    // Arrange
    // Reset global translations to a production bundle. Other tests may install
    // a test-only bundle via L10nTestUtils.useTestTranslation(), which would
    // make this localized message assertion nondeterministic.
    new NodeL10n();
    Config config = new Config();
    SubConfig sc = config.createSubConfig("core");
    ShortOption opt = newOption(sc, cb, false, (short) 0);

    // Act + Assert
    InvalidConfigValueException ex =
        assertThrows(InvalidConfigValueException.class, () -> opt.setValue("garbage"));
    assertTrue(
        ex.getMessage()
            .contains("The value specified can't be parsed as a 16-bit integer: garbage"));
  }

  @Test
  void getValueDisplayString_whenIsSizeTrue_expectIECUnits(@Mock ShortCallback cb)
      throws Exception {
    // Arrange: value chosen to format as IEC (KiB) when isSize=true
    Config config = new Config();
    SubConfig sc = config.createSubConfig("core");
    ShortOption opt = newOption(sc, cb, true, (short) 0);

    // Act
    opt.setInitialValue("2048");

    // Assert: display uses IEC units, persistence uses plain
    assertEquals("2KiB", opt.getValueDisplayString());
    assertEquals("2048", opt.getValueString());
  }

  @Test
  void setValue_whenCallbackThrowsNodeNeedRestartException_expectPropagateAndValueRecorded(
      @Mock ShortCallback cb) throws Exception {
    // Arrange
    Config config = new Config();
    SubConfig sc = config.createSubConfig("core");
    ShortOption opt = newOption(sc, cb, false, (short) 1);
    doThrow(new NodeNeedRestartException("need restart")).when(cb).set((short) 1500);

    // Act + Assert
    NodeNeedRestartException ex =
        assertThrows(NodeNeedRestartException.class, () -> opt.setValue("1500"));
    assertEquals("need restart", ex.getMessage());
    assertEquals(
        (short) 1500, opt.getValue()); // currentValue is still updated on restart requirement
    assertEquals("1500", opt.getValueString());
  }

  @Test
  void setValue_whenCallbackThrowsInvalidConfigValueException_expectPropagateAndValueUnchanged(
      @Mock ShortCallback cb) throws Exception {
    // Arrange
    Config config = new Config();
    SubConfig sc = config.createSubConfig("core");
    ShortOption opt = newOption(sc, cb, false, (short) 7);
    doThrow(new InvalidConfigValueException("bad"))
        .when(cb)
        .set((short) 100); // parse succeeds, callback rejects

    // Act + Assert
    assertThrows(InvalidConfigValueException.class, () -> opt.setValue("100"));
    assertEquals((short) 7, opt.getValue()); // remains default
  }

  @Test
  void getValue_whenFinishedInitialization_expectDelegatesToCallbackGet(@Mock ShortCallback cb)
      throws Exception {
    // Arrange
    Config config = new Config();
    SubConfig sc = config.createSubConfig("core");
    ShortOption opt = newOption(sc, cb, false, (short) 11);
    doAnswer(
            _ -> {
              // simulate successful apply; underlying state would become 1234
              return null;
            })
        .when(cb)
        .set((short) 1234);
    when(cb.get()).thenReturn((short) 3210);

    // Act: apply value before initialization completes, then complete init and read back
    opt.setValue("1234");
    sc.finishedInitialization();
    short effective = opt.getValue();

    // Assert: get() path used after initialization
    assertEquals((short) 3210, effective);
  }

  @Test
  void ctor_and_accessors_expectMetadataAndDataTypeSet(@Mock ShortCallback cb) {
    // Arrange
    Config config = new Config();
    SubConfig sc = config.createSubConfig("core");
    ShortOption opt = newOption(sc, cb, false, (short) 9);

    // Assert
    assertEquals("test.short", opt.getName());
    assertEquals(42, opt.getSortOrder());
    assertTrue(opt.isExpert());
    assertFalse(opt.isForcedWrite());
    assertEquals(Option.DataType.NUMBER, opt.getDataType());
  }
}
