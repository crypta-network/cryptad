package network.crypta.config;

import network.crypta.l10n.BaseL10n;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class StringOptionTest {
  private static final String SHORT_KEY = "short.desc.key";
  private static final String LONG_KEY = "long.desc.key";
  private static final String NEW_VALUE = "newValue";
  private static final String RESTART_VALUE = "needsRestart";
  private static final String FROM_CB = "fromCb";
  private static final String BAD_VALUE = "badValue";
  private static final String DEFAULT_VAL = "def";

  private static StringOption newOption(SubConfig subConfig, StringCallback cb) {
    return new StringOption(
        subConfig,
        "test.option",
        DEFAULT_VAL,
        new Option.Meta(42, true, true, SHORT_KEY, LONG_KEY),
        cb);
  }

  @Test
  void constructor_setsDefaultAndMeta_expectInitialState() {
    Config cfg = new Config();
    SubConfig sc = cfg.createSubConfig("test");
    StringCallback cb = Mockito.mock(StringCallback.class);

    StringOption opt = newOption(sc, cb);

    assertEquals("test.option", opt.getName());
    assertEquals(DEFAULT_VAL, opt.getDefault());
    assertEquals(DEFAULT_VAL, opt.getValueString());
    assertTrue(opt.isExpert());
    assertTrue(opt.isForcedWrite());
    assertEquals(42, opt.getSortOrder());
    assertEquals(Option.DataType.STRING, opt.getDataType());
    assertEquals("string", opt.getDataTypeStr());

    BaseL10n l10n = Mockito.mock(BaseL10n.class);
    Mockito.when(l10n.getString(SHORT_KEY, "default", DEFAULT_VAL)).thenReturn("SHORT(def)");
    Mockito.when(l10n.getString(LONG_KEY, "default", DEFAULT_VAL)).thenReturn("LONG(def)");
    assertEquals("SHORT(def)", opt.getLocalisedShortDesc(l10n));
    assertEquals("LONG(def)", opt.getLocalisedLongDesc(l10n));

    // getCallback() should return the same instance we injected
    assertEquals(cb, opt.getCallback());
  }

  @Test
  void setValue_whenCallbackAccepts_expectCurrentUpdatedAndCallbackCalled() throws Exception {
    Config cfg = new Config();
    SubConfig sc = cfg.createSubConfig("test");
    StringCallback cb = Mockito.mock(StringCallback.class);

    StringOption opt = newOption(sc, cb);

    opt.setValue("");
    assertEquals("", opt.getValueString());

    opt.setValue(NEW_VALUE);
    assertEquals(NEW_VALUE, opt.getValueString());

    Mockito.verify(cb, Mockito.times(1)).set("");
    Mockito.verify(cb, Mockito.times(1)).set(NEW_VALUE);
  }

  @Test
  void setValue_whenCallbackThrowsInvalid_expectExceptionAndCurrentNotChanged() throws Exception {
    Config cfg = new Config();
    SubConfig sc = cfg.createSubConfig("test");
    StringCallback cb = Mockito.mock(StringCallback.class);
    Mockito.doThrow(new InvalidConfigValueException("bad")).when(cb).set(BAD_VALUE);

    StringOption opt = newOption(sc, cb);

    InvalidConfigValueException ex =
        assertThrows(InvalidConfigValueException.class, () -> opt.setValue(BAD_VALUE));
    assertEquals("bad", ex.getMessage());
    // the current value must remain the default because set() failed before updating
    assertEquals("def", opt.getValueString());
    Mockito.verify(cb).set(BAD_VALUE);
  }

  @Test
  void setValue_whenCallbackThrowsRestart_expectExceptionButCurrentUpdated() throws Exception {
    Config cfg = new Config();
    SubConfig sc = cfg.createSubConfig("test");
    StringCallback cb = Mockito.mock(StringCallback.class);
    Mockito.doThrow(new NodeNeedRestartException("restart")).when(cb).set(RESTART_VALUE);

    StringOption opt = newOption(sc, cb);

    NodeNeedRestartException ex =
        assertThrows(NodeNeedRestartException.class, () -> opt.setValue(RESTART_VALUE));
    assertEquals("restart", ex.getMessage());
    // For restart, the currentValue is still updated
    assertEquals(RESTART_VALUE, opt.getValueString());
    Mockito.verify(cb).set(RESTART_VALUE);
  }

  @Test
  void setInitialValue_beforeInitialization_expectCurrentUpdatedAndNoCallback() throws Exception {
    Config cfg = new Config();
    SubConfig sc = cfg.createSubConfig("test");
    StringCallback cb = Mockito.mock(StringCallback.class);
    StringOption opt = newOption(sc, cb);

    opt.setInitialValue("init");
    assertEquals("init", opt.getValueString());
    Mockito.verify(cb, Mockito.never()).set(Mockito.any());
  }

  @Test
  void getValue_whenNotInitialized_expectNoCallbackGetAndCurrentReturned() {
    Config cfg = new Config();
    SubConfig sc = cfg.createSubConfig("test");
    StringCallback cb = Mockito.mock(StringCallback.class);
    StringOption opt = newOption(sc, cb);

    // simulate value parsed from the config file without calling callback
    opt.setDefault();
    assertEquals("def", opt.getValue());
    Mockito.verify(cb, Mockito.never()).get();
  }

  @Test
  void getValue_whenInitialized_expectRefreshFromCallback() {
    Config cfg = new Config();
    SubConfig sc = cfg.createSubConfig("test");
    StringCallback cb = Mockito.mock(StringCallback.class);
    Mockito.when(cb.get()).thenReturn(FROM_CB);

    StringOption opt = newOption(sc, cb);
    sc.finishedInitialization();

    assertEquals(FROM_CB, opt.getValue());
    assertEquals(FROM_CB, opt.getValueString());
    Mockito.verify(cb, Mockito.times(1)).get();
  }

  @Test
  void isDefault_and_setDefault_expectTransitions() throws Exception {
    Config cfg = new Config();
    SubConfig sc = cfg.createSubConfig("test");
    StringCallback cb = Mockito.mock(StringCallback.class);
    StringOption opt = newOption(sc, cb);

    assertTrue(opt.isDefault());
    opt.setValue("notDefault");
    assertFalse(opt.isDefault());
    opt.setDefault();
    assertTrue(opt.isDefault());
  }
}
