package network.crypta.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // method_whenCondition_expectOutcome naming
class BooleanOptionTest {

  private SubConfig subConfig;

  @Mock private BooleanCallback callback;

  // Do not override NodeL10n base: rely on default main translations for stability.

  @BeforeEach
  void setUp() {
    Config config = new Config();
    subConfig = config.createSubConfig("test");
  }

  private BooleanOption newOption(boolean defaultValue) {
    return new BooleanOption(
        subConfig,
        "flag",
        defaultValue,
        new Option.Meta(1, false, false, "short", "long"),
        callback);
  }

  @ParameterizedTest
  @ValueSource(strings = {"true", "TRUE", "TrUe", "yes", "YeS"})
  @DisplayName("parseString accepts yes/true case-insensitively")
  void parseString_whenTrueSynonyms_expectTrue(String input) throws Exception {
    BooleanOption opt = newOption(false);
    assertTrue(opt.parseString(input));
  }

  @ParameterizedTest
  @ValueSource(strings = {"false", "FALSE", "FaLsE", "no", "NO"})
  @DisplayName("parseString accepts no/false case-insensitively")
  void parseString_whenFalseSynonyms_expectFalse(String input) throws Exception {
    BooleanOption opt = newOption(true);
    assertFalse(opt.parseString(input));
  }

  @ParameterizedTest
  @ValueSource(strings = {"", " ", "y", "n", "maybe", "1", "0", "on", "off", "truthy", "falsa"})
  @DisplayName("parseString rejects unknown values")
  void parseString_whenInvalid_throwsOptionFormatException(String input) {
    BooleanOption opt = newOption(false);
    assertThrows(OptionFormatException.class, () -> opt.parseString(input));
  }

  @ParameterizedTest
  @CsvSource({"true,true", "false,false"})
  @DisplayName("toString(Boolean) returns lowercase canonical form")
  void toString_whenGivenValue_returnsCanonical(boolean value, String expected) {
    BooleanOption opt = newOption(!value);
    assertEquals(expected, opt.toString(value));
  }

  @Test
  void constructor_setsDefaultAndCurrent_andDataTypeIsBoolean() {
    BooleanOption opt = newOption(true);
    assertTrue(opt.isDefault());
    assertEquals("true", opt.getDefault());
    assertEquals("true", opt.getValueString());
    assertEquals(Option.DataType.BOOLEAN, opt.getDataType());
    assertEquals("boolean", opt.getDataTypeStr());
  }

  @Test
  void setInitialValue_whenValid_updatesCurrentWithoutCallback() throws Exception {
    BooleanOption opt = newOption(false);

    opt.setInitialValue("YeS");

    assertTrue(opt.getValue());
    assertEquals("true", opt.getValueString());
    verifyNoInteractions(callback);
  }

  @Test
  void setValue_whenValid_invokesCallbackAndUpdatesCurrent() throws Exception {
    BooleanOption opt = newOption(false);

    opt.setValue("true");

    verify(callback, times(1)).set(Boolean.TRUE);
    assertTrue(opt.getValue());
    assertEquals("true", opt.getValueString());
  }

  @Test
  void setValue_whenCallbackRejects_keepsPreviousValue() throws Exception {
    BooleanOption opt = newOption(false); // default false
    doThrow(new InvalidConfigValueException("bad")).when(callback).set(Boolean.TRUE);

    assertThrows(InvalidConfigValueException.class, () -> opt.setValue("true"));

    // Value should remain unchanged (default)
    assertFalse(opt.getValue());
    verify(callback, times(1)).set(Boolean.TRUE);
  }

  @Test
  void setValue_whenCallbackRequestsRestart_updatesCurrentAndPropagates() throws Exception {
    BooleanOption opt = newOption(false);
    doThrow(new NodeNeedRestartException("restart")).when(callback).set(Boolean.TRUE);

    NodeNeedRestartException ex =
        assertThrows(NodeNeedRestartException.class, () -> opt.setValue("true"));
    assertEquals("restart", ex.getMessage());
    // Even on restart‑required, currentValue must be updated
    assertTrue(opt.getValue());
    verify(callback, times(1)).set(Boolean.TRUE);
  }

  @Test
  void getValue_whenFinishedInitialization_readsFromCallback() {
    BooleanOption opt = newOption(false);
    when(callback.get()).thenReturn(Boolean.TRUE);

    subConfig.finishedInitialization();
    boolean value = opt.getValue();

    assertTrue(value);
    // getValue() should have consulted the callback exactly once
    verify(callback, times(1)).get();
  }

  @Test
  void getValue_whenNotFinishedInitialization_usesCachedValue() {
    BooleanOption opt = newOption(true);

    boolean value = opt.getValue();

    assertTrue(value);
    verify(callback, never()).get();
  }

  @Test
  void isDefault_afterChange_returnsFalse_withoutInitialization() throws Exception {
    BooleanOption opt = newOption(false);
    opt.setValue("true");
    assertFalse(opt.isDefault());
  }
}
