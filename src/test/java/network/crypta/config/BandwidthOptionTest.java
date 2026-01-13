package network.crypta.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import network.crypta.support.api.IntCallback;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100") // Allow method names like method_whenCondition_expectOutcome
@ExtendWith(MockitoExtension.class)
class BandwidthOptionTest {

  private SubConfig subConfig;
  private static final String TWO_KIB_PER_S = "2KiB/s";

  @Mock private IntCallback callback;

  @BeforeEach
  void setUp() {
    // Real Config/SubConfig so Option logic (initialization gating, etc.) runs as in production
    Config config = new Config();
    subConfig = config.createSubConfig("test");
    // No stubbing: tests verify only set() side-effects; get() is unused before initialization
  }

  private BandwidthOption newOptionWithDefault(int defaultValue) {
    return new BandwidthOption(
        subConfig,
        "bandwidth",
        defaultValue,
        new Option.Meta(10, false, false, "short", "long"),
        callback);
  }

  // no helper for String default to avoid Sonar warning about always-constant parameter values

  @ParameterizedTest(name = "{0} -> {1} bytes")
  @CsvSource({
    // plain numbers
    "1000,1000",
    // SI unit
    "2k,2000",
    // IEC unit
    "2K,2048",
    "2KiB,2048",
    // bits (lowercase 'b' means bits)
    "16kb,2000",
    // with per-second variants
    "1000/s,1000",
    "2KiB/s,2048",
    "16kb/s,2000",
    "16kbps,2000",
    // case-insensitive suffix
    "1000/S,1000",
    // surrounding whitespace
    "  2000/s  ,2000",
    // zero boundary
    "0/s,0"
  })
  @DisplayName("setInitialValue trims per-second and parses units deterministically")
  void setInitialValue_whenVariousInputs_expectParsedBytes(String input, int expectedBytes)
      throws Exception {
    BandwidthOption opt = newOptionWithDefault(0);

    // Act: parse without invoking a callback
    opt.setInitialValue(input);

    // Assert: current value and string forms
    assertEquals(expectedBytes, opt.getValue(), "parsed numeric value");
    String expectedPersist =
        network.crypta.support.Fields.intToString(expectedBytes, Dimension.NOT);
    assertEquals(expectedPersist, opt.getValueString(), "persistence string");
  }

  @Test
  void setValue_whenValidBandwidth_callsCallbackWithParsedValue() throws Exception {
    BandwidthOption opt = newOptionWithDefault(0);

    opt.setValue(TWO_KIB_PER_S);

    verify(callback, times(1)).set(2048);
    assertEquals(2048, opt.getValue());
    // UI display uses Dimension.SIZE (may compact when evenly divisible)
    assertEquals("2KiB", opt.getValueDisplayString());
    // Persistence always uses a plain number
    assertEquals("2048", opt.getValueString());
  }

  @Test
  void setValue_whenInvalidString_throwsInvalidConfigValueException_andKeepsOldValue() {
    BandwidthOption opt = newOptionWithDefault(1000);

    assertThrows(InvalidConfigValueException.class, () -> opt.setValue("bogus/s"));

    // Value unchanged after a failed set
    assertEquals(1000, opt.getValue());
    assertEquals("1000", opt.getValueString());
  }

  @Test
  void setValue_whenCallbackRequestsRestart_updatesCurrentValueAndRethrows() throws Exception {
    BandwidthOption opt = newOptionWithDefault(0);

    doThrow(new NodeNeedRestartException("restart please")).when(callback).set(2048);

    assertThrows(NodeNeedRestartException.class, () -> opt.setValue(TWO_KIB_PER_S));

    // Even though a restart is required, Option updates the currentValue before rethrowing
    assertEquals(2048, opt.getValue());
    verify(callback, times(1)).set(2048);
  }

  @Test
  void setValue_whenCallbackRejects_keepsPreviousValue() throws Exception {
    BandwidthOption opt = newOptionWithDefault(2000); // default: 2000 bytes

    doThrow(new InvalidConfigValueException("nope")).when(callback).set(2048);

    assertThrows(InvalidConfigValueException.class, () -> opt.setValue(TWO_KIB_PER_S));

    // The current value should remain the default (unchanged)
    assertEquals(2000, opt.getValue());
    String expectedPersist = network.crypta.support.Fields.intToString(2000, Dimension.NOT);
    assertEquals(expectedPersist, opt.getValueString());
    verify(callback, times(1)).set(2048);
  }

  @Test
  void constructor_withStringDefault_parsesSizeUnits() {
    BandwidthOption opt =
        new BandwidthOption(
            subConfig,
            "bandwidth",
            "2MiB",
            new Option.Meta(10, false, false, "short", "long"),
            callback); // 2 * 1<<20 = 2,097,152 bytes

    // Default (and initial current) value
    assertEquals(2 * 1024 * 1024, opt.getValue());
    // UI: Dimension.SIZE compacts to IEC when evenly divisible
    assertEquals("2MiB", opt.getValueDisplayString());
    // Persistence: plain number
    assertEquals("2097152", opt.getDefault());
  }

  @Test
  void setValue_whenOnlySuffixOrEmpty_throwsInvalidConfigValueException() {
    BandwidthOption opt = newOptionWithDefault(0);
    assertThrows(InvalidConfigValueException.class, () -> opt.setValue("/s"));
    assertThrows(InvalidConfigValueException.class, () -> opt.setValue("   "));
  }

  @Test
  void getDataTypeStr_whenQueried_isNumber() {
    BandwidthOption opt = newOptionWithDefault(0);
    assertEquals(Option.DataType.NUMBER, opt.getDataType());
    assertEquals("number", opt.getDataTypeStr());
  }
}
