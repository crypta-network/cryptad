package network.crypta.config;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.emptyArray;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.util.Arrays;
import java.util.stream.Stream;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.IntCallback;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SubConfigTest {

  private Config config;
  private SubConfig subConfig;

  @BeforeEach
  void setUp() {
    config = new Config();
    subConfig = config.createSubConfig("test");
  }

  @Test
  void registerIgnoredOption_whenRegistered_notListedInOptions() {
    // Arrange
    subConfig.registerIgnoredOption("ignored");
    // Act + Assert
    assertThat(subConfig.getOptions(), emptyArray());
  }

  @Test
  void exportFieldSet_whenIgnoredOptionRegistered_notExported() {
    // Arrange
    subConfig.registerIgnoredOption("ignored");
    // Act + Assert
    assertThat(subConfig.exportFieldSet().isEmpty(), equalTo(true));
  }

  @Test
  void register_whenNameContainsDot_expectIllegalArgument() {
    // Arrange
    String invalidName = "has.dot";
    IntCallback cb = new NullIntCallback();
    Option.Meta meta = new Option.Meta(0, false, false, "s", "l");
    // Act + Assert
    assertThrows(
        IllegalArgumentException.class, () -> subConfig.register(invalidName, 1, meta, cb, false));
  }

  @Test
  void register_whenDuplicateName_expectIllegalArgument() {
    // Arrange
    String name = "dup";
    IntCallback firstCb = new NullIntCallback();
    IntCallback secondCb = new NullIntCallback();
    subConfig.register(name, 1, new Option.Meta(0, false, false, "s", "l"), firstCb, false);
    Option.Meta secondMeta = new Option.Meta(1, false, false, "s2", "l2");
    // Act + Assert
    assertThrows(
        IllegalArgumentException.class,
        () -> subConfig.register(name, 2, secondMeta, secondCb, false));
  }

  @Test
  void getters_whenMissingOrIgnored_returnFallbacks() {
    // Arrange: missing
    assertEquals(-1, subConfig.getInt("missingInt"));
    assertEquals(-1L, subConfig.getLong("missingLong"));
    assertFalse(subConfig.getBoolean("missingBool"));
    assertEquals("", subConfig.getString("missingStr"));
    assertArrayEquals(new String[] {}, subConfig.getStringArr("missingArr"));
    assertEquals(-1, subConfig.getShort("missingShort"));

    // Arrange: ignored
    subConfig.registerIgnoredOption("ignoredInt");
    subConfig.registerIgnoredOption("ignoredLong");
    subConfig.registerIgnoredOption("ignoredBool");
    subConfig.registerIgnoredOption("ignoredStr");
    subConfig.registerIgnoredOption("ignoredArr");
    subConfig.registerIgnoredOption("ignoredShort");

    // Act + Assert: same fallbacks
    assertEquals(-1, subConfig.getInt("ignoredInt"));
    assertEquals(-1L, subConfig.getLong("ignoredLong"));
    assertFalse(subConfig.getBoolean("ignoredBool"));
    assertEquals("", subConfig.getString("ignoredStr"));
    assertArrayEquals(new String[] {}, subConfig.getStringArr("ignoredArr"));
    assertEquals(-1, subConfig.getShort("ignoredShort"));
  }

  @Test
  void getters_whenDefaults_expectTrimmedValues() {
    // Arrange
    subConfig.register(
        "i", 42, new Option.Meta(1, false, false, "sd", "ld"), new NullIntCallback(), false);
    subConfig.register(
        "l", 100L, new Option.Meta(1, false, false, "sd", "ld"), new NullLongCallback(), false);
    subConfig.register(
        "b", true, new Option.Meta(1, false, false, "sd", "ld"), new NullBooleanCallback());
    subConfig.register(
        "s", "  value  ", new Option.Meta(1, false, false, "sd", "ld"), new NullStringCallback());
    subConfig.register(
        "sh",
        (short) 7,
        new Option.Meta(1, false, false, "sd", "ld"),
        new NullShortCallback(),
        false);
    subConfig.register(
        "arr", new String[] {"x", "", "a b"}, new Option.Meta(1, false, false, "sd", "ld"), null);

    // Act + Assert
    assertEquals(42, subConfig.getInt("i"));
    assertEquals(100L, subConfig.getLong("l"));
    assertTrue(subConfig.getBoolean("b"));
    assertEquals("value", subConfig.getString("s")); // SubConfig trims Strings on read
    assertEquals(7, subConfig.getShort("sh"));
    assertArrayEquals(new String[] {"x", "", "a b"}, subConfig.getStringArr("arr"));
  }

  @Test
  void set_whenBooleanAndString_expectApplied() throws Exception {
    // Arrange
    subConfig.register(
        "bool", false, new Option.Meta(1, false, false, "sd", "ld"), new NullBooleanCallback());
    subConfig.register(
        "str", "default", new Option.Meta(1, false, false, "sd", "ld"), new NullStringCallback());
    // Act
    subConfig.set("bool", true);
    subConfig.set("str", "  hi  ");
    // Assert
    assertTrue(subConfig.getBoolean("bool"));
    assertEquals("hi", subConfig.getString("str"));
  }

  @Test
  void finishedInitialization_whenCalled_gettersReflectCallbackValues() {
    // Arrange
    IntCallback cb = mock(IntCallback.class);
    when(cb.get()).thenReturn(123);
    subConfig.register("val", 7, new Option.Meta(1, false, false, "sd", "ld"), cb, false);

    // Before finish: default is returned
    assertEquals(7, subConfig.getInt("val"));

    // Act
    subConfig.finishedInitialization();

    // Assert: now getter proxies to callback
    assertEquals(123, subConfig.getInt("val"));
  }

  @Test
  void forceUpdate_whenUnchanged_stillInvokesCallback() throws Exception {
    // Arrange
    IntCallback cb = mock(IntCallback.class);
    subConfig.register("x", 5, new Option.Meta(1, false, false, "sd", "ld"), cb, false);

    // Act
    subConfig.forceUpdate("x");

    // Assert: callback.set called with the current value
    verify(cb, times(1)).set(5);
  }

  @Test
  void setOptions_whenValidValues_expectApplied() {
    // Arrange
    subConfig.register(
        "i", 0, new Option.Meta(1, false, false, "sd", "ld"), new NullIntCallback(), false);
    subConfig.register(
        "l", 1L, new Option.Meta(1, false, false, "sd", "ld"), new NullLongCallback(), false);
    subConfig.register(
        "b", false, new Option.Meta(1, false, false, "sd", "ld"), new NullBooleanCallback());
    subConfig.register(
        "s", "d", new Option.Meta(1, false, false, "sd", "ld"), new NullStringCallback());
    subConfig.register(
        "sh",
        (short) 1,
        new Option.Meta(1, false, false, "sd", "ld"),
        new NullShortCallback(),
        false);
    subConfig.register(
        "arr",
        new String[] {"abc"},
        new Option.Meta(1, false, false, "sd", "ld"),
        new network.crypta.support.api.StringArrCallback() {
          @Override
          public String[] get() {
            return new String[0];
          }

          @Override
          public void set(String[] val) {
            // no-op
          }
        });

    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("i", "5");
    sfs.putSingle("l", "2");
    sfs.putSingle("b", "true");
    sfs.putSingle("s", "hello ");
    sfs.putSingle("sh", "12");
    sfs.putSingle("arr", "a;b;%20");

    // Act
    subConfig.setOptions(sfs);

    // Assert
    assertEquals(5, subConfig.getInt("i"));
    assertEquals(2L, subConfig.getLong("l"));
    assertTrue(subConfig.getBoolean("b"));
    assertEquals("hello", subConfig.getString("s"));
    assertEquals(12, subConfig.getShort("sh"));
    assertArrayEquals(new String[] {"a", "b", " "}, subConfig.getStringArr("arr"));
  }

  @Test
  void setOptions_whenInvalidValue_expectErrorLoggedAndValueUnchanged() {
    // Arrange
    subConfig.register(
        "i", 10, new Option.Meta(1, false, false, "sd", "ld"), new NullIntCallback(), false);
    Option<?> opt = subConfig.getOption("i");
    String before = opt.getValueString();
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("i", "abc");

    LoggerContext ctx = (LoggerContext) org.slf4j.LoggerFactory.getILoggerFactory();
    ch.qos.logback.classic.Logger logger = ctx.getLogger(SubConfig.class);
    Level prev = logger.getLevel();
    logger.setLevel(Level.TRACE);
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    try {
      // Act
      subConfig.setOptions(sfs);
    } finally {
      logger.detachAppender(appender);
      appender.stop();
      logger.setLevel(prev);
    }

    // Assert: the value unchanged from before and not set to the invalid input; the error was
    // printed
    assertEquals(before, opt.getValueString());
    assertNotEquals("abc", opt.getValueString());
    String combined =
        appender.list.stream()
            .map(ILoggingEvent::getFormattedMessage)
            .reduce("", (a, b) -> a + "\n" + b);
    assertTrue(combined.contains("Invalid config value:"));
    assertTrue(combined.contains("test.i"));
  }

  @Test
  void setOptions_whenCallbackRequestsRestart_expectValueAppliedAndNoThrow() throws Exception {
    // Arrange
    IntCallback cb = mock(IntCallback.class);
    doThrow(new NodeNeedRestartException("needs restart")).when(cb).set(123);
    subConfig.register("j", 0, new Option.Meta(1, false, false, "sd", "ld"), cb, false);
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("j", "123");

    // Act: should not throw
    subConfig.setOptions(sfs);

    // Assert: value updated and callback was invoked
    assertEquals(123, subConfig.getInt("j"));
    verify(cb, times(1)).set(123);
  }

  @Test
  void exportFieldSet_whenCurrentSettings_respectsDefaultsAndForceWrite() {
    // Arrange
    subConfig.register(
        "i", 10, new Option.Meta(1, false, false, "sd", "ld"), new NullIntCallback(), false);
    subConfig.register(
        "force", "def", new Option.Meta(2, false, true, "sd", "ld"), new NullStringCallback());
    subConfig.register(
        "b", false, new Option.Meta(3, false, false, "sd", "ld"), new NullBooleanCallback());
    subConfig.register(
        "l", 100L, new Option.Meta(4, true, false, "sd", "ld"), new NullLongCallback(), false);
    // change two values
    assertDoesNotThrow(() -> subConfig.set("b", true));
    assertDoesNotThrow(() -> subConfig.set("l", "1000"));

    // Act
    SimpleFieldSet fs = subConfig.exportFieldSet(Config.RequestType.CURRENT_SETTINGS, false);

    // Assert
    // default + not forceWrite => absent
    assertNull(fs.get("i"));
    // changed or forceWrite => present
    assertEquals("def", fs.get("force"));
    assertEquals("true", fs.get("b"));
    assertEquals("1000", fs.get("l"));
  }

  @Test
  void exportFieldSet_whenWithDefaultsTrue_includesDefaults() {
    // Arrange
    subConfig.register(
        "i", 10, new Option.Meta(1, false, false, "sd", "ld"), new NullIntCallback(), false);
    // Act
    SimpleFieldSet fs = subConfig.exportFieldSet(Config.RequestType.CURRENT_SETTINGS, true);
    // Assert
    assertEquals("10", fs.get("i"));
  }

  @Test
  void exportFieldSet_whenMetadataRequested_containsExpectedValues() {
    // Arrange
    subConfig.register(
        "i",
        10,
        new Option.Meta(42, true, false, "short.i", "long.i"),
        new NullIntCallback(),
        false);
    subConfig.register(
        "s", "x", new Option.Meta(7, false, true, "short.s", "long.s"), new NullStringCallback());
    subConfig.register(
        "arr",
        new String[] {"a", "b"},
        new Option.Meta(11, false, false, "short.arr", "long.arr"),
        new network.crypta.support.api.StringArrCallback() {
          @Override
          public String[] get() {
            return new String[0];
          }

          @Override
          public void set(String[] val) {
            // no-op
          }
        });

    // Act + Assert
    SimpleFieldSet defaults = subConfig.exportFieldSet(Config.RequestType.DEFAULT_SETTINGS, false);
    assertEquals("10", defaults.get("i"));
    assertEquals("x", defaults.get("s"));

    SimpleFieldSet sorts = subConfig.exportFieldSet(Config.RequestType.SORT_ORDER, false);
    assertEquals("42", sorts.get("i"));
    assertEquals("7", sorts.get("s"));

    SimpleFieldSet experts = subConfig.exportFieldSet(Config.RequestType.EXPERT_FLAG, false);
    assertEquals("true", experts.get("i"));
    assertEquals("false", experts.get("s"));

    SimpleFieldSet forces = subConfig.exportFieldSet(Config.RequestType.FORCE_WRITE_FLAG, false);
    assertEquals("false", forces.get("i"));
    assertEquals("true", forces.get("s"));

    SimpleFieldSet types = subConfig.exportFieldSet(Config.RequestType.DATA_TYPE, false);
    assertEquals("number", types.get("i"));
    assertEquals("string", types.get("s"));
    assertEquals("stringArray", types.get("arr"));

    // Descriptions go through l10n; ensure non-null strings are produced
    SimpleFieldSet shorts = subConfig.exportFieldSet(Config.RequestType.SHORT_DESCRIPTION, false);
    assertNotNull(shorts.get("i"));
    assertNotNull(shorts.get("s"));

    SimpleFieldSet longs = subConfig.exportFieldSet(Config.RequestType.LONG_DESCRIPTION, false);
    assertNotNull(longs.get("i"));
    assertNotNull(longs.get("s"));
  }

  @Test
  void removeOption_whenPresent_expectRemovedAndFallbacks() {
    // Arrange
    subConfig.register(
        "toRemove", 1, new Option.Meta(0, false, false, "sd", "ld"), new NullIntCallback(), false);
    assertNotNull(subConfig.getOption("toRemove"));
    // Act
    Option<?> removed = subConfig.removeOption("toRemove");
    // Assert
    assertNotNull(removed);
    assertNull(subConfig.getOption("toRemove"));
    assertEquals(-1, subConfig.getInt("toRemove"));
  }

  @Test
  @SuppressWarnings("SelfComparison")
  void compareTo_whenUsingPrefixLexOrder_returnsZeroForSameInstance() {
    // Arrange
    SubConfig a = config.createSubConfig("alpha");
    SubConfig b = config.createSubConfig("bravo");
    // Act + Assert
    //noinspection EqualsWithItself
    assertEquals(0, a.compareTo(a));
    assertTrue(a.compareTo(b) < 0);
    assertTrue(b.compareTo(a) > 0);
  }

  @DisplayName("getRawOption lifecycle around PersistentConfig init")
  @Test
  void getRawOption_whenLifecycleTransitions_behavesAsSpecified() {
    // Arrange: prepare PersistentConfig with an initial value for the key
    SimpleFieldSet initial = new SimpleFieldSet(true);
    initial.putSingle("pfx.key", "123");
    PersistentConfig pc = new PersistentConfig(initial);
    SubConfig sc = new SubConfig("pfx", pc);

    // Before registering the option: raw value is visible
    assertEquals("123", sc.getRawOption("key"));

    // After registering: PersistentConfig.onRegister consumes the raw value
    sc.register(
        "key", 0, new Option.Meta(0, false, false, "sd", "ld"), new NullIntCallback(), false);
    assertNull(sc.getRawOption("key"));

    // After finishedInit: calling getRawOption throws
    pc.finishedInit();
    IllegalStateException ex =
        assertThrows(IllegalStateException.class, () -> sc.getRawOption("key"));
    assertTrue(ex.getMessage().contains("finishedInit()"));
  }

  @ParameterizedTest
  @MethodSource("optionNamesOrder")
  void getOptions_whenRegisteredMultiple_preservesInsertionOrder(String[] names) {
    // Arrange
    for (String n : names) {
      subConfig.register(
          n, 0, new Option.Meta(0, false, false, "sd", "ld"), new NullIntCallback(), false);
    }
    // Act
    String[] actual =
        Arrays.stream(subConfig.getOptions()).map(Option::getName).toArray(String[]::new);
    // Assert
    assertArrayEquals(names, actual);
  }

  private static Stream<org.junit.jupiter.params.provider.Arguments> optionNamesOrder() {
    return Stream.of(
        org.junit.jupiter.params.provider.Arguments.of((Object) new String[] {"a", "b"}),
        org.junit.jupiter.params.provider.Arguments.of((Object) new String[] {"x", "y", "z"}));
  }
}
