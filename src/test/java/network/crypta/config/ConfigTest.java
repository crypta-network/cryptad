package network.crypta.config;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import network.crypta.test.UTFUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Test case for the {@link Config} class.
 *
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 */
@SuppressWarnings("java:S100")
class ConfigTest {
  @BeforeEach
  void setUp() {
    conf = new Config();
    sc = conf.createSubConfig("testing");
  }

  @Test
  void testConfig() {
    // A fresh Config has no registered sub-configs.
    assertEquals(0, new Config().getConfigs().length);
  }

  @Test
  void testRegister() {
    /* test if we can register */
    StringBuilder sb = new StringBuilder();
    char[] printableAscii = UTFUtil.printableAscii();
    for (char value : printableAscii) {
      sb.append(value);
    }
    char[] stressedUtf = UTFUtil.stressedUtf();
    for (char value : stressedUtf) {
      sb.append(value);
    }
    assertNotNull(conf.createSubConfig(sb.toString()));

    /* test if it prevents multiple registrations */
    try {
      conf.register(sc);
    } catch (IllegalArgumentException _) {
      return;
    }
    fail();
  }

  @Test
  void testGetConfigs() {
    assertNotNull(conf.getConfigs());
    // Compare arrays to arrays to avoid dissimilar-type comparison.
    assertNotEquals(conf.getConfigs(), new Config().getConfigs());
    assertEquals(1, conf.getConfigs().length);
    assertSame(sc, conf.getConfigs()[0]);
  }

  @Test
  void testGet() {
    assertSame(sc, conf.get("testing"));
  }

  @Test
  void get_whenUnknownPrefix_returnsNull() {
    assertNull(conf.get("does-not-exist"));
  }

  @Test
  void longOption_whenOptionMissing_throwsNullPointerException() {
    // Arrange
    SubConfig local = conf.createSubConfig("numbers");
    // Act + Assert
    assertThrows(NullPointerException.class, () -> Config.longOption(local, "missing"));
  }

  @Test
  void longOption_whenNonNumeric_throwsClassCastException() {
    // Arrange
    SubConfig local = conf.createSubConfig("strings");
    local.register(
        "greeting",
        "hello",
        new Option.Meta(0, false, false, "short", "long"),
        new NullStringCallback());
    // Act + Assert
    assertThrows(ClassCastException.class, () -> Config.longOption(local, "greeting"));
  }

  @Test
  void longOption_whenLongOption_returnsSameInstance() {
    // Arrange
    SubConfig local = conf.createSubConfig("numbers2");
    local.register(
        "answer",
        42L,
        new Option.Meta(0, false, false, "short", "long"),
        new NullLongCallback(),
        false);

    // Act
    Option<?> expected = local.getOption("answer");
    Option<Long> actual = Config.longOption(local, "answer");

    // Assert
    assertSame(expected, actual);
    assertEquals("42", actual.getValueString());
  }

  @Test
  void longOption_whenIntOption_valueAccessCausesClassCast() {
    // Arrange
    SubConfig local = conf.createSubConfig("ints");
    local.register(
        "seven",
        7,
        new Option.Meta(0, false, false, "short", "long"),
        new NullIntCallback(),
        false);

    Option<Long> numeric = Config.longOption(local, "seven");

    // Act + Assert: lambda makes exactly one call; cast happens in helper
    assertThrows(ClassCastException.class, () -> castToLong(numeric));
  }

  @Test
  void finishedInit_whenSubConfigNotInitialized_logsErrorOnce() {
    // Arrange: one initialized, one not
    SubConfig s1 = conf.createSubConfig("init.done");
    s1.finishedInitialization();
    conf.createSubConfig("init.pending");

    Logger logger = (Logger) LoggerFactory.getLogger(Config.class);
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);

    try {
      // Act
      conf.finishedInit();

      // Assert
      long errorCount =
          appender.list.stream()
              .filter(e -> e.getLevel() == Level.ERROR)
              .filter(e -> e.getFormattedMessage().contains("init.pending"))
              .count();
      assertEquals(1L, errorCount);
    } finally {
      logger.detachAppender(appender);
      appender.stop();
    }
  }

  Config conf;
  SubConfig sc;

  private static void castToLong(Option<Long> opt) {
    // Trigger a runtime cast to Long by passing through a Long-typed parameter.
    consumeLong(opt.getValue());
  }

  private static void consumeLong(Long value) {
    if (value == null) {
      throw new AssertionError("Expected non-null Long");
    }
  }
}
