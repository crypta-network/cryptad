package network.crypta.config;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PersistentConfigTest {

  // -----------------------
  // Helpers
  // -----------------------
  private static List<String> capturePersistentConfigLogs(Runnable r) {
    LoggerContext ctx = (LoggerContext) LoggerFactory.getILoggerFactory();
    ch.qos.logback.classic.Logger logger = ctx.getLogger(PersistentConfig.class);
    Level prev = logger.getLevel();
    logger.setLevel(Level.TRACE);
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    try {
      r.run();
    } finally {
      logger.detachAppender(appender);
      appender.stop();
      logger.setLevel(prev);
    }
    List<String> messages = new ArrayList<>();
    for (ILoggingEvent e : appender.list) {
      messages.add(e.getFormattedMessage());
    }
    return messages;
  }

  // -----------------------
  // Tests
  // -----------------------

  @Test
  void finishedInit_whenOnlyIgnoredOptions_present_noUnknownOptionLogged() {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.put("sub.ignored", true);
    PersistentConfig cfg = new PersistentConfig(sfs);
    SubConfig sub = cfg.createSubConfig("sub");
    sub.registerIgnoredOption("ignored");
    sub.finishedInitialization();

    // Act
    List<String> messages = capturePersistentConfigLogs(cfg::finishedInit);

    // Assert
    assertTrue(messages.isEmpty(), "No unknown-option errors should be logged");
  }

  @Test
  void exportFieldSet_whenOnlyIgnoredOptions_returnsEmpty() {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.put("sub.ignored", true);
    PersistentConfig cfg = new PersistentConfig(sfs);
    SubConfig sub = cfg.createSubConfig("sub");
    sub.registerIgnoredOption("ignored");

    // Act
    SimpleFieldSet out = cfg.exportFieldSet();

    // Assert
    assertTrue(out.isEmpty());
  }

  @Test
  void onRegister_whenMatchingSFSValue_setsTrimmedInitialValue() throws Exception {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("sub.mock", "  value  ");
    PersistentConfig cfg = new PersistentConfig(sfs);
    SubConfig sub = cfg.createSubConfig("sub");

    // Using a Mockito partial mock of Option to capture the value passed to setInitialValue()
    AtomicReference<String> captured = new AtomicReference<>();
    @SuppressWarnings("unchecked")
    Option<Object> mockedOption =
        (Option<Object>)
            mock(
                Option.class,
                withSettings()
                    .useConstructor(
                        sub,
                        "mock",
                        new ConfigCallback<>() {
                          @Override
                          public Object get() {
                            return null;
                          }

                          @Override
                          public void set(Object val) {
                            // No-op for test stub (intentionally empty)
                          }
                        },
                        /* meta= */ null,
                        Option.DataType.STRING)
                    .defaultAnswer(org.mockito.Mockito.RETURNS_DEFAULTS));

    doAnswer(
            inv -> {
              captured.set(inv.getArgument(0, String.class));
              return null;
            })
        .when(mockedOption)
        .setInitialValue(anyString());

    // Act
    sub.register(mockedOption);

    // Assert
    assertEquals("value", captured.get(), "setInitialValue() should receive a trimmed value");
    SimpleFieldSet copy = cfg.getSimpleFieldSet();
    assertNotNull(copy, "Pre-finished copy should not be null");
    assertNull(copy.get("sub.mock"), "Option must be removed from original SFS after processing");
  }

  @Test
  void onRegister_whenInvalidValue_logsErrorAndKeepsDefault() {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("sub.intOpt", "not-a-number");
    PersistentConfig cfg = new PersistentConfig(sfs);
    SubConfig sub = cfg.createSubConfig("sub");
    // Act: register inside capture to record onRegister() logging
    List<String> msgs =
        capturePersistentConfigLogs(
            () ->
                sub.register(
                    "intOpt",
                    7,
                    new Option.Meta(0, false, false, "short", "long"),
                    new NullIntCallback(),
                    false));

    // Assert: error logged and value is default (7)
    boolean sawParseError =
        msgs.stream().anyMatch(m -> m.startsWith("Could not parse config option sub.intOpt"));
    assertTrue(sawParseError, "Should log parse error for invalid initial value");
    assertEquals(7, sub.getInt("intOpt"));

    // And the processed key should be removed from the original SFS
    assertNull(cfg.getSimpleFieldSet().get("sub.intOpt"));
  }

  @Test
  void finishedInit_whenUnknownOptionsRemain_logsEachUnknown() {
    // Arrange: leave keys unprocessed so they are considered unknown
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("orphan.key", "v1");
    sfs.putSingle("foo.bar", "v2");
    PersistentConfig cfg = new PersistentConfig(sfs);

    // Act
    List<String> msgs = capturePersistentConfigLogs(cfg::finishedInit);

    // Assert
    assertTrue(
        msgs.stream().anyMatch(m -> m.contains("Unknown option: orphan.key (value=v1)")),
        "Should log first unknown option");
    assertTrue(
        msgs.stream().anyMatch(m -> m.contains("Unknown option: foo.bar (value=v2)")),
        "Should log second unknown option");
    assertNull(cfg.getSimpleFieldSet(), "After finishedInit, the SFS reference must be null");
  }

  @Test
  void onRegister_whenCalledAfterFinishedInit_throwsIllegalState() {
    // Arrange
    PersistentConfig cfg = new PersistentConfig(new SimpleFieldSet(true));
    cfg.finishedInit();
    SubConfig sub = cfg.createSubConfig("s");
    NullIntCallback cb = new NullIntCallback();
    Option.Meta meta = new Option.Meta(0, false, false, "sd", "ld");

    // Act + Assert
    assertThrows(IllegalStateException.class, () -> sub.register("o", 1, meta, cb, false));
  }

  @Test
  void getSimpleFieldSet_beforeAndAfterFinishedInit_behavesAsExpected() {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("a.b", "c");
    PersistentConfig cfg = new PersistentConfig(sfs);

    // Act + Assert pre-finished
    SimpleFieldSet copy1 = cfg.getSimpleFieldSet();
    assertNotNull(copy1);
    assertEquals("c", copy1.get("a.b"));
    // mutate the copy should not affect internal sfs
    copy1.putSingle("x.y", "z");
    SimpleFieldSet copy2 = cfg.getSimpleFieldSet();
    assertNull(copy2.get("x.y"));

    // After finishedInit it returns null
    cfg.finishedInit();
    assertNull(cfg.getSimpleFieldSet());
  }

  @Test
  void exportFieldSet_withAndWithoutDefaults_respectsOptionState() {
    // Arrange: one changed option, one defaulted option
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    final String KEY_EXP_X = "exp.x";
    final String KEY_EXP_Y = "exp.y";
    sfs.putSingle(KEY_EXP_X, "9"); // will be applied on register
    PersistentConfig cfg = new PersistentConfig(sfs);
    SubConfig sub = cfg.createSubConfig("exp");
    sub.register(
        "x", 5, new Option.Meta(0, false, false, "sd", "ld"), new NullIntCallback(), false);
    sub.register(
        "y", 1, new Option.Meta(0, false, false, "sd", "ld"), new NullIntCallback(), false);

    // Act
    SimpleFieldSet noDefaults = cfg.exportFieldSet(false);
    SimpleFieldSet withDefaults = cfg.exportFieldSet(true);

    // Assert
    assertEquals("9", noDefaults.get(KEY_EXP_X));
    assertNull(
        noDefaults.get(KEY_EXP_Y), "Defaulted option should be omitted when withDefaults=false");
    assertEquals("9", withDefaults.get(KEY_EXP_X));
    assertEquals("1", withDefaults.get(KEY_EXP_Y));
    assertFalse(withDefaults.isEmpty());
  }

  @Test
  void onRegister_whenNoInitialSFS_keepsDefaultsAndNoSfsCopy() {
    // Arrange
    PersistentConfig cfg = new PersistentConfig(null);
    SubConfig sub = cfg.createSubConfig("p");

    // Act
    sub.register(
        "count", 11, new Option.Meta(0, false, false, "sd", "ld"), new NullIntCallback(), false);

    // Assert: value remains default and getSimpleFieldSet() is null since no SFS was provided
    assertEquals(11, sub.getInt("count"));
    assertNull(cfg.getSimpleFieldSet());
  }
}
