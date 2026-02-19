package network.crypta.support;

import ch.qos.logback.classic.LoggerContext;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

@SuppressWarnings("java:S100")
class LoggingTest {
  private final Map<String, ch.qos.logback.classic.Level> previousLoggerLevels = new HashMap<>();
  private LoggerContext loggerContext;
  private ch.qos.logback.classic.Logger rootLogger;
  private ch.qos.logback.classic.Level previousRootLevel;

  @BeforeEach
  void setUp() {
    loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();
    rootLogger = loggerContext.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
    previousRootLevel = rootLogger.getLevel();

    // Ensure static override tracking starts clean for each test.
    Logging.bootstrap(Level.INFO, "");
    rootLogger.setLevel(previousRootLevel);
    loggerContext.resetTurboFilterList();
  }

  @AfterEach
  void tearDown() {
    Logging.bootstrap(Level.INFO, "");
    for (Map.Entry<String, ch.qos.logback.classic.Level> entry : previousLoggerLevels.entrySet()) {
      logger(entry.getKey()).setLevel(entry.getValue());
    }
    previousLoggerLevels.clear();
    rootLogger.setLevel(previousRootLevel);
    loggerContext.resetTurboFilterList();
  }

  @Test
  void setRootLevel_whenLevelProvided_expectRootLoggerLevelUpdated() {
    // Arrange
    ch.qos.logback.classic.Level expectedLevel = ch.qos.logback.classic.Level.ERROR;

    // Act
    Logging.setRootLevel(Level.ERROR);

    // Assert
    assertEquals(expectedLevel, rootLogger.getLevel());
  }

  @Test
  void setLevel_whenNamedLoggerProvided_expectNamedLoggerLevelUpdated() {
    // Arrange
    String loggerName = "network.crypta.support.LoggingTest.setLevelLogger";
    rememberLevel(loggerName);

    // Act
    Logging.setLevel(loggerName, Level.TRACE);

    // Assert
    assertEquals(ch.qos.logback.classic.Level.TRACE, logger(loggerName).getLevel());
  }

  @Test
  void setOff_whenNamedLoggerProvided_expectNamedLoggerTurnedOff() {
    // Arrange
    String loggerName = "network.crypta.support.LoggingTest.setOffLogger";
    rememberLevel(loggerName);

    // Act
    Logging.setOff(loggerName);

    // Assert
    assertEquals(ch.qos.logback.classic.Level.OFF, logger(loggerName).getLevel());
  }

  @Test
  void bootstrap_whenDetailsContainValidLevels_expectRootAndOverridesApplied() {
    // Arrange
    String debugLogger = "network.crypta.support.LoggingTest.bootstrapDebugLogger";
    String errorLogger = "network.crypta.support.LoggingTest.bootstrapErrorLogger";
    rememberLevel(debugLogger);
    rememberLevel(errorLogger);
    String details = debugLogger + ":dEbUg," + errorLogger + ":ERROR";

    // Act
    Logging.bootstrap(Level.WARN, details);

    // Assert
    assertEquals(ch.qos.logback.classic.Level.WARN, rootLogger.getLevel());
    assertEquals(ch.qos.logback.classic.Level.DEBUG, logger(debugLogger).getLevel());
    assertEquals(ch.qos.logback.classic.Level.ERROR, logger(errorLogger).getLevel());
  }

  @Test
  void bootstrap_whenDetailsContainOffAliases_expectNamedLoggersTurnedOff() {
    // Arrange
    String offLogger = "network.crypta.support.LoggingTest.bootstrapOffLogger";
    String noneLogger = "network.crypta.support.LoggingTest.bootstrapNoneLogger";
    rememberLevel(offLogger);
    rememberLevel(noneLogger);
    String details = offLogger + ":off," + noneLogger + ":NoNe";

    // Act
    Logging.bootstrap(Level.INFO, details);

    // Assert
    assertEquals(ch.qos.logback.classic.Level.OFF, logger(offLogger).getLevel());
    assertEquals(ch.qos.logback.classic.Level.OFF, logger(noneLogger).getLevel());
  }

  @Test
  void bootstrap_whenDetailsContainMalformedAndUnknownEntries_expectOnlyValidOverridesApplied() {
    // Arrange
    String ignoredLogger = "network.crypta.support.LoggingTest.bootstrapIgnoredLogger";
    String validLogger = "network.crypta.support.LoggingTest.bootstrapValidLogger";
    rememberLevel(ignoredLogger);
    rememberLevel(validLogger);
    String details = "missingColon," + ignoredLogger + ":BOGUS," + validLogger + ":trace";

    // Act
    Logging.bootstrap(Level.INFO, details);

    // Assert
    assertNull(logger(ignoredLogger).getLevel());
    assertEquals(ch.qos.logback.classic.Level.TRACE, logger(validLogger).getLevel());
  }

  @Test
  void bootstrap_whenDetailsUpdated_expectObsoleteOverrideCleared() {
    // Arrange
    String oldLogger = "network.crypta.support.LoggingTest.bootstrapOldLogger";
    String keptLogger = "network.crypta.support.LoggingTest.bootstrapKeptLogger";
    rememberLevel(oldLogger);
    rememberLevel(keptLogger);
    Logging.bootstrap(Level.INFO, oldLogger + ":DEBUG," + keptLogger + ":ERROR");
    assertEquals(ch.qos.logback.classic.Level.DEBUG, logger(oldLogger).getLevel());
    assertEquals(ch.qos.logback.classic.Level.ERROR, logger(keptLogger).getLevel());

    // Act
    Logging.bootstrap(Level.ERROR, keptLogger + ":TRACE");

    // Assert
    assertEquals(ch.qos.logback.classic.Level.ERROR, rootLogger.getLevel());
    assertNull(logger(oldLogger).getLevel());
    assertEquals(ch.qos.logback.classic.Level.TRACE, logger(keptLogger).getLevel());
  }

  @ParameterizedTest
  @NullSource
  @ValueSource(strings = {"", "   "})
  void bootstrap_whenDetailsMissing_expectExistingOverridesClearedAndRootUpdated(String details) {
    // Arrange
    String loggerName = "network.crypta.support.LoggingTest.bootstrapMissingDetailsLogger";
    rememberLevel(loggerName);
    Logging.bootstrap(Level.DEBUG, loggerName + ":INFO");
    assertEquals(ch.qos.logback.classic.Level.INFO, logger(loggerName).getLevel());

    // Act
    Logging.bootstrap(Level.WARN, details);

    // Assert
    assertEquals(ch.qos.logback.classic.Level.WARN, rootLogger.getLevel());
    assertNull(logger(loggerName).getLevel());
  }

  private void rememberLevel(String loggerName) {
    previousLoggerLevels.putIfAbsent(loggerName, logger(loggerName).getLevel());
  }

  private ch.qos.logback.classic.Logger logger(String loggerName) {
    return loggerContext.getLogger(loggerName);
  }
}
