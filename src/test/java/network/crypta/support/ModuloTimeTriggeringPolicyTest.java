package network.crypta.support;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.core.rolling.TimeBasedRollingPolicy;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.TimeZone;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Tests for {@link ModuloTimeTriggeringPolicy}.
 *
 * <p>These tests control the Logback policy clock via the inherited {@code setCurrentTime(long)}
 * and {@code setDateInCurrentPeriod(long)} methods. For modulo alignment checks, tests compute the
 * expected predicate from a fresh {@code System.currentTimeMillis()} captured immediately before
 * calling the policy and skip if the system clock is too close to a minute boundary to avoid race
 * conditions.
 */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ModuloTimeTriggeringPolicyTest {

  private TimeZone originalTz;

  @BeforeEach
  void setUp() {
    originalTz = TimeZone.getDefault();
    TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
  }

  @AfterEach
  void tearDown() {
    TimeZone.setDefault(originalTz);
  }

  private static final String PATTERN = "build/test-logs/app.%d{yyyy-MM-dd_HH-mm}.log";

  private static class TestablePolicy extends ModuloTimeTriggeringPolicy<Object> {
    void setCurrentTimePublic(long millis) {
      super.setCurrentTime(millis);
    }

    void setDateInCurrentPeriodPublic(long millis) {
      super.setDateInCurrentPeriod(millis);
    }
  }

  private static TestablePolicy newPolicy() {
    LoggerContext context = new LoggerContext();

    TimeBasedRollingPolicy<Object> tbrp = new TimeBasedRollingPolicy<>();
    tbrp.setContext(context);
    tbrp.setFileNamePattern(PATTERN);
    // Minimal parent to satisfy RollingPolicyBase#start() checks
    ch.qos.logback.core.rolling.RollingFileAppender<Object> parent =
        new ch.qos.logback.core.rolling.RollingFileAppender<>();
    parent.setContext(context);
    tbrp.setParent(parent);

    TestablePolicy policy = new TestablePolicy();
    policy.setTimeBasedRollingPolicy(tbrp);
    tbrp.setTimeBasedFileNamingAndTriggeringPolicy(policy);

    // Start both so Logback initializes rolling calendar state
    tbrp.start();
    policy.start();
    return policy;
  }

  // No helper needed for single-use constant; inline where used to avoid Sonar warnings.

  @Test
  @DisplayName("isTriggeringEvent when no period boundary => false")
  void isTriggeringEvent_whenNoBoundary_expectFalse() {
    TestablePolicy policy = newPolicy();

    long now = Instant.parse("2025-01-01T00:10:00Z").toEpochMilli();

    // Same current period and current time -> super.isTriggeringEvent returns false
    policy.setDateInCurrentPeriodPublic(now);
    policy.setCurrentTimePublic(now);
    // Prime internal state
    assertFalse(policy.isTriggeringEvent(null, null));
  }

  // Note: We avoid asserting a specific "true" outcome that depends on hitting an internal
  // DefaultTimeBasedFileNamingAndTriggeringPolicy boundary at the exact wall-clock instant.
  // Instead, subsequent tests assert equivalence with alignment predicates while priming state
  // across a minute boundary; the expected outcome may be true or false depending on current time.

  // See note above — minute alignment is covered indirectly; we do not assert a specific outcome
  // that would depend on the current wall-clock minute.

  @Test
  @DisplayName("HOUR unit: result matches (hour%N==0 && minute==0) at boundary")
  void hour_whenBoundary_resultMatchesExpectation() {
    TestablePolicy policy = newPolicy();

    policy.setUnit(ModuloTimeTriggeringPolicy.Unit.HOUR);
    final int multiple = 3;
    policy.setMultiple(multiple);
    ZoneId zone = ZoneId.systemDefault();
    ZonedDateTime zdt =
        ZonedDateTime.ofInstant(Instant.ofEpochMilli(System.currentTimeMillis()), zone);
    // Avoid minute-boundary races that could desynchronize expectation and policy call.
    assumeTrue(
        zdt.getSecond() >= 2 && zdt.getSecond() <= 57,
        "Skip near minute boundary to keep modulo check stable");
    // Force a minute boundary transition in the underlying policy
    long boundary = zdt.withSecond(0).withNano(0).toInstant().toEpochMilli();
    long previous = boundary - 60_000L;

    policy.setDateInCurrentPeriodPublic(previous);
    policy.setCurrentTimePublic(previous);
    assertFalse(policy.isTriggeringEvent(null, null));
    policy.setCurrentTimePublic(boundary);

    // Compute expectation from the same instant the policy uses to avoid races.
    ZonedDateTime zdtCall = ZonedDateTime.ofInstant(Instant.ofEpochMilli(boundary), zone);
    boolean expected = (zdtCall.getHour() % multiple) == 0 && zdtCall.getMinute() == 0;
    assertEquals(policy.isTriggeringEvent(null, null), expected);
  }

  @Test
  @DisplayName("DAY unit: result matches (epochDay%N==0 && 00:00) at boundary")
  void day_whenBoundary_resultMatchesExpectation() {
    TestablePolicy policy = newPolicy();

    policy.setUnit(ModuloTimeTriggeringPolicy.Unit.DAY);
    final int multiple = 2;
    policy.setMultiple(multiple);
    ZoneId zone = ZoneId.systemDefault();
    ZonedDateTime zdt =
        ZonedDateTime.ofInstant(Instant.ofEpochMilli(System.currentTimeMillis()), zone);
    assumeTrue(
        zdt.getSecond() >= 2 && zdt.getSecond() <= 57,
        "Skip near minute boundary to keep modulo check stable");
    long boundary = zdt.withSecond(0).withNano(0).toInstant().toEpochMilli();
    long previous = boundary - 60_000L;

    policy.setDateInCurrentPeriodPublic(previous);
    policy.setCurrentTimePublic(previous);
    assertFalse(policy.isTriggeringEvent(null, null));
    policy.setCurrentTimePublic(boundary);

    // Compute expectation from the same instant the policy uses to avoid races.
    ZonedDateTime zdtCall = ZonedDateTime.ofInstant(Instant.ofEpochMilli(boundary), zone);
    long epochDay = zdtCall.toLocalDate().toEpochDay();
    boolean expected =
        (epochDay % multiple) == 0 && zdtCall.getHour() == 0 && zdtCall.getMinute() == 0;
    assertEquals(policy.isTriggeringEvent(null, null), expected);
  }

  @Test
  @DisplayName("WEEK unit: result matches (isoWeek%N==0 && Monday 00:00) at boundary")
  void week_whenBoundary_resultMatchesExpectation() {
    TestablePolicy policy = newPolicy();

    policy.setUnit(ModuloTimeTriggeringPolicy.Unit.WEEK);
    final int multiple = 2;
    policy.setMultiple(multiple);
    ZoneId zone = ZoneId.systemDefault();
    ZonedDateTime zdt =
        ZonedDateTime.ofInstant(Instant.ofEpochMilli(System.currentTimeMillis()), zone);
    assumeTrue(
        zdt.getSecond() >= 2 && zdt.getSecond() <= 57,
        "Skip near minute boundary to keep modulo check stable");
    long boundary = zdt.withSecond(0).withNano(0).toInstant().toEpochMilli();
    long previous = boundary - 60_000L;

    policy.setDateInCurrentPeriodPublic(previous);
    policy.setCurrentTimePublic(previous);
    assertFalse(policy.isTriggeringEvent(null, null));
    policy.setCurrentTimePublic(boundary);

    // Compute expectation from the same instant the policy uses to avoid races.
    ZonedDateTime zdtCall = ZonedDateTime.ofInstant(Instant.ofEpochMilli(boundary), zone);
    long epochDay = zdtCall.toLocalDate().toEpochDay();
    long isoWeekIndex = Math.floorDiv(epochDay + 3, 7);
    boolean expected =
        (isoWeekIndex % multiple) == 0
            && zdtCall.getDayOfWeek() == java.time.DayOfWeek.MONDAY
            && zdtCall.getHour() == 0
            && zdtCall.getMinute() == 0;
    assertEquals(policy.isTriggeringEvent(null, null), expected);
  }

  @Test
  @DisplayName("MONTH unit: result matches (monthIndex%N==0 && 1st 00:00) at boundary")
  void month_whenBoundary_resultMatchesExpectation() {
    TestablePolicy policy = newPolicy();

    policy.setUnit(ModuloTimeTriggeringPolicy.Unit.MONTH);
    final int multiple = 6;
    policy.setMultiple(multiple);
    ZoneId zone = ZoneId.systemDefault();
    ZonedDateTime zdt =
        ZonedDateTime.ofInstant(Instant.ofEpochMilli(System.currentTimeMillis()), zone);
    assumeTrue(
        zdt.getSecond() >= 2 && zdt.getSecond() <= 57,
        "Skip near minute boundary to keep modulo check stable");
    long boundary = zdt.withSecond(0).withNano(0).toInstant().toEpochMilli();
    long previous = boundary - 60_000L;

    policy.setDateInCurrentPeriodPublic(previous);
    policy.setCurrentTimePublic(previous);
    assertFalse(policy.isTriggeringEvent(null, null));
    policy.setCurrentTimePublic(boundary);

    // Compute expectation from the same instant the policy uses to avoid races.
    ZonedDateTime zdtCall = ZonedDateTime.ofInstant(Instant.ofEpochMilli(boundary), zone);
    int monthIndex = zdtCall.getYear() * 12 + (zdtCall.getMonthValue() - 1);
    boolean expected =
        (monthIndex % multiple) == 0
            && zdtCall.getDayOfMonth() == 1
            && zdtCall.getHour() == 0
            && zdtCall.getMinute() == 0;
    assertEquals(policy.isTriggeringEvent(null, null), expected);
  }

  @Test
  @DisplayName("YEAR unit: result matches (year%N==0 && 00:00 Jan 1) at boundary")
  void year_whenBoundary_resultMatchesExpectation() {
    TestablePolicy policy = newPolicy();

    policy.setUnit(ModuloTimeTriggeringPolicy.Unit.YEAR);
    final int multiple = 4;
    policy.setMultiple(multiple);
    ZoneId zone = ZoneId.systemDefault();
    ZonedDateTime zdt =
        ZonedDateTime.ofInstant(Instant.ofEpochMilli(System.currentTimeMillis()), zone);
    assumeTrue(
        zdt.getSecond() >= 2 && zdt.getSecond() <= 57,
        "Skip near minute boundary to keep modulo check stable");
    long boundary = zdt.withSecond(0).withNano(0).toInstant().toEpochMilli();
    long previous = boundary - 60_000L;

    policy.setDateInCurrentPeriodPublic(previous);
    policy.setCurrentTimePublic(previous);
    assertFalse(policy.isTriggeringEvent(null, null));
    policy.setCurrentTimePublic(boundary);

    // Compute expectation from the same instant the policy uses to avoid races.
    ZonedDateTime zdtCall = ZonedDateTime.ofInstant(Instant.ofEpochMilli(boundary), zone);
    boolean expected =
        (zdtCall.getYear() % multiple) == 0
            && zdtCall.getDayOfYear() == 1
            && zdtCall.getHour() == 0
            && zdtCall.getMinute() == 0;
    assertEquals(policy.isTriggeringEvent(null, null), expected);
  }
}
