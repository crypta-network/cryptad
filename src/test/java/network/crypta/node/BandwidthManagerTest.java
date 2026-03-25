package network.crypta.node;

import network.crypta.compat.BandwidthIndicator;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.l10n.NodeL10n;
import network.crypta.runtime.alerts.UserAlert;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.support.HTMLNode;
import network.crypta.support.SizeUtil;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static java.util.concurrent.TimeUnit.HOURS;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // test naming convention: method_whenCondition_expectOutcome
class BandwidthManagerTest {

  private static final long DELAY_MS = HOURS.toMillis(24);

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private Ticker ticker;
  @Mock private NodeIPDetector ipDetector;
  @Mock private PersistentConfig config;
  @Mock private SubConfig nodeSubConfig;
  @Mock private BandwidthIndicator indicator;
  @Mock private NodeClientCore clientCore;
  @Mock private UserAlertManager alerts;

  @Captor private ArgumentCaptor<Runnable> runnableCaptor;

  @BeforeEach
  void setUp() {
    // Intentionally, do not stub here to avoid unnecessary stubbing violations on tests that
    // validate static methods only. Each scheduler test wires its own minimal stubs.
  }

  private void wireStartCommon(boolean detectionEnabled) {
    when(node.network().ticker()).thenReturn(ticker);
    when(node.network().ipDetector()).thenReturn(ipDetector);
    when(node.getConfig()).thenReturn(config);
    when(config.get("node")).thenReturn(nodeSubConfig);
    when(nodeSubConfig.getBoolean("connectionSpeedDetection")).thenReturn(detectionEnabled);
  }

  // -------- Static limit validation: output --------

  @ParameterizedTest
  @DisplayName("checkOutputBandwidthLimit: non‑positive -> throws with positive message")
  @ValueSource(ints = {0, -1, -100})
  void checkOutputBandwidthLimit_whenNonPositive_throws(int limit) {
    InvalidConfigValueException ex =
        assertThrows(
            InvalidConfigValueException.class,
            () -> BandwidthManager.checkOutputBandwidthLimit(limit));
    assertEquals(NodeL10n.getBase().getString("Node.bwlimitMustBePositive"), ex.getMessage());
  }

  @Test
  void checkOutputBandwidthLimit_whenBelowMinimum_throwsMinimumMessage() {
    int min = Node.getMinimumBandwidth();
    int underMin = min - 1;
    InvalidConfigValueException ex =
        assertThrows(
            InvalidConfigValueException.class,
            () -> BandwidthManager.checkOutputBandwidthLimit(underMin));
    String expected =
        NodeL10n.getBase()
            .getString(
                "Node.bandwidthMinimum",
                new String[] {"limit", "minimum"},
                new String[] {Integer.toString(underMin), Integer.toString(min)});
    assertEquals(expected, ex.getMessage());
  }

  @Test
  void checkOutputBandwidthLimit_whenAboveMax_throwsWithMaxMessage() {
    int tooHigh = (int) (java.util.concurrent.TimeUnit.SECONDS.toNanos(1) + 1);
    InvalidConfigValueException ex =
        assertThrows(
            InvalidConfigValueException.class,
            () -> BandwidthManager.checkOutputBandwidthLimit(tooHigh));
    String expected =
        NodeL10n.getBase()
            .getString(
                "Node.outputBwlimitMustBeLessThan",
                "max",
                Long.toString(java.util.concurrent.TimeUnit.SECONDS.toNanos(1)));
    assertEquals(expected, ex.getMessage());
  }

  @Test
  void checkOutputBandwidthLimit_whenAtBoundaries_doesNotThrow() {
    int min = Node.getMinimumBandwidth();
    assertDoesNotThrow(() -> BandwidthManager.checkOutputBandwidthLimit(min));
    // Boundary: exactly equal to SECONDS.toNanos(1) is accepted by current implementation
    int atUpper = (int) java.util.concurrent.TimeUnit.SECONDS.toNanos(1);
    assertDoesNotThrow(() -> BandwidthManager.checkOutputBandwidthLimit(atUpper));
  }

  // -------- Static limit validation: input --------

  @ParameterizedTest
  @DisplayName("checkInputBandwidthLimit: 0/1 -> throws specific message")
  @ValueSource(ints = {0, 1})
  void checkInputBandwidthLimit_whenZeroOrOne_throws(int limit) {
    InvalidConfigValueException ex =
        assertThrows(
            InvalidConfigValueException.class,
            () -> BandwidthManager.checkInputBandwidthLimit(limit));
    assertEquals(
        NodeL10n.getBase().getString("Node.bandwidthLimitMustBePositiveOrMinusOne"),
        ex.getMessage());
  }

  @Test
  void checkInputBandwidthLimit_whenMinusOne_isAccepted() {
    assertDoesNotThrow(() -> BandwidthManager.checkInputBandwidthLimit(-1));
  }

  @Test
  void checkInputBandwidthLimit_whenBelowMinimum_throwsMinimumMessage() {
    int min = Node.getMinimumBandwidth();
    int underMin = min - 1;
    InvalidConfigValueException ex =
        assertThrows(
            InvalidConfigValueException.class,
            () -> BandwidthManager.checkInputBandwidthLimit(underMin));
    String expected =
        NodeL10n.getBase()
            .getString(
                "Node.bandwidthMinimum",
                new String[] {"limit", "minimum"},
                new String[] {Integer.toString(underMin), Integer.toString(min)});
    assertEquals(expected, ex.getMessage());
  }

  @Test
  void checkInputBandwidthLimit_whenAtMinimum_isAccepted() {
    assertDoesNotThrow(() -> BandwidthManager.checkInputBandwidthLimit(Node.getMinimumBandwidth()));
  }

  // -------- Scheduler behavior (start) --------

  @Test
  void start_whenDetectionDisabled_schedulesAndReschedulesWithoutAlert() {
    wireStartCommon(false);
    when(ipDetector.getBandwidthIndicator()).thenReturn(null);

    BandwidthManager bm = new BandwidthManager(node);
    bm.start();

    verify(ticker, times(1)).queueTimedJob(runnableCaptor.capture(), eq(DELAY_MS));
    Runnable scheduled = runnableCaptor.getValue();

    // Running the task should early‑exit and reschedule itself
    scheduled.run();

    // Scheduled twice totally (initial + reschedule with same instance)
    verify(ticker, times(2)).queueTimedJob(scheduled, DELAY_MS);
    // Should not attempt detection or create alerts
    // getBandwidthIndicator() is called before checking the flag; we stubbed it to return null
    verify(ipDetector, times(1)).getBandwidthIndicator();
    verify(alerts, never()).register(any(UserAlert.class));
  }

  @Test
  void start_whenIndicatorNull_schedulesAndReschedulesWithoutAlert() {
    wireStartCommon(true);
    when(ipDetector.getBandwidthIndicator()).thenReturn(null);

    BandwidthManager bm = new BandwidthManager(node);
    bm.start();

    verify(ticker).queueTimedJob(runnableCaptor.capture(), eq(DELAY_MS));
    Runnable scheduled = runnableCaptor.getValue();

    scheduled.run();

    verify(ticker, times(2)).queueTimedJob(scheduled, DELAY_MS);
    verify(alerts, never()).register(any(UserAlert.class));
  }

  @Test
  void start_whenDetectedValuesExactlyTripled_doesNotAlert() {
    wireStartCommon(true);
    when(ipDetector.getBandwidthIndicator()).thenReturn(indicator);

    int currentIn = 1000;
    int currentOut = 2000;
    when(nodeSubConfig.getInt("inputBandwidthLimit")).thenReturn(currentIn);
    when(nodeSubConfig.getInt("outputBandwidthLimit")).thenReturn(currentOut);

    // Detected values are exactly 3x current (no alert because the condition uses >, not >=)
    when(indicator.getDownstreamMaxBitRate()).thenReturn(currentIn * 3 * 8);
    when(indicator.getUpstreamMaxBitRate()).thenReturn(currentOut * 3 * 8);

    BandwidthManager bm = new BandwidthManager(node);
    bm.start();
    verify(ticker).queueTimedJob(runnableCaptor.capture(), eq(DELAY_MS));
    Runnable scheduled = runnableCaptor.getValue();

    scheduled.run();

    verify(alerts, never()).register(any(UserAlert.class));
    verify(ticker, times(2)).queueTimedJob(scheduled, DELAY_MS);
  }

  @Test
  void start_whenInputDetectedTriples_registersAlertWithExpectedOffer() {
    wireStartCommon(true);
    when(ipDetector.getBandwidthIndicator()).thenReturn(indicator);
    when(node.services().clientCore()).thenReturn(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);
    when(clientCore.getFormPassword()).thenReturn("pw");

    int currentIn = 1000;
    int currentOut = 1000;
    when(nodeSubConfig.getInt("inputBandwidthLimit")).thenReturn(currentIn);
    when(nodeSubConfig.getInt("outputBandwidthLimit")).thenReturn(currentOut);

    // Downstream (download) detected at 4000 bytes/s (32,000 bps); upstream small (100 bytes/s)
    when(indicator.getDownstreamMaxBitRate()).thenReturn(4000 * 8);
    when(indicator.getUpstreamMaxBitRate()).thenReturn(100 * 8);

    BandwidthManager bm = new BandwidthManager(node);
    bm.start();
    verify(ticker).queueTimedJob(runnableCaptor.capture(), eq(DELAY_MS));
    Runnable scheduled = runnableCaptor.getValue();

    // Capture the registered alert
    ArgumentCaptor<UserAlert> alertCaptor = ArgumentCaptor.forClass(UserAlert.class);

    scheduled.run();

    verify(alerts, times(1)).register(alertCaptor.capture());
    UserAlert registered = alertCaptor.getValue();
    // Render HTML and ensure the recommended values appear as input defaults
    HTMLNode html = registered.getHTMLText();
    String rendered = html.generate();

    long expectedDown = 2000; // detected(4000)/2 dominates currentIn
    String expectedDownStr = SizeUtil.formatSize(expectedDown);
    String expectedUpStr = SizeUtil.formatSize(currentOut);

    assertTrue(
        rendered.contains("value=\"" + expectedDownStr + "\""),
        "HTML should include offered download limit");
    assertTrue(
        rendered.contains("value=\"" + expectedUpStr + "\""),
        "HTML should include offered upload limit");

    verify(ticker, times(2)).queueTimedJob(scheduled, DELAY_MS);
  }

  @Test
  void start_whenReRunWithoutFurtherIncrease_doesNotReAlert() {
    when(node.network().ticker()).thenReturn(ticker);
    when(node.network().ipDetector()).thenReturn(ipDetector);
    when(ipDetector.getBandwidthIndicator()).thenReturn(indicator);
    when(node.getConfig()).thenReturn(config);
    when(config.get("node")).thenReturn(nodeSubConfig);
    when(nodeSubConfig.getBoolean("connectionSpeedDetection")).thenReturn(true);
    when(node.services().clientCore()).thenReturn(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);

    int currentIn = 1000;
    int currentOut = 1000;
    when(nodeSubConfig.getInt("inputBandwidthLimit")).thenReturn(currentIn);
    when(nodeSubConfig.getInt("outputBandwidthLimit")).thenReturn(currentOut);

    when(indicator.getDownstreamMaxBitRate()).thenReturn(4000 * 8); // bytes: 4000
    when(indicator.getUpstreamMaxBitRate()).thenReturn(800 * 8); // bytes: 800

    BandwidthManager bm = new BandwidthManager(node);
    bm.start();
    verify(ticker).queueTimedJob(runnableCaptor.capture(), eq(DELAY_MS));
    Runnable scheduled = runnableCaptor.getValue();

    scheduled.run(); // The first run will alert

    // The second run with the same detected values should not alert again
    scheduled.run();

    verify(alerts, times(1)).register(any(UserAlert.class));
    verify(ticker, times(3)).queueTimedJob(scheduled, DELAY_MS);
  }

  @Test
  void start_whenDetectorThrows_stillReschedulesAndPropagates() {
    when(node.network().ticker()).thenReturn(ticker);
    when(node.network().ipDetector()).thenReturn(ipDetector);
    doThrow(new RuntimeException("boom")).when(ipDetector).getBandwidthIndicator();

    BandwidthManager bm = new BandwidthManager(node);
    bm.start();
    verify(ticker).queueTimedJob(runnableCaptor.capture(), eq(DELAY_MS));
    Runnable scheduled = runnableCaptor.getValue();

    RuntimeException thrown =
        assertThrows(RuntimeException.class, scheduled::run, "Expected original exception");
    assertEquals("boom", thrown.getMessage());
    // Even on exception, the runnable reschedules itself in finally
    verify(ticker, times(2)).queueTimedJob(scheduled, DELAY_MS);
  }
}
