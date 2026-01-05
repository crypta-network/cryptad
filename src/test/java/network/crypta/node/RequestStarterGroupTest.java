package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequestScheduler;
import network.crypta.config.Config;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.Key;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.TimeUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class RequestStarterGroupTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeClientCore core;
  @Mock private PeerManager peerManager;
  @Mock private RandomSource random;
  @Mock private ClientContext clientContext;
  @Mock private PriorityAwareExecutor executor;
  @Mock private NodeStats nodeStats;
  @Mock private NodeNetworkSubsystem network;

  private Config config;

  @BeforeEach
  void setup() {
    config = new Config();
  }

  private RequestStarterGroup newGroup() throws InvalidConfigValueException {
    // portNumber only affects thread names; pick a stable value
    when(core.getNode()).thenReturn(node);
    when(node.network()).thenReturn(network);
    lenient().when(network.executor()).thenReturn(executor);
    when(network.stats()).thenReturn(nodeStats);
    return new RequestStarterGroup(node, core, 12345, random, config, null, clientContext);
  }

  @Test
  @DisplayName("start() schedules all eight starters with descriptive names")
  void start_whenCalled_executesAllStarters() throws Exception {
    RequestStarterGroup group = newGroup();

    List<String> jobNames = new ArrayList<>();
    doAnswer(
            inv -> {
              String name = inv.getArgument(1);
              // Record name and avoid actually running background threads
              jobNames.add(name);
              return null;
            })
        .when(executor)
        .execute(any(Runnable.class), anyString());

    group.start();

    // Eight starters: CHK/SSK × Request/Insert × Bulk/RT
    assertEquals(8, jobNames.size(), "Expected 8 starters to be scheduled");

    // Sanity-check expected labels are present (both bulk and realtime variants)
    assertTrue(
        jobNames.stream().anyMatch(s -> s.contains("CHK Request starter (")),
        "Contains CHK Request starter");
    assertTrue(
        jobNames.stream().anyMatch(s -> s.contains("CHK Insert starter (")),
        "Contains CHK Insert starter");
    assertTrue(
        jobNames.stream().anyMatch(s -> s.contains("SSK Request starter (")),
        "Contains SSK Request starter");
    assertTrue(
        jobNames.stream().anyMatch(s -> s.contains("SSK Insert starter (")),
        "Contains SSK Insert starter");

    // Ensure both realtime and bulk suffixes appear
    assertTrue(jobNames.stream().anyMatch(s -> s.endsWith("(realtime)")), "Has realtime starter");
    assertTrue(jobNames.stream().anyMatch(s -> s.endsWith("(bulk)")), "Has bulk starter");

    // Also verify total invocation count via Mockito
    verify(executor, times(8)).execute(any(Runnable.class), anyString());
  }

  @Test
  @DisplayName("getWindow() reflects peer count and default window")
  void getWindow_whenPeersVary_returnsExpected() throws Exception {
    when(network.peers()).thenReturn(peerManager);
    when(peerManager.countNonBackedOffPeers(true)).thenReturn(3);
    when(peerManager.countNonBackedOffPeers(false)).thenReturn(2);
    RequestStarterGroup group = newGroup();

    // ThrottleWindowManager default is 2.0; currentValue multiplies by non-backed-off peer count
    assertEquals(6.0, group.getWindow(true), 1e-9);
    assertEquals(4.0, group.getWindow(false), 1e-9);
  }

  @Test
  @DisplayName("requestCompleted() increases window and reports location")
  void requestCompleted_whenCalled_updatesWindowAndStats() throws Exception {
    RequestStarterGroup group = newGroup();
    double before = group.getRealWindow(true);

    Key key = mock(Key.class);
    when(key.toNormalizedDouble()).thenReturn(0.42);

    group.requestCompleted(true, false, key, true); // SSK request, realtime

    double after = group.getRealWindow(true);
    assertTrue(after > before, "Window should increase after successful request");
    verify(nodeStats).reportOutgoingRequestLocation(0.42);
  }

  @Test
  @DisplayName("rejectedOverload() decreases window")
  void rejectedOverload_whenCalled_decreasesWindow() throws Exception {
    RequestStarterGroup group = newGroup();

    double before = group.getRealWindow(false);
    group.rejectedOverload(false, true, false); // CHK insert, bulk
    double after = group.getRealWindow(false);

    assertTrue(after < before, "Window should decrease after overload");
  }

  @Test
  @DisplayName("getRTT()/getDelay() return expected defaults for CHK/SSK and RT/Bulk")
  void getDelayAndRTT_whenDefaults_expectConsistentValues() throws Exception {
    // With one peer and default window=2.0, delay is rtt/2
    org.mockito.Mockito.lenient().when(network.peers()).thenReturn(peerManager);
    org.mockito.Mockito.lenient().when(peerManager.countNonBackedOffPeers(false)).thenReturn(1);
    RequestStarterGroup group = newGroup();

    // CHK Request Bulk: rtt=5000, delay=2500
    assertEquals(5000.0, group.getRTT(false, false, false), 1e-9);
    assertEquals(2500.0, group.getDelay(false, false, false), 1e-9);

    // CHK Insert Bulk: rtt=20000, delay=10000
    assertEquals(20000.0, group.getRTT(false, true, false), 1e-9);
    assertEquals(10000.0, group.getDelay(false, true, false), 1e-9);

    // SSK Request RT: rtt=5000, delay=2500
    assertEquals(5000.0, group.getRTT(true, false, true), 1e-9);
    assertEquals(2500.0, group.getDelay(true, false, true), 1e-9);
  }

  @Test
  @DisplayName("getScheduler() maps to correct queue by type and priority default is SOFT")
  void getScheduler_whenCombos_expectCorrectMapping() throws Exception {
    RequestStarterGroup group = newGroup();

    ClientRequestScheduler chkReqBulk = group.getScheduler(false, false, false);
    assertFalse(chkReqBulk.isInsertScheduler(), "CHK requester should be a request scheduler");
    assertEquals("CHKrequester", chkReqBulk.name);
    assertEquals(ClientRequestScheduler.PRIORITY_SOFT, chkReqBulk.getChoosenPriorityScheduler());

    ClientRequestScheduler chkInsBulk = group.getScheduler(false, true, false);
    assertTrue(chkInsBulk.isInsertScheduler(), "CHK inserter should be an insert scheduler");
    assertEquals("CHKinserter", chkInsBulk.name);

    ClientRequestScheduler sskReqRT = group.getScheduler(true, false, true);
    assertFalse(sskReqRT.isInsertScheduler(), "SSK requester RT should be a request scheduler");
    assertEquals("SSKrequester", sskReqRT.name);

    ClientRequestScheduler sskInsRT = group.getScheduler(true, true, true);
    assertTrue(sskInsRT.isInsertScheduler(), "SSK inserter RT should be an insert scheduler");
    assertEquals("SSKinserter", sskInsRT.name);
  }

  @Test
  @DisplayName("setGlobalSalt() initializes persistent salters on all schedulers")
  void setGlobalSalt_whenCalled_initializesPersistentSchedulers() throws Exception {
    RequestStarterGroup group = newGroup();

    // Before: persistent salter is null
    assertNull(group.getScheduler(false, false, false).getGlobalKeySalter(true));
    assertNull(group.getScheduler(true, false, false).getGlobalKeySalter(true));
    assertNull(group.getScheduler(false, true, true).getGlobalKeySalter(true));
    assertNull(group.getScheduler(true, true, true).getGlobalKeySalter(true));

    byte[] salt = new byte[32];
    group.setGlobalSalt(salt);

    // After: persistent salter present for all
    assertNotNull(group.getScheduler(false, false, false).getGlobalKeySalter(true));
    assertNotNull(group.getScheduler(true, false, false).getGlobalKeySalter(true));
    assertNotNull(group.getScheduler(false, true, true).getGlobalKeySalter(true));
    assertNotNull(group.getScheduler(true, true, true).getGlobalKeySalter(true));
  }

  @Test
  @DisplayName("statsPageLine() formats RTT, delay and bandwidth deterministically")
  void statsPageLine_whenDefaults_formatsNumbers() throws Exception {
    when(network.peers()).thenReturn(peerManager);
    when(peerManager.countNonBackedOffPeers(false)).thenReturn(1);
    RequestStarterGroup group = newGroup();

    String line = group.statsPageLine(false, false, false); // CHK Request Bulk

    // Expected with rtt=5000ms, delay=2500ms, size=32768 bytes
    String expected =
        "CHK Request Bulk RTT="
            + TimeUtil.formatTime(5000, 2, true)
            + " delay="
            + TimeUtil.formatTime(2500, 2, true)
            + " bw="
            + (long) ((1000.0 / 2500.0) * 32768)
            + "B/sec";
    assertEquals(expected, line);
  }

  @Test
  @DisplayName("PrioritySchedulerCallback rejects invalid value")
  void priorityCallback_whenInvalid_throws() {
    RequestStarterGroup.PrioritySchedulerCallback cb =
        new RequestStarterGroup.PrioritySchedulerCallback();
    assertThrows(InvalidConfigValueException.class, () -> cb.set("bogus"));
  }

  @Test
  @DisplayName("persistToFieldSet() contains all expected throttle keys")
  void persistToFieldSet_whenCalled_containsExpectedKeys() throws Exception {
    RequestStarterGroup group = newGroup();
    SimpleFieldSet fs = group.persistToFieldSet();

    // Presence checks only (structure is SimpleFieldSet subtrees)
    assertNotNull(fs.subset("ThrottleWindow"));
    assertNotNull(fs.subset("ThrottleWindowRT"));
    assertNotNull(fs.subset("ThrottleWindowCHK"));
    assertNotNull(fs.subset("ThrottleWindowSSK"));
    assertNotNull(fs.subset("CHKRequestThrottle"));
    assertNotNull(fs.subset("SSKRequestThrottle"));
    assertNotNull(fs.subset("CHKInsertThrottle"));
    assertNotNull(fs.subset("SSKInsertThrottle"));
    assertNotNull(fs.subset("CHKRequestThrottleRT"));
    assertNotNull(fs.subset("SSKRequestThrottleRT"));
    assertNotNull(fs.subset("CHKInsertThrottleRT"));
    assertNotNull(fs.subset("SSKInsertThrottleRT"));
  }

  @Test
  @DisplayName("MyRequestThrottle.successfulCompletion() floors RTT and clamps delay")
  @org.mockito.junit.jupiter.MockitoSettings(strictness = org.mockito.quality.Strictness.LENIENT)
  void myRequestThrottle_successfulCompletion_belowFloor_clampsDelayAndUpdatesRTT()
      throws Exception {
    org.mockito.Mockito.lenient().when(network.peers()).thenReturn(peerManager);
    org.mockito.Mockito.lenient().when(peerManager.countNonBackedOffPeers(false)).thenReturn(1);
    RequestStarterGroup group = newGroup();

    // CHK Request Bulk throttle: initial rtt=5000ms, window=2 -> delay=2500
    RequestStarterGroup.MyRequestThrottle throttle = group.getThrottle(false, false, false);
    assertEquals(2500L, throttle.getDelay());

    // Report too-small RTT; should be normalized to 10ms internally
    throttle.successfulCompletion(5);
    assertEquals(10.0, throttle.getRTT(), 1e-9);
    assertEquals(BaseRequestThrottle.MIN_DELAY, throttle.getDelay());

    // Rate = (1000/delay)*size = (1000/20)*32768 = 1,638,400
    assertEquals(1_638_400L, throttle.getRate());
    assertTrue(throttle.toString().contains("RT=false"));

    // Export contains RoundTripTime sub-structure
    SimpleFieldSet tf = throttle.exportFieldSet();
    assertNotNull(tf.subset("RoundTripTime"));
  }

  @Test
  @DisplayName("PrioritySchedulerCallback applies values case-insensitively to both schedulers")
  void priorityCallback_whenValidValues_appliesToBothSchedulers() throws Exception {
    ClientRequestScheduler csRT = mock(ClientRequestScheduler.class);
    ClientRequestScheduler csBulk = mock(ClientRequestScheduler.class);
    // get() consulted during init(); return SOFT first, then HARD after set
    when(csBulk.getChoosenPriorityScheduler())
        .thenReturn(ClientRequestScheduler.PRIORITY_SOFT)
        .thenReturn(ClientRequestScheduler.PRIORITY_HARD)
        .thenReturn(ClientRequestScheduler.PRIORITY_SOFT);

    RequestStarterGroup.PrioritySchedulerCallback cb =
        new RequestStarterGroup.PrioritySchedulerCallback();
    cb.init(csRT, csBulk, "HARD");
    verify(csRT, times(1)).setPriorityScheduler(ClientRequestScheduler.PRIORITY_HARD);
    verify(csBulk, times(1)).setPriorityScheduler(ClientRequestScheduler.PRIORITY_HARD);

    // Change back to soft with mixed case
    cb.set("soft");
    verify(csRT, times(1)).setPriorityScheduler(ClientRequestScheduler.PRIORITY_SOFT);
    verify(csBulk, times(1)).setPriorityScheduler(ClientRequestScheduler.PRIORITY_SOFT);

    // Null is a no-op
    cb.set(null);
    // No further interactions expected
  }

  @Test
  @DisplayName("countQueuedRequests() is zero on a fresh group")
  void countQueuedRequests_whenFresh_isZero() throws Exception {
    RequestStarterGroup group = newGroup();
    assertEquals(0L, group.countQueuedRequests());
  }

  @Test
  @DisplayName("diagnosticThrottlesLine() shows either Request/Insert or CHK/SSK windows")
  void diagnosticThrottlesLine_whenModeSwitches_containsExpectedLabels() throws Exception {
    RequestStarterGroup group = newGroup();
    String reqIns = group.diagnosticThrottlesLine(true);
    assertTrue(reqIns.contains("Request window:"));
    assertTrue(reqIns.contains(", Insert window:"));

    String chkSsk = group.diagnosticThrottlesLine(false);
    assertTrue(chkSsk.contains("CHK window:"));
    assertTrue(chkSsk.contains(", SSK window:"));
  }

  @Test
  @DisplayName("getWindow() uses at least one peer when none are routable")
  void getWindow_whenZeroPeers_usesFloorOfOne() throws Exception {
    when(network.peers()).thenReturn(peerManager);
    when(peerManager.countNonBackedOffPeers(false)).thenReturn(0);
    RequestStarterGroup group = newGroup();
    // Default simulated window = 2.0; Math.max(1, 0 peers) = 1 -> 2 * 1
    assertEquals(2.0, group.getWindow(false), 1e-9);
  }

  @Test
  @DisplayName("MyRequestThrottle.getRate() computes bytes/sec for SSK request")
  void myRequestThrottle_getRate_forSSK() throws Exception {
    when(network.peers()).thenReturn(peerManager);
    when(peerManager.countNonBackedOffPeers(false)).thenReturn(1);
    RequestStarterGroup group = newGroup();
    // SSK Request Bulk uses size=1024 and rtt=5000 => delay=2500, rate=(1000/2500)*1024=409
    RequestStarterGroup.MyRequestThrottle sskReq = group.getThrottle(true, false, false);
    assertEquals(409L, sskReq.getRate());
  }

  @Test
  @DisplayName("requestCompleted() only changes the matching realtime/bulk window")
  void requestCompleted_affectsOnlySelectedModeWindow() throws Exception {
    RequestStarterGroup group = newGroup();
    double bulkBefore = group.getRealWindow(false);
    double rtBefore = group.getRealWindow(true);

    Key key = mock(Key.class);
    when(key.toNormalizedDouble()).thenReturn(0.1);

    group.requestCompleted(false, false, key, true); // realtime path

    double bulkAfter = group.getRealWindow(false);
    double rtAfter = group.getRealWindow(true);

    assertEquals(bulkBefore, bulkAfter, 1e-12, "Bulk window should be unchanged");
    assertTrue(rtAfter > rtBefore, "Realtime window should increase");
  }
}
