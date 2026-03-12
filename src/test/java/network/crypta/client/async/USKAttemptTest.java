package network.crypta.client.async;

import network.crypta.client.FetchContext;
import network.crypta.client.FetchContextOptions;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.ClientSSKBlock;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.USK;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class USKAttemptTest {

  private static final short PROGRESS_PRIORITY = 7;
  private static final short NORMAL_PRIORITY = 3;
  private static final short PARENT_PRIORITY = 9;

  @Mock private USKAttemptCallbacks callbacks;
  @Mock private ClientRequester parent;
  @Mock private ClientContext context;

  private FetchContext fetchContext;
  private USK usk;

  @BeforeEach
  void setUp() throws Exception {
    byte[] pubKeyHash = new byte[NodeSSK.PUBKEY_HASH_SIZE];
    byte[] cryptoKey = new byte[ClientSSK.CRYPTO_KEY_LENGTH];
    byte[] extras =
        new byte[] {
          NodeSSK.SSK_VERSION, 0, Key.ALGO_AES_PCFB_256_SHA256, 0, (byte) KeyBlock.HASH_SHA256
        };
    usk = new USK(pubKeyHash, cryptoKey, extras, "site", 0L);

    fetchContext =
        new FetchContext(
            FetchContextOptions.builder()
                .limits(16 * 1024L, 16 * 1024L, 4096)
                .archiveLimits(1, 0, 0, true)
                .retryLimits(0, 0, 2)
                .splitfileLimits(true, 0, 0)
                .behavior(false, false, false)
                .clientOptions(new SimpleEventProducer(), true, false)
                .filterOverrides(null, null, null)
                .build());
  }

  @Test
  void onSuccess_whenCalled_marksSucceededAndNotifiesCallbacks() {
    USKAttempt attempt = newAttempt(false);
    ClientSSKBlock block = mock(ClientSSKBlock.class);

    attempt.onSuccess(block, context);

    assertTrue(attempt.succeeded);
    assertNull(attempt.checker);
    verify(callbacks).onSuccess(attempt, false, block, context);
  }

  @Test
  void onDNF_whenCalled_marksDnfAndNotifiesCallbacks() {
    USKAttempt attempt = newAttempt(false);

    attempt.onDNF(context);

    assertTrue(attempt.dnf);
    assertNull(attempt.checker);
    verify(callbacks).onDNF(attempt, context);
  }

  @Test
  void onFatalAuthorError_whenCalled_reportsDontUpdateSuccess() {
    USKAttempt attempt = newAttempt(false);

    attempt.onFatalAuthorError(context);

    assertNull(attempt.checker);
    verify(callbacks).onSuccess(attempt, true, null, context);
  }

  @Test
  void onNetworkError_whenCalled_reportsDnf() {
    USKAttempt attempt = newAttempt(false);

    attempt.onNetworkError(context);

    assertNull(attempt.checker);
    verify(callbacks).onDNF(attempt, context);
  }

  @Test
  void onCancelled_whenCalledTwice_notifiesOnce() {
    USKAttempt attempt = newAttempt(false);

    attempt.onCancelled(context);
    attempt.onCancelled(context);

    assertNull(attempt.checker);
    verify(callbacks, times(1)).onCancelled(attempt, context);
  }

  @Test
  void cancel_whenCheckerPresent_invokesCheckerCancelAndNotifiesOnce() {
    USKAttempt attempt = newAttempt(false);
    USKChecker checker = mock(USKChecker.class);
    attempt.checker = checker;

    attempt.cancel(context);

    assertTrue(attempt.cancelled);
    assertNull(attempt.checker);
    verify(checker).cancel(context);
    verify(callbacks, times(1)).onCancelled(attempt, context);
  }

  @Test
  void schedule_whenCheckerPresent_delegatesToChecker() {
    USKAttempt attempt = newAttempt(false);
    USKChecker checker = mock(USKChecker.class);
    attempt.checker = checker;

    attempt.schedule(context);

    verify(checker).schedule(context);
  }

  @Test
  void schedule_whenCheckerMissing_doesNothing() {
    USKAttempt attempt = newAttempt(false);
    attempt.checker = null;

    attempt.schedule(context);

    assertNull(attempt.checker);
  }

  @Test
  void reloadPollParameters_whenCheckerPresent_refreshesChecker() {
    USKAttempt attempt = newAttempt(false);
    USKChecker checker = mock(USKChecker.class);
    attempt.checker = checker;

    attempt.reloadPollParameters();

    verify(checker).onChangedFetchContext();
  }

  @Test
  void reloadPollParameters_whenCheckerMissing_doesNothing() {
    USKAttempt attempt = newAttempt(false);
    attempt.checker = null;

    attempt.reloadPollParameters();

    assertNull(attempt.checker);
  }

  @Test
  void getPriority_whenBackgroundForeverNotInCooldown_returnsProgressPriority() {
    USKAttempt attempt = newAttempt(true);
    when(callbacks.isBackgroundPoll()).thenReturn(true);
    when(callbacks.getProgressPollPriority()).thenReturn(PROGRESS_PRIORITY);

    short priority = attempt.getPriority();

    assertEquals(PROGRESS_PRIORITY, priority);
  }

  @Test
  void getPriority_whenBackgroundForeverInCooldown_returnsNormalPriority() {
    USKAttempt attempt = newAttempt(true);
    when(callbacks.isBackgroundPoll()).thenReturn(true);
    when(callbacks.getNormalPollPriority()).thenReturn(NORMAL_PRIORITY);

    attempt.onEnterFiniteCooldown(context);

    short priority = attempt.getPriority();

    assertEquals(NORMAL_PRIORITY, priority);
    verify(callbacks).onEnterFiniteCooldown(context);
  }

  @Test
  void getPriority_whenBackgroundNonForever_returnsNormalPriority() {
    USKAttempt attempt = newAttempt(false);
    when(callbacks.isBackgroundPoll()).thenReturn(true);
    when(callbacks.getNormalPollPriority()).thenReturn(NORMAL_PRIORITY);

    short priority = attempt.getPriority();

    assertEquals(NORMAL_PRIORITY, priority);
  }

  @Test
  void getPriority_whenNotBackground_returnsParentPriority() {
    USKAttempt attempt = newAttempt(false);
    when(callbacks.isBackgroundPoll()).thenReturn(false);
    when(parent.getPriorityClass()).thenReturn(PARENT_PRIORITY);

    short priority = attempt.getPriority();

    assertEquals(PARENT_PRIORITY, priority);
  }

  @Test
  void everInCooldown_whenNeverTriggered_returnsFalse() {
    USKAttempt attempt = newAttempt(false);

    assertFalse(attempt.everInCooldown());
  }

  @Test
  void toString_whenForeverIncludesUriAndFlag() {
    USKAttempt attempt = newAttempt(true);

    String description = attempt.toString();

    assertNotNull(description);
    assertTrue(description.contains("USKAttempt for"));
    assertTrue(description.contains(usk.getURI().toString()));
    assertTrue(description.contains("(forever)"));
  }

  @Test
  void toString_whenOneOffOmitsForeverFlag() {
    USKAttempt attempt = newAttempt(false);

    String description = attempt.toString();

    assertNotNull(description);
    assertTrue(description.contains("USKAttempt for"));
    assertTrue(description.contains(usk.getURI().toString()));
    assertFalse(description.contains("(forever)"));
  }

  private USKAttempt newAttempt(boolean forever) {
    USKAttemptContext attemptContext =
        new USKAttemptContext(callbacks, usk, fetchContext, fetchContext, parent, false);
    USKKeyWatchSet.Lookup lookup = new USKKeyWatchSet.Lookup();
    lookup.val = 11L;
    lookup.key = usk.getSSK(lookup.val);
    lookup.ignoreStore = false;
    lookup.label = "test";
    return new USKAttempt(attemptContext, lookup, forever);
  }
}
