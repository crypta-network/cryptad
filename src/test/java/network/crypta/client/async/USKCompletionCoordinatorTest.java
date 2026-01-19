package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.util.Arrays;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.ClientSSKBlock;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.USK;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestStarter;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class USKCompletionCoordinatorTest {

  @Mock private USKCompletionHandler completionHandler;
  @Mock private USKManager uskManager;
  @Mock private ClientRequester parent;
  @Mock private ClientContext context;

  private USK usk;

  @BeforeEach
  void setUp() throws Exception {
    usk = newUSK();
  }

  @Test
  void applyDecodedData_whenDecodeFalse_doesNothing() {
    USKCompletionCoordinator coordinator = newCoordinator(false);
    ClientSSKBlock block = mock(ClientSSKBlock.class);

    coordinator.applyDecodedData(false, block, context);

    //noinspection resource
    verify(completionHandler, never()).decodeBlockIfNeeded(any(Boolean.class), any(), any(), any());
    verify(completionHandler, never()).applyDecodedData(any(Boolean.class), any(), any());
  }

  @Test
  void applyDecodedData_whenDecodeTrue_decodesAndApplies() {
    USKCompletionCoordinator coordinator = newCoordinator(false);
    ClientSSKBlock block = mock(ClientSSKBlock.class);
    Bucket bucket = mock(Bucket.class);
    when(completionHandler.decodeBlockIfNeeded(true, block, context, parent)).thenReturn(bucket);

    coordinator.applyDecodedData(true, block, context);

    //noinspection resource
    verify(completionHandler).decodeBlockIfNeeded(true, block, context, parent);
    verify(completionHandler).applyDecodedData(true, block, bucket);
  }

  @Test
  void applyFoundDecodedData_whenCalled_delegates() {
    USKCompletionCoordinator coordinator = newCoordinator(false);
    byte[] data = new byte[] {1, 2, 3};

    coordinator.applyFoundDecodedData(true, true, (short) 7, data, context);

    verify(completionHandler).applyFoundDecodedData(true, true, (short) 7, data, context);
  }

  @Test
  void hasLastRequestData_whenHandlerReportsTrue_returnsTrue() {
    when(completionHandler.hasLastRequestData()).thenReturn(true);
    USKCompletionCoordinator coordinator = newCoordinator(false);

    assertTrue(coordinator.hasLastRequestData());
  }

  @Test
  void clearLastRequestData_whenCalled_delegates() {
    USKCompletionCoordinator coordinator = newCoordinator(false);

    coordinator.clearLastRequestData();

    verify(completionHandler).clearLastRequestData();
  }

  @Test
  void releaseLastDataBytes_whenCalled_returnsHandlerValue() {
    byte[] expected = new byte[] {9, 4};
    when(completionHandler.releaseLastDataBytes()).thenReturn(expected);
    USKCompletionCoordinator coordinator = newCoordinator(false);

    assertSame(expected, coordinator.releaseLastDataBytes());
  }

  @Test
  void lastCompressionCodec_whenCalled_returnsHandlerValue() {
    when(completionHandler.lastCompressionCodec()).thenReturn((short) 11);
    USKCompletionCoordinator coordinator = newCoordinator(false);

    assertEquals((short) 11, coordinator.lastCompressionCodec());
  }

  @Test
  void lastWasMetadata_whenCalled_returnsHandlerValue() {
    when(completionHandler.lastWasMetadata()).thenReturn(true);
    USKCompletionCoordinator coordinator = newCoordinator(false);

    assertTrue(coordinator.lastWasMetadata());
  }

  @Test
  void completeCallbacks_whenEditionMissing_callsFailureAndCleansUp() throws Exception {
    KeyListenerTracker tracker = mock(KeyListenerTracker.class);
    ClientRequestScheduler scheduler = newScheduler(context, tracker);
    when(context.getSskFetchScheduler(false)).thenReturn(scheduler);
    when(uskManager.lookupLatestSlot(usk)).thenReturn(-1L);

    USKFetcher fetcher = mock(USKFetcher.class);
    USKFetcherCallback callback = mock(USKFetcherCallback.class);
    USKCompletionCoordinator coordinator = newCoordinator(false);

    coordinator.completeCallbacks(context, fetcher, new USKFetcherCallback[] {callback});

    verify(uskManager).unsubscribe(usk, fetcher);
    verify(uskManager).onFinished(fetcher);
    verify(tracker).removePendingKeys((KeyListener) fetcher);
    verify(callback).onFailure(context);
    verify(callback, never()).onFoundEdition(any());
    verify(completionHandler).releaseLastDataBytes();
    verify(completionHandler).lastCompressionCodec();
    verify(completionHandler).lastWasMetadata();
  }

  @Test
  void completeCallbacks_whenEditionFound_callsFoundEditionWithRetainedData() throws Exception {
    KeyListenerTracker tracker = mock(KeyListenerTracker.class);
    ClientRequestScheduler scheduler = newScheduler(context, tracker);
    when(context.getSskFetchScheduler(true)).thenReturn(scheduler);
    when(uskManager.lookupLatestSlot(usk)).thenReturn(5L);
    byte[] data = new byte[] {1, 2};
    when(completionHandler.releaseLastDataBytes()).thenReturn(data);
    when(completionHandler.lastCompressionCodec()).thenReturn((short) 3);
    when(completionHandler.lastWasMetadata()).thenReturn(true);

    USKFetcher fetcher = mock(USKFetcher.class);
    USKFetcherCallback callback = mock(USKFetcherCallback.class);
    USKCompletionCoordinator coordinator = newCoordinator(true);

    coordinator.completeCallbacks(context, fetcher, new USKFetcherCallback[] {callback});

    ArgumentCaptor<USKFoundEdition> captor = ArgumentCaptor.forClass(USKFoundEdition.class);
    verify(callback).onFoundEdition(captor.capture());
    verify(callback, never()).onFailure(any());

    USKFoundEdition found = captor.getValue();
    assertEquals(5L, found.edition());
    assertEquals(usk.copy(5L), found.key());
    assertSame(context, found.context());
    assertTrue(found.metadata());
    assertEquals((short) 3, found.codec());
    assertArrayEquals(data, found.data());
    assertFalse(found.newKnownGood());
    assertFalse(found.newSlotToo());
  }

  @Test
  void completeCallbacks_whenCallbackThrows_continuesToNext() throws Exception {
    KeyListenerTracker tracker = mock(KeyListenerTracker.class);
    ClientRequestScheduler scheduler = newScheduler(context, tracker);
    when(context.getSskFetchScheduler(false)).thenReturn(scheduler);
    when(uskManager.lookupLatestSlot(usk)).thenReturn(-1L);

    USKFetcher fetcher = mock(USKFetcher.class);
    USKFetcherCallback throwing = mock(USKFetcherCallback.class);
    USKFetcherCallback next = mock(USKFetcherCallback.class);
    doThrow(new RuntimeException("boom")).when(throwing).onFailure(context);

    USKCompletionCoordinator coordinator = newCoordinator(false);

    assertDoesNotThrow(
        () ->
            coordinator.completeCallbacks(
                context, fetcher, new USKFetcherCallback[] {throwing, next}));

    verify(next).onFailure(context);
  }

  @Test
  void finishCancelled_whenCalled_notifiesAllCallbacks() {
    USKCompletionCoordinator coordinator = newCoordinator(true);
    USKFetcherCallback first = mock(USKFetcherCallback.class);
    USKFetcherCallback second = mock(USKFetcherCallback.class);

    coordinator.finishCancelled(context, new USKFetcherCallback[] {first, second});

    verify(first).onCancelled(context);
    verify(second).onCancelled(context);
  }

  private USKCompletionCoordinator newCoordinator(boolean realTimeFlag) {
    return new USKCompletionCoordinator(completionHandler, uskManager, usk, parent, realTimeFlag);
  }

  private static final String SCHED_TRANSIENT_FIELD = "schedTransient";
  private static final String DEFAULT_SITE = "site";
  private static final long DEFAULT_EDITION = 3L;

  private static ClientRequestScheduler newScheduler(
      ClientContext context, KeyListenerTracker tracker) throws Exception {
    RandomSource random = mock(RandomSource.class);
    RequestStarter starter = mock(RequestStarter.class);
    Node node = mock(Node.class);
    NodeClientCore core = mock(NodeClientCore.class);
    DatastoreChecker datastoreChecker = mock(DatastoreChecker.class);
    when(core.getStoreChecker()).thenReturn(datastoreChecker);
    ClientRequestScheduler scheduler =
        new ClientRequestScheduler(
            new ClientRequestScheduler.SchedulerMode(false, true, false),
            random,
            starter,
            node,
            core,
            "test",
            context);
    setSchedTransient(scheduler, tracker);
    return scheduler;
  }

  private static void setSchedTransient(
      ClientRequestScheduler scheduler, KeyListenerTracker tracker) throws Exception {
    Field field = scheduler.getClass().getDeclaredField(SCHED_TRANSIENT_FIELD);
    field.setAccessible(true);
    field.set(scheduler, tracker);
  }

  private static USK newUSK() throws MalformedURLException {
    byte[] pubKeyHash = new byte[NodeSSK.PUBKEY_HASH_SIZE];
    byte[] cryptoKey = new byte[ClientSSK.CRYPTO_KEY_LENGTH];
    Arrays.fill(pubKeyHash, (byte) 0x11);
    Arrays.fill(cryptoKey, (byte) 0x22);
    byte[] extra = new byte[5];
    extra[0] = NodeSSK.SSK_VERSION;
    extra[1] = 0;
    extra[2] = Key.ALGO_AES_PCFB_256_SHA256;
    extra[3] = 0;
    extra[4] = (byte) KeyBlock.HASH_SHA256;
    return new USK(pubKeyHash, cryptoKey, extra, DEFAULT_SITE, DEFAULT_EDITION);
  }
}
