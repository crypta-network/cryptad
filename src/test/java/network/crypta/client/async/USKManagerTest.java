package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.net.MalformedURLException;
import java.util.concurrent.atomic.AtomicInteger;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchContextOptions;
import network.crypta.client.FetchResult;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.USK;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestClientBuilder;
import network.crypta.node.RequestStarter;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.api.Bucket;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@org.mockito.junit.jupiter.MockitoSettings(strictness = org.mockito.quality.Strictness.LENIENT)
@SuppressWarnings("java:S100")
class USKManagerTest {

  // Minimal inline executor: runs tasks immediately on the calling thread
  private static final class DirectExecutor implements PriorityAwareExecutor {
    @Override
    public void execute(@NonNull Runnable job) {
      job.run();
    }

    @Override
    public void execute(Runnable job, String jobName) {
      job.run();
    }

    @Override
    public void execute(Runnable job, String jobName, boolean fromTicker) {
      job.run();
    }

    @Override
    public int[] waitingThreads() {
      return new int[] {0};
    }

    @Override
    public int[] runningThreads() {
      return new int[] {1};
    }

    @Override
    public int getWaitingThreadsCount() {
      return 0;
    }
  }

  // Minimal HighLevelSimpleClient stub fulfilling only the bits USKManager uses in ctor
  private static final class HLClientStub implements HighLevelSimpleClient {
    @Override
    public void setMaxLength(long maxLength) {
      // no-op in test stub
    }

    @Override
    public void setMaxIntermediateLength(long maxIntermediateLength) {
      // no-op in test stub
    }

    @Override
    public FetchResult fetch(network.crypta.keys.FreenetURI uri) {
      throw new UnsupportedOperationException();
    }

    @Override
    public FetchResult fetchFromMetadata(Bucket initialMetadata) {
      throw new UnsupportedOperationException();
    }

    @Override
    public FetchResult fetch(network.crypta.keys.FreenetURI uri, long maxSize) {
      throw new UnsupportedOperationException();
    }

    @Override
    public FetchResult fetch(
        network.crypta.keys.FreenetURI uri, long maxSize, RequestClient context) {
      throw new UnsupportedOperationException();
    }

    @Override
    public ClientGetter fetch(
        network.crypta.keys.FreenetURI uri,
        ClientGetCallback callback,
        FetchContext fctx,
        short prio) {
      throw new UnsupportedOperationException();
    }

    @Override
    public ClientGetter fetchFromMetadata(
        Bucket initialMetadata, ClientGetCallback callback, FetchContext fctx, short prio) {
      throw new UnsupportedOperationException();
    }

    @Override
    public ClientGetter fetch(
        network.crypta.keys.FreenetURI uri, ClientGetCallback callback, FetchContext fctx) {
      throw new UnsupportedOperationException();
    }

    @Override
    public ClientGetter fetch(
        network.crypta.keys.FreenetURI uri,
        long maxSize,
        ClientGetCallback callback,
        FetchContext fctx,
        short priorityClass) {
      throw new UnsupportedOperationException();
    }

    @Override
    public network.crypta.keys.FreenetURI insert(
        network.crypta.client.InsertBlock insert, boolean getCHKOnly, String filenameHint) {
      throw new UnsupportedOperationException();
    }

    @Override
    public network.crypta.keys.FreenetURI insert(
        network.crypta.client.InsertBlock insert,
        boolean getCHKOnly,
        String filenameHint,
        short priority) {
      throw new UnsupportedOperationException();
    }

    @Override
    public network.crypta.keys.FreenetURI insert(
        network.crypta.client.InsertBlock insert,
        String filenameHint,
        short priority,
        network.crypta.client.InsertContext ctx) {
      throw new UnsupportedOperationException();
    }

    @Override
    public ClientPutter insert(
        network.crypta.client.InsertBlock insert,
        String filenameHint,
        boolean isMetadata,
        network.crypta.client.InsertContext ctx,
        ClientPutCallback cb) {
      throw new UnsupportedOperationException();
    }

    @Override
    public ClientPutter insert(
        network.crypta.client.InsertBlock insert,
        String filenameHint,
        boolean isMetadata,
        network.crypta.client.InsertContext ctx,
        ClientPutCallback cb,
        short priority) {
      throw new UnsupportedOperationException();
    }

    @Override
    public network.crypta.keys.FreenetURI insertRedirect(
        network.crypta.keys.FreenetURI insertURI, network.crypta.keys.FreenetURI target) {
      throw new UnsupportedOperationException();
    }

    @Override
    public network.crypta.keys.FreenetURI insertManifest(
        network.crypta.keys.FreenetURI insertURI,
        java.util.Map<String, Object> bucketsByName,
        String defaultName) {
      throw new UnsupportedOperationException();
    }

    @Override
    public network.crypta.keys.FreenetURI insertManifest(
        network.crypta.keys.FreenetURI insertURI,
        java.util.Map<String, Object> bucketsByName,
        String defaultName,
        short priorityClass) {
      throw new UnsupportedOperationException();
    }

    @Override
    public network.crypta.keys.FreenetURI insertManifest(
        network.crypta.keys.FreenetURI insertURI,
        java.util.Map<String, Object> bucketsByName,
        String defaultName,
        short priorityClass,
        byte[] forceCryptoKey) {
      throw new UnsupportedOperationException();
    }

    @Override
    public FetchContext getFetchContext() {
      // Minimal, deterministic context (values patterned after existing tests)
      return new FetchContext(
          FetchContextOptions.builder()
              .limits(Long.MAX_VALUE, Long.MAX_VALUE, 1024 * 1024)
              .archiveLimits(1, 1, 1, false)
              .retryLimits(0, 0, 0)
              .splitfileLimits(true, 1, 1)
              .behavior(true, false, false)
              .clientOptions(new SimpleEventProducer(), false, true)
              .filterOverrides(null, null, null)
              .build());
    }

    @Override
    public FetchContext getFetchContext(long size) {
      return getFetchContext();
    }

    @Override
    public FetchContext getFetchContext(long size, String schemeHostAndPort) {
      return getFetchContext();
    }

    @Override
    public network.crypta.client.InsertContext getInsertContext(boolean forceNonPersistent) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void addEventHook(network.crypta.client.events.ClientEventListener listener) {
      // No-op for tests
    }

    @Override
    public network.crypta.keys.FreenetURI[] generateKeyPair(String docName) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void prefetch(
        network.crypta.keys.FreenetURI uri,
        long timeout,
        long maxSize,
        java.util.Set<String> allowedTypes) {
      // No-op for tests
    }

    @Override
    public void prefetch(
        network.crypta.keys.FreenetURI uri,
        long timeout,
        long maxSize,
        java.util.Set<String> allowedTypes,
        short prio) {
      // No-op for tests
    }

    @Override
    public HighLevelSimpleClient copy() {
      return this;
    }
  }

  // Simple RequestClient stub with fixed flags
  private static final class RC implements RequestClient {
    private final boolean persistent;
    private final boolean rt;

    RC(boolean persistent, boolean rt) {
      this.persistent = persistent;
      this.rt = rt;
    }

    @Override
    public boolean persistent() {
      return persistent;
    }

    @Override
    public boolean realTimeFlag() {
      return rt;
    }
  }

  // Deterministic USK material for tests
  private static USK newUSK(String site, long edition) throws MalformedURLException {
    byte[] pubKeyHash = new byte[NodeSSK.PUBKEY_HASH_SIZE];
    for (int i = 0; i < pubKeyHash.length; i++) pubKeyHash[i] = (byte) (i & 0xFF);
    byte[] cryptoKey = new byte[ClientSSK.CRYPTO_KEY_LENGTH];
    for (int i = 0; i < cryptoKey.length; i++) cryptoKey[i] = (byte) ((i + 7) & 0xFF);
    byte[] extra =
        new byte[] {
          NodeSSK.SSK_VERSION, 0, Key.ALGO_AES_PCFB_256_SHA256, 0, (byte) KeyBlock.HASH_SHA256
        };
    return new USK(pubKeyHash, cryptoKey, extra, site, edition);
  }

  @Mock private network.crypta.node.NodeClientCore core;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private network.crypta.node.Node node;

  @Mock private ClientContext context;

  private USKManager manager;
  private final PriorityAwareExecutor direct = new DirectExecutor();

  @BeforeEach
  void setUp() {
    // Provide stub client and direct executor for the manager
    when(core.makeClient(RequestStarter.UPDATE_PRIORITY_CLASS, false, false))
        .thenReturn(new HLClientStub());
    when(core.getNode()).thenReturn(node);
    when(node.getExecutor()).thenReturn(direct);
    when(node.network().executor()).thenReturn(direct);
    manager = new USKManager(core);
    manager.init(context);
    when(context.getMainExecutor()).thenReturn(direct);
  }

  @Test
  @DisplayName("lookupKnownGood_and_lookupLatestSlot_initiallyMinusOne")
  void lookupKnownGood_and_lookupLatestSlot_initiallyMinusOne() throws Exception {
    // Arrange
    USK usk = newUSK("site-a", 0L);

    // Act + Assert
    assertEquals(-1, manager.lookupKnownGood(usk));
    assertEquals(-1, manager.lookupLatestSlot(usk));
  }

  @Test
  @DisplayName("updateKnownGood_then_lookup_reflects_new_values")
  void updateKnownGood_then_lookup_reflects_new_values() throws Exception {
    // Arrange
    USK usk = newUSK("site-b", 0L);

    // Act
    manager.updateKnownGood(usk, 10L, context);

    // Assert: both known-good and slot advance to 10
    assertEquals(10L, manager.lookupKnownGood(usk));
    assertEquals(10L, manager.lookupLatestSlot(usk));
  }

  @Test
  @DisplayName("updateSlot_advances_slot_only")
  void updateSlot_advances_slot_only() throws Exception {
    // Arrange
    USK usk = newUSK("site-c", 0L);
    manager.updateKnownGood(usk, 10L, context);

    // Act
    manager.updateSlot(usk, 12L, context);

    // Assert
    assertEquals(10L, manager.lookupKnownGood(usk), "known-good must not change");
    assertEquals(12L, manager.lookupLatestSlot(usk), "slot must advance");
  }

  private static final class CapturingCallback implements USKCallback {
    long l;
    USK key;
    boolean metadata;
    short codec;
    byte[] data;
    boolean newKnownGood;
    boolean newSlotToo;
    final AtomicInteger calls = new AtomicInteger();

    @Override
    public void onFoundEdition(USKFoundEdition foundEdition) {
      this.l = foundEdition.edition();
      this.key = foundEdition.key();
      this.metadata = foundEdition.metadata();
      this.codec = foundEdition.codec();
      this.data = foundEdition.data();
      this.newKnownGood = foundEdition.newKnownGood();
      this.newSlotToo = foundEdition.newSlotToo();
      calls.incrementAndGet();
    }

    @Override
    public short getPollingPriorityNormal() {
      return RequestStarter.UPDATE_PRIORITY_CLASS;
    }

    @Override
    public short getPollingPriorityProgress() {
      return RequestStarter.UPDATE_PRIORITY_CLASS;
    }
  }

  @Test
  @DisplayName("subscribe_whenGoodAndSlotAdvance_triggersImmediateCallbackOnce")
  void subscribe_whenGoodAndSlotAdvance_triggersImmediateCallbackOnce() throws Exception {
    // Arrange: known-good=10, slot=12; subscribe at edition=5
    USK usk = newUSK("site-d", 5L);
    manager.updateKnownGood(usk, 10L, context);
    manager.updateSlot(usk, 12L, context);

    CapturingCallback cb = new CapturingCallback();
    RequestClient client = new RequestClientBuilder().build(); // non-persistent, bulk

    // Act
    manager.subscribe(usk, cb, false, /*ignoreUSKDatehints*/ false, client);

    // Assert: immediate callback with l=goodEd(10) and key edition=curEd(12)
    assertEquals(1, cb.calls.get());
    assertEquals(10L, cb.l);
    assertEquals(12L, cb.key.suggestedEdition);
    assertTrue(cb.newKnownGood);
    assertTrue(cb.newSlotToo);
    assertEquals(-1, cb.codec);
    assertFalse(cb.metadata);
    assertNull(cb.data);

    // Act again: duplicate subscribe is allowed to re-notify when newer editions exist
    manager.subscribe(usk, cb, false, /*ignoreUSKDatehints*/ false, client);
    assertEquals(2, cb.calls.get(), "duplicate subscribe may re-notify when newer editions exist");
  }

  @Test
  @DisplayName("subscribe_whenClientPersistent_throwsUnsupportedOperationException")
  void subscribe_whenClientPersistent_throwsUnsupportedOperationException() throws Exception {
    // Arrange
    USK usk = newUSK("site-e", 0L);
    USKCallback cb = new CapturingCallback();
    RequestClient persistentClient = new RC(true, false);

    // Act + Assert
    assertThrows(
        UnsupportedOperationException.class,
        () -> manager.subscribe(usk, cb, false, /*ignoreUSKDatehints*/ false, persistentClient));
  }

  @Test
  @DisplayName("unsubscribe_removesOnlyTarget_whenMultipleSubscribers")
  void unsubscribe_removesOnlyTarget_whenMultipleSubscribers() throws Exception {
    // Arrange
    USK usk = newUSK("site-f", 0L);
    CapturingCallback cb1 = new CapturingCallback();
    CapturingCallback cb2 = new CapturingCallback();
    RequestClient client = new RC(false, false);

    manager.subscribe(usk, cb1, false, false, client);
    manager.subscribe(usk, cb2, false, false, client);

    // Act
    manager.unsubscribe(usk, cb1);

    // Assert: internal map still has cb2 only
    USK clear = usk.clearCopy();
    USKCallback[] callbacks = manager.subscribersByClearUSK.get(clear);
    assertNotNull(callbacks);
    assertEquals(1, callbacks.length);
    assertSame(cb2, callbacks[0]);
  }

  // Simple USKFetcherCallback for tag creation tests
  private static final class DummyFetcherCallback implements USKFetcherCallback {
    @Override
    public void onFoundEdition(USKFoundEdition foundEdition) {
      // Intentionally no-op: test stub does not assert fetcher callback payloads.
      // These tests only verify tag creation/mapping, not callback behavior.
    }

    @Override
    public void onFailure(ClientContext context) {
      // Intentionally no-op: failure handling is out of scope for this unit test.
    }

    @Override
    public void onCancelled(ClientContext context) {
      // Intentionally no-op: cancellation side effects are not exercised here.
    }

    @Override
    public short getPollingPriorityNormal() {
      return RequestStarter.UPDATE_PRIORITY_CLASS;
    }

    @Override
    public short getPollingPriorityProgress() {
      return RequestStarter.UPDATE_PRIORITY_CLASS;
    }
  }

  @Test
  @DisplayName("getFetcher_buildsTag_withFlagsMapped_fromArguments")
  void getFetcher_buildsTag_withFlagsMapped_fromArguments() throws Exception {
    // Arrange
    USK usk = newUSK("site-g", 1L);
    FetchContext fctx = new HLClientStub().getFetchContext();
    USKFetcherCallback cb = new DummyFetcherCallback();

    // Act
    USKFetcherTag tag =
        manager.getFetcher(
            usk,
            fctx,
            cb,
            new USKFetcherTagOptions(
                /* keepLastData= */ true,
                /* persistent= */ true,
                /* realTime= */ true,
                /* ownFetchContext= */ true,
                context,
                /* checkStoreOnly= */ false));

    // Assert: tag preserves key/callback/context and maps flags as expected
    assertSame(usk, tag.origUSK);
    assertSame(cb, tag.callback);
    assertSame(fctx, tag.ctx);
    assertTrue(tag.keepLastData);
    assertTrue(tag.persistent);
    assertEquals(0L, tag.getToken());
  }

  @Test
  @DisplayName("getFetcherForInsertDontSchedule_respectsIgnoreDateHints_andPersistence")
  void getFetcherForInsertDontSchedule_respectsIgnoreDateHints_andPersistence() throws Exception {
    // Arrange
    USK usk = newUSK("site-h", 2L);
    USKFetcherCallback cb = new DummyFetcherCallback();

    // persistent client: expect a copied FetchContext and keepLastData=true
    RequestClient persistentClient = new RC(true, false);
    USKFetcherTag tag1 =
        manager.getFetcherForInsertDontSchedule(
            usk,
            RequestStarter.UPDATE_PRIORITY_CLASS,
            cb,
            persistentClient,
            context,
            /* persistent= */ true,
            /* ignoreUSKDatehints= */ true);
    // Context is a copy of backgroundFetchContextIgnoreDBR when persistent
    assertTrue(tag1.persistent);
    assertTrue(tag1.keepLastData);
    assertTrue(tag1.ctx.getIgnoreUSKDatehints());

    // bulk non-persistent client: expect manager.backgroundFetchContext (ignore=false)
    RequestClient bulkClient = new RC(false, false);
    USKFetcherTag tag2 =
        manager.getFetcherForInsertDontSchedule(
            usk,
            RequestStarter.UPDATE_PRIORITY_CLASS,
            cb,
            bulkClient,
            context,
            /* persistent= */ false,
            /* ignoreUSKDatehints= */ false);
    assertFalse(tag2.persistent);
    assertTrue(tag2.keepLastData);
    assertFalse(tag2.ctx.getIgnoreUSKDatehints());
  }
}
