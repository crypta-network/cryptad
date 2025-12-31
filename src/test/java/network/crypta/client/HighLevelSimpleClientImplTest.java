package network.crypta.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.ClientPutCallback;
import network.crypta.client.events.ClientEvent;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.crypt.EntropySource;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.support.Ticker;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.PersistentTempBucketFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings({"java:S100", "java:S3011"})
class HighLevelSimpleClientImplTest {

  private BucketFactory bucketFactory;
  private ClientContext clientContext;
  private Ticker ticker;

  private HighLevelSimpleClientImpl client;

  @BeforeEach
  void setUp() {
    NodeClientCore core = mock(NodeClientCore.class);
    network.crypta.node.Node node = mock(network.crypta.node.Node.class);
    bucketFactory = mock(BucketFactory.class);
    PersistentTempBucketFactory persistentTempBucketFactory =
        mock(PersistentTempBucketFactory.class);
    clientContext = mock(ClientContext.class);
    ticker = mock(Ticker.class);

    when(core.getNode()).thenReturn(node);
    when(core.getPersistentTempBucketFactory()).thenReturn(persistentTempBucketFactory);
    when(core.getClientContext()).thenReturn(clientContext);
    when(node.getTicker()).thenReturn(ticker);

    // Deterministic RandomSource for key generation tests
    RandomSource random = new DeterministicRandomSource(123456789L);

    client =
        new HighLevelSimpleClientImpl(
            core,
            bucketFactory,
            random,
            /*priorityClass*/ (short) 4,
            /*forceDontIgnoreTooManyPathComponents*/ false,
            /*realTimeFlag*/ true);
  }

  @Test
  void getFetchContext_withoutOverride_usesCurrentMaxesAndDefaults() {
    // Arrange
    client.setMaxLength(1234L);
    client.setMaxIntermediateLength(5678L);

    // Act
    FetchContext ctx = client.getFetchContext();

    // Assert representative fields and all key constants/defaults
    assertEquals(1234L, ctx.getMaxOutputLength(), "maxOutputLength should reflect client setting");
    assertEquals(5678L, ctx.getMaxTempLength(), "maxTempLength should reflect client setting");
    assertEquals(1024 * 1024, ctx.getMaxMetadataSize());
    assertEquals(HighLevelSimpleClientImpl.MAX_RECURSION, ctx.getMaxRecursionLevel());
    assertEquals(HighLevelSimpleClientImpl.MAX_ARCHIVE_RESTARTS, ctx.getMaxArchiveRestarts());
    assertEquals(HighLevelSimpleClientImpl.MAX_ARCHIVE_LEVELS, ctx.getMaxArchiveLevels());
    assertEquals(
        HighLevelSimpleClientImpl.SPLITFILE_BLOCK_RETRIES, ctx.getMaxSplitfileBlockRetries());
    assertEquals(HighLevelSimpleClientImpl.NON_SPLITFILE_RETRIES, ctx.getMaxNonSplitfileRetries());
    assertEquals(HighLevelSimpleClientImpl.USK_RETRIES, ctx.maxUSKRetries);
    assertEquals(HighLevelSimpleClientImpl.FETCH_SPLITFILES, ctx.getAllowSplitfiles());
    assertEquals(HighLevelSimpleClientImpl.FOLLOW_REDIRECTS, ctx.getFollowRedirects());
    assertEquals(HighLevelSimpleClientImpl.LOCAL_REQUESTS_ONLY, ctx.getLocalRequestOnly());
    assertEquals(HighLevelSimpleClientImpl.FILTER_DATA, ctx.getFilterData());
    assertEquals(
        HighLevelSimpleClientImpl.MAX_SPLITFILE_BLOCKS_PER_SEGMENT,
        ctx.getMaxDataBlocksPerSegment());
    assertEquals(
        HighLevelSimpleClientImpl.MAX_SPLITFILE_CHECK_BLOCKS_PER_SEGMENT,
        ctx.getMaxCheckBlocksPerSegment());
    assertEquals(HighLevelSimpleClientImpl.CAN_WRITE_CLIENT_CACHE, ctx.getCanWriteClientCache());
  }

  @Test
  void getFetchContext_withSingleArgOverride_isIgnoredByImplementation() {
    // Arrange
    client.setMaxLength(100L);
    client.setMaxIntermediateLength(200L);

    // Act
    FetchContext ctx = client.getFetchContext(42L);

    // Assert: current implementation ignores the single-arg override
    assertEquals(100L, ctx.getMaxOutputLength());
    assertEquals(200L, ctx.getMaxTempLength());
  }

  @Test
  void getFetchContext_withTwoArgsOverride_setsBothLengths() {
    // Arrange
    client.setMaxLength(100L);
    client.setMaxIntermediateLength(200L);

    // Act
    FetchContext ctx = client.getFetchContext(8192L, "https://localhost:1234");

    // Assert: override applied when >= 0
    assertEquals(8192L, ctx.getMaxOutputLength());
    assertEquals(8192L, ctx.getMaxTempLength());
  }

  @Test
  void makeDefaultFetchContext_returnsContextWithProvidedProducerAndLimits() {
    SimpleEventProducer ep = new SimpleEventProducer();
    BucketFactory bf = mock(BucketFactory.class);

    FetchContext ctx = HighLevelSimpleClientImpl.makeDefaultFetchContext(777L, 888L, bf, ep);

    assertEquals(777L, ctx.getMaxOutputLength());
    assertEquals(888L, ctx.getMaxTempLength());
    assertSame(ep, ctx.getEventProducer(), "should use the provided event producer instance");
    assertEquals(HighLevelSimpleClientImpl.CAN_WRITE_CLIENT_CACHE, ctx.getCanWriteClientCache());
    assertEquals(HighLevelSimpleClientImpl.FILTER_DATA, ctx.getFilterData());
  }

  @Test
  void getFetchContext_withZeroOverride_setsLengthsToZero_andStoresSchemeHostPort()
      throws Exception {
    // Act
    FetchContext ctx = client.getFetchContext(0L, "https://example.org:4040");

    // Assert
    assertEquals(0L, ctx.getMaxOutputLength());
    assertEquals(0L, ctx.getMaxTempLength());

    // Verify schemeHostAndPort private field via reflection to avoid adding public API
    Field f = FetchContext.class.getDeclaredField("schemeHostAndPort");
    f.setAccessible(true);
    assertEquals("https://example.org:4040", f.get(ctx));
  }

  @Test
  void getInsertContext_returnsDefaultsFromConstants() {
    InsertContext ic = client.getInsertContext(true);

    assertEquals(HighLevelSimpleClientImpl.INSERT_RETRIES, ic.getMaxInsertRetries());
    assertEquals(
        HighLevelSimpleClientImpl.CONSECUTIVE_RNFS_ASSUME_SUCCESS,
        ic.getConsecutiveRNFsCountAsSuccess());
    assertEquals(
        HighLevelSimpleClientImpl.SPLITFILE_BLOCKS_PER_SEGMENT, ic.getSplitfileSegmentDataBlocks());
    assertEquals(
        HighLevelSimpleClientImpl.SPLITFILE_CHECK_BLOCKS_PER_SEGMENT,
        ic.getSplitfileSegmentCheckBlocks());
    assertEquals(
        HighLevelSimpleClientImpl.CAN_WRITE_CLIENT_CACHE_INSERTS, ic.isCanWriteClientCache());
    assertEquals(network.crypta.node.Node.FORK_ON_CACHEABLE_DEFAULT, ic.isForkOnCacheable());
    assertEquals(
        HighLevelSimpleClientImpl.EXTRA_INSERTS_SINGLE_BLOCK, ic.getExtraInsertsSingleBlock());
    assertEquals(
        HighLevelSimpleClientImpl.EXTRA_INSERTS_SPLITFILE_HEADER,
        ic.getExtraInsertsSplitfileHeaderBlock());
    assertEquals(CompatibilityMode.latest(), ic.getCompatibilityMode());
  }

  @Test
  void makeDefaultInsertContext_returnsContextWithExpectedDefaults() {
    SimpleEventProducer ep = new SimpleEventProducer();
    InsertContext ic = HighLevelSimpleClientImpl.makeDefaultInsertContext(bucketFactory, ep);

    assertEquals(HighLevelSimpleClientImpl.INSERT_RETRIES, ic.getMaxInsertRetries());
    assertSame(ep, ic.getEventProducer());
    assertEquals(
        HighLevelSimpleClientImpl.CAN_WRITE_CLIENT_CACHE_INSERTS, ic.isCanWriteClientCache());
  }

  @Test
  void copy_preservesLimitsAndFlags_independentInstance() {
    client.setMaxLength(111L);
    client.setMaxIntermediateLength(222L);

    HighLevelSimpleClient copy = client.copy();
    assertNotNull(copy);
    assertNotSame(client, copy);

    FetchContext ctx = copy.getFetchContext();
    assertEquals(111L, ctx.getMaxOutputLength());
    assertEquals(222L, ctx.getMaxTempLength());

    // RequestClient flags
    assertFalse(((HighLevelSimpleClientImpl) copy).persistent());
    assertTrue(((HighLevelSimpleClientImpl) copy).realTimeFlag());
  }

  @Test
  void fetch_overloadWithMaxSize_updatesContextAndStartsGetter() throws Exception {
    // Arrange
    FreenetURI uri = new FreenetURI("KSK@doc");
    ClientGetCallback cb = mock(ClientGetCallback.class);
    when(cb.getRequestClient()).thenReturn(client);
    FetchContext fctx =
        HighLevelSimpleClientImpl.makeDefaultFetchContext(
            10L, 20L, bucketFactory, new SimpleEventProducer());

    // Act
    client.fetch(uri, 4096L, cb, fctx, (short) 5);

    // Assert: fctx maxes updated and start called
    assertEquals(4096L, fctx.getMaxOutputLength());
    assertEquals(4096L, fctx.getMaxTempLength());
    ArgumentCaptor<ClientGetter> cap = ArgumentCaptor.forClass(ClientGetter.class);
    verify(clientContext, times(1)).start(cap.capture());
    assertNotNull(cap.getValue());
  }

  @Test
  void fetch_withNullUri_throwsNPE() {
    assertThrows(NullPointerException.class, () -> client.fetch(null));
  }

  @Test
  void fetchFromMetadata_withNullBucket_throwsNPE() {
    assertThrows(NullPointerException.class, () -> client.fetchFromMetadata(null));
  }

  @Test
  void fetch_asyncWithNullUri_throwsNPE() {
    ClientGetCallback cb = mock(ClientGetCallback.class);
    FetchContext fctx =
        HighLevelSimpleClientImpl.makeDefaultFetchContext(
            1L, 1L, bucketFactory, new SimpleEventProducer());
    assertThrows(NullPointerException.class, () -> client.fetch(null, cb, fctx, (short) 1));
  }

  @Test
  void prefetch_setsAllowedTypes_andSchedulesCancel_andStarts() throws Exception {
    // Arrange
    FreenetURI uri = new FreenetURI("KSK@page");
    Set<String> allowed = new HashSet<>();
    allowed.add("text/html");
    allowed.add("application/xhtml+xml");

    // Act
    client.prefetch(uri, /*timeout*/ 1500L, /*maxSize*/ 2048L, allowed);

    // Assert: scheduled cancel and started
    ArgumentCaptor<Runnable> job = ArgumentCaptor.forClass(Runnable.class);
    verify(ticker, times(1)).queueTimedJob(job.capture(), anyLong());
    assertNotNull(job.getValue());

    ArgumentCaptor<ClientGetter> getterCap = ArgumentCaptor.forClass(ClientGetter.class);
    verify(clientContext, times(1)).start(getterCap.capture());

    // Verify allowed types propagated into the getter's FetchContext
    ClientGetter getter = getterCap.getValue();
    FetchContext ctx = extractFetchContext(getter);
    assertSame(allowed, ctx.getAllowedMIMETypes());
  }

  @Test
  void prefetch_withExplicitPriority_usesProvidedPrio() throws Exception {
    // Arrange
    FreenetURI uri = new FreenetURI("KSK@prio");
    Set<String> allowed = new HashSet<>();
    short prio = 11;

    // Act
    client.prefetch(uri, /*timeout*/ 250L, /*maxSize*/ 512L, allowed, prio);

    // Assert
    ArgumentCaptor<ClientGetter> getterCap = ArgumentCaptor.forClass(ClientGetter.class);
    verify(clientContext, times(1)).start(getterCap.capture());
    ClientGetter getter = getterCap.getValue();
    assertNotNull(getter);

    // priorityClass is defined on ClientRequester (superclass)
    try {
      Field pf =
          getter.getClass().getSuperclass().getSuperclass().getDeclaredField("priorityClass");
      pf.setAccessible(true);
      assertEquals(prio, pf.get(getter));
    } catch (ReflectiveOperationException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  void insertRedirect_whenBucketFactoryThrows_wrapsAsInternalError() throws Exception {
    // Arrange
    FreenetURI insertURI = new FreenetURI("KSK@foo");
    FreenetURI targetURI = new FreenetURI("KSK@bar");
    when(bucketFactory.makeBucket(anyLong())).thenThrow(new java.io.IOException("disk full"));

    // Act + Assert
    assertThrows(InsertException.class, () -> client.insertRedirect(insertURI, targetURI));
  }

  @Test
  void insert_asyncWithPriorityAndMetadata_wiresPutterAndStarts() throws Exception {
    // Arrange
    RandomAccessBucket data = mock(RandomAccessBucket.class);
    ClientMetadata cm = new ClientMetadata();
    InsertBlock block = new InsertBlock(data, cm, FreenetURI.EMPTY_CHK_URI);
    InsertContext ctx = client.getInsertContext(true);
    ClientPutCallback cb = mock(ClientPutCallback.class);
    // The putter constructor reads the RequestClient from the callback
    when(cb.getRequestClient()).thenReturn(client);
    short prio = 7;

    // Act
    client.insert(block, /*filenameHint*/ "file.bin", /*isMetadata*/ true, ctx, cb, prio);

    // Assert: started and fields wired
    ArgumentCaptor<network.crypta.client.async.ClientPutter> cap =
        ArgumentCaptor.forClass(network.crypta.client.async.ClientPutter.class);
    verify(clientContext, times(1)).start(cap.capture());
    network.crypta.client.async.ClientPutter putter = cap.getValue();
    assertNotNull(putter);

    // priorityClass is on ClientRequester
    Field pf = putter.getClass().getSuperclass().getSuperclass().getDeclaredField("priorityClass");
    pf.setAccessible(true);
    assertEquals(prio, pf.get(putter));

    // isMetadata and targetFilename are private fields on ClientPutter
    Field metaF = putter.getClass().getDeclaredField("isMetadata");
    metaF.setAccessible(true);
    assertEquals(true, metaF.get(putter));

    Field nameF = putter.getClass().getDeclaredField("targetFilename");
    nameF.setAccessible(true);
    assertEquals("file.bin", nameF.get(putter));
  }

  @Test
  void fetchFromMetadata_validBucket_startsGetterAndUsesEmptyChkUri() throws Exception {
    // Arrange
    Bucket initial = new network.crypta.support.io.NullBucket();
    ClientGetCallback cb = mock(ClientGetCallback.class);
    when(cb.getRequestClient()).thenReturn(client);
    FetchContext fctx =
        HighLevelSimpleClientImpl.makeDefaultFetchContext(
            100L, 200L, bucketFactory, new SimpleEventProducer());

    // Act
    ClientGetter getter = client.fetchFromMetadata(initial, cb, fctx, (short) 3);

    // Assert
    assertNotNull(getter);
    verify(clientContext, times(1)).start(getter);
    assertEquals(FreenetURI.EMPTY_CHK_URI, getter.getURI());
  }

  @Test
  void addEventHook_acceptsListener() {
    // Arrange
    AtomicInteger hits = new AtomicInteger(0);
    network.crypta.client.events.ClientEventListener listener =
        (ev, producer) -> hits.incrementAndGet();

    // Act: register and synthesize a test event through the internal producer
    client.addEventHook(listener);
    try {
      Field epField = HighLevelSimpleClientImpl.class.getDeclaredField("eventProducer");
      epField.setAccessible(true);
      Object ep = epField.get(client);
      if (ep instanceof network.crypta.client.events.SimpleEventProducer sep) {
        ClientEvent ev =
            new ClientEvent() {
              @Override
              public String getDescription() {
                return "test";
              }

              @Override
              public int getCode() {
                return 42;
              }
            };
        sep.produceEvent(ev, null);
      }
    } catch (ReflectiveOperationException e) {
      throw new AssertionError(e);
    }

    // Assert: listener observed exactly one event
    assertEquals(1, hits.get());
  }

  @Test
  void persistent_returnsFalse() {
    assertFalse(client.persistent());
  }

  @Test
  void generateKeyPair_returnsTwoSSKUris_withDocName() {
    FreenetURI[] pair = client.generateKeyPair("docname");
    assertNotNull(pair);
    assertEquals(2, pair.length);
    assertEquals("SSK", pair[0].getKeyType());
    assertEquals("SSK", pair[1].getKeyType());
    assertEquals("docname", pair[0].getDocName());
    assertEquals("docname", pair[1].getDocName());
  }

  // --- helpers ---

  private static FetchContext extractFetchContext(ClientGetter getter) {
    try {
      Field f;
      try {
        f = getter.getClass().getDeclaredField("ctx");
      } catch (NoSuchFieldException nsf) {
        f = getter.getClass().getSuperclass().getDeclaredField("ctx");
      }
      f.setAccessible(true);
      return (FetchContext) f.get(getter);
    } catch (ReflectiveOperationException e) {
      throw new AssertionError(e);
    }
  }

  /**
   * Minimal deterministic RandomSource for tests: seeds the underlying Random and no-ops entropy.
   */
  private static final class DeterministicRandomSource extends RandomSource {
    DeterministicRandomSource(long seed) {
      setSeed(seed);
    }

    @Override
    public int acceptEntropy(EntropySource source, long data, int entropyGuess) {
      return 0;
    }

    @Override
    public int acceptTimerEntropy(EntropySource timer) {
      return 0;
    }

    @Override
    public int acceptTimerEntropy(EntropySource fnpTimingSource, double bias) {
      return 0;
    }

    @Override
    public int acceptEntropyBytes(
        EntropySource myPacketDataSource, byte[] buf, int offset, int length, double bias) {
      return 0;
    }

    @Override
    public void close() {
      // No resources to release in this deterministic test RandomSource; intentional no-op.
    }
  }
}
