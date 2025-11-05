package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.crypt.HashResult;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.Key;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.USK;
import network.crypta.support.compress.Compressor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class USKProxyCompletionCallbackTest {

  @Mock private GetCompletionCallback downstream;

  @Mock private USKManager uskManager;

  private ClientContext context;

  @BeforeEach
  void setUp() {
    // Build a minimal ClientContext instance carrying only the mocked USKManager.
    context =
        new ClientContext(
            0L, // bootID
            null, // ClientLayerPersister jobRunner
            null, // PriorityAwareExecutor mainExecutor
            null, // ArchiveManager archiveManager
            null, // PersistentTempBucketFactory ptbf
            null, // TempBucketFactory tbf
            null, // PersistentFileTracker tracker
            null, // HealingQueue hq
            uskManager, // USKManager
            null, // RandomSource strongRandom
            null, // Random fastWeakRandom
            null, // Ticker ticker
            null, // MemoryLimitedJobRunner
            null, // FilenameGenerator fg
            null, // FilenameGenerator persistentFG
            null, // LockableRandomAccessBufferFactory rafFactory
            null, // LockableRandomAccessBufferFactory persistentRAFFactory
            null, // FileRandomAccessBufferFactory fileRAFTransient
            null, // FileRandomAccessBufferFactory fileRAFPersistent
            null, // RealCompressor rc
            null, // DatastoreChecker checker
            null, // PersistentRequestRoot persistentRoot
            null, // MasterSecret cryptoSecretTransient
            null, // LinkFilterExceptionProvider
            null, // FetchContext defaultPersistentFetchContext
            null, // InsertContext defaultPersistentInsertContext
            null // Config config
            );
  }

  private static byte[] bytes32(byte value) {
    byte[] b = new byte[32];
    Arrays.fill(b, value);
    return b;
  }

  private static byte[] makeSskExtra() {
    // Replicate ClientSSK.getExtraBytes(algo) without accessing protected API.
    byte[] extra = new byte[5];
    extra[0] = NodeSSK.SSK_VERSION;
    extra[1] = 0;
    extra[2] = Key.ALGO_AES_PCFB_256_SHA256;
    extra[3] = 0;
    extra[4] = (byte) 1; // KeyBlock.HASH_SHA256
    return extra;
  }

  private static USK makeUSK(String site, long edition) throws MalformedURLException {
    byte[] pkHash = bytes32((byte) 0x11);
    byte[] crypto = bytes32((byte) 0x22);
    byte[] extra = makeSskExtra();
    return new USK(pkHash, crypto, extra, site, edition);
  }

  @Test
  void onSuccess_whenCalled_updatesKnownGood_andDelegates() throws Exception {
    USK usk = makeUSK("site", 7);
    USKProxyCompletionCallback cb = new USKProxyCompletionCallback(usk, downstream, true);

    StreamGenerator sg = mock(StreamGenerator.class);
    ClientMetadata meta = mock(ClientMetadata.class);
    List<Compressor> decompressors = Collections.emptyList();
    ClientGetState state = mock(ClientGetState.class);

    cb.onSuccess(sg, meta, decompressors, state, context);

    verify(uskManager, times(1)).updateKnownGood(usk, usk.suggestedEdition, context);
    verify(downstream, times(1)).onSuccess(sg, meta, decompressors, state, context);
  }

  @Test
  void onFailure_whenNotEnoughPathComponents_updatesKnownGood_andConvertsURI() throws Exception {
    USK usk = makeUSK("mysite", 42);
    USKProxyCompletionCallback cb = new USKProxyCompletionCallback(usk, downstream, false);

    // Build an SSK that corresponds to the USK edition; turnMySSKIntoUSK should convert it.
    FreenetURI ssk = usk.getURI().sskForUSK();
    FetchException original =
        new FetchException(FetchExceptionMode.NOT_ENOUGH_PATH_COMPONENTS, ssk);

    ClientGetState state = mock(ClientGetState.class);
    cb.onFailure(original, state, context);

    verify(uskManager, times(1)).updateKnownGood(usk, usk.suggestedEdition, context);

    // Downstream should receive a cloned FetchException with the converted USK URI.
    verify(downstream)
        .onFailure(
            org.mockito.ArgumentMatchers.argThat(
                fx -> fx.newURI != null && fx.newURI.isUSK() && fx.newURI.equals(usk.getURI())),
            org.mockito.ArgumentMatchers.eq(state),
            org.mockito.ArgumentMatchers.eq(context));
  }

  @Test
  void onFailure_whenPermanentRedirect_updatesKnownGood_andPassesThroughWhenNoNewURI()
      throws Exception {
    USK usk = makeUSK("abc", 1);
    USKProxyCompletionCallback cb = new USKProxyCompletionCallback(usk, downstream, false);

    FetchException fe = new FetchException(FetchExceptionMode.PERMANENT_REDIRECT);
    ClientGetState state = mock(ClientGetState.class);

    cb.onFailure(fe, state, context);

    verify(uskManager, times(1)).updateKnownGood(usk, usk.suggestedEdition, context);
    verify(downstream, times(1)).onFailure(fe, state, context);
  }

  @Test
  void onFailure_whenOtherMode_doesNotUpdateKnownGood_andPassesThrough() throws Exception {
    USK usk = makeUSK("xyz", 5);
    USKProxyCompletionCallback cb = new USKProxyCompletionCallback(usk, downstream, false);

    FetchException fe = new FetchException(FetchExceptionMode.DATA_NOT_FOUND);
    ClientGetState state = mock(ClientGetState.class);

    cb.onFailure(fe, state, context);

    verify(uskManager, never())
        .updateKnownGood(any(USK.class), any(Long.class), any(ClientContext.class));
    verify(downstream, times(1)).onFailure(fe, state, context);
  }

  @Test
  void onFailure_whenNewUriNull_passthroughSameInstance() throws Exception {
    USK usk = makeUSK("p", 9);
    USKProxyCompletionCallback cb = new USKProxyCompletionCallback(usk, downstream, true);

    FetchException fe = new FetchException(FetchExceptionMode.DATA_NOT_FOUND);
    ClientGetState state = mock(ClientGetState.class);

    cb.onFailure(fe, state, context);

    verify(downstream, times(1)).onFailure(fe, state, context);
  }

  @Test
  void onFailure_whenNewUriSSKNotConvertible_delegatesWithOriginalSSK() throws Exception {
    USK usk = makeUSK("siteA", 2);
    USKProxyCompletionCallback cb = new USKProxyCompletionCallback(usk, downstream, false);

    // Build an SSK with a different docName prefix so turnMySSKIntoUSK will not convert it.
    FreenetURI nonMatchingSSK =
        new FreenetURI(
            "SSK",
            "other-123",
            usk.getURI().getRoutingKey(),
            usk.getURI().getCryptoKey(),
            usk.getURI().getExtra());

    FetchException original =
        new FetchException(FetchExceptionMode.NOT_ENOUGH_PATH_COMPONENTS, nonMatchingSSK);
    ClientGetState state = mock(ClientGetState.class);

    cb.onFailure(original, state, context);

    // Downstream sees a new exception instance but with the same SSK newURI.
    verify(downstream)
        .onFailure(
            org.mockito.ArgumentMatchers.argThat(
                fx -> fx.newURI != null && fx.newURI.equals(nonMatchingSSK) && !fx.newURI.isUSK()),
            org.mockito.ArgumentMatchers.eq(state),
            org.mockito.ArgumentMatchers.eq(context));
  }

  @Test
  void onTransition_whenCalled_doesNotDelegate() throws Exception {
    USK usk = makeUSK("zzz", 0);
    USKProxyCompletionCallback cb = new USKProxyCompletionCallback(usk, downstream, true);

    ClientGetState oldState = mock(ClientGetState.class);
    ClientGetState newState = mock(ClientGetState.class);

    cb.onTransition(oldState, newState, context);

    verify(downstream, never())
        .onTransition(
            any(ClientGetState.class), any(ClientGetState.class), any(ClientContext.class));
  }

  @Test
  void onExpectedMIME_whenDownstreamThrows_propagatesException() throws Exception {
    USK usk = makeUSK("mime", 3);
    USKProxyCompletionCallback cb = new USKProxyCompletionCallback(usk, downstream, false);

    ClientMetadata metadata = mock(ClientMetadata.class);
    doThrow(new FetchException(FetchExceptionMode.WRONG_MIME_TYPE))
        .when(downstream)
        .onExpectedMIME(metadata, context);

    assertThrows(FetchException.class, () -> cb.onExpectedMIME(metadata, context));
  }

  @Test
  void passThrough_sizeAndMetadata_delegates() throws Exception {
    USK usk = makeUSK("pass", 10);
    USKProxyCompletionCallback cb = new USKProxyCompletionCallback(usk, downstream, false);

    ClientGetState state = mock(ClientGetState.class);

    cb.onBlockSetFinished(state, context);
    verify(downstream, times(1)).onBlockSetFinished(state, context);

    cb.onExpectedSize(123L, context);
    verify(downstream, times(1)).onExpectedSize(123L, context);

    cb.onFinalizedMetadata();
    verify(downstream, times(1)).onFinalizedMetadata();
  }

  @Test
  void passThrough_splitfileAndHashes_delegates() throws Exception {
    USK usk = makeUSK("split", 77);
    USKProxyCompletionCallback cb = new USKProxyCompletionCallback(usk, downstream, true);

    cb.onExpectedTopSize(10L, 5L, 3, 4, context);
    verify(downstream, times(1)).onExpectedTopSize(10L, 5L, 3, 4, context);

    byte[] splitKey = new byte[] {1, 2, 3};
    cb.onSplitfileCompatibilityMode(
        CompatibilityMode.COMPAT_CURRENT,
        CompatibilityMode.latest(),
        splitKey,
        true,
        false,
        true,
        context);
    verify(downstream, times(1))
        .onSplitfileCompatibilityMode(
            CompatibilityMode.COMPAT_CURRENT,
            CompatibilityMode.latest(),
            splitKey,
            true,
            false,
            true,
            context);

    HashResult[] hashes = new HashResult[0];
    cb.onHashes(hashes, context);
    verify(downstream, times(1)).onHashes(hashes, context);
  }
}
