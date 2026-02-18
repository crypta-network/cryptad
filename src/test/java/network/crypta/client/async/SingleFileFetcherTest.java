package network.crypta.client.async;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchContextOptions;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.keys.BaseClientKey;
import network.crypta.keys.ClientKey;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.compress.Compressor;
import network.crypta.support.io.BucketTools;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SingleFileFetcherTest {

  @Mock private ClientRequester parent;
  @Mock private GetCompletionCallback cb;
  @Mock private ClientKey key;
  @Mock private ClientContext clientContext;
  @Mock private PersistentJobRunner jobRunner;
  @Mock private BucketFactory bucketFactory;

  @Captor private ArgumentCaptor<FetchException> fetchExceptionCaptor;
  @Captor private ArgumentCaptor<StreamGenerator> sgCaptor;
  @Captor private ArgumentCaptor<ClientMetadata> metadataCaptor;
  @Captor private ArgumentCaptor<List<? extends Compressor>> decompressorsCaptor;

  private FetchContext newCtx(long maxOut, boolean ignoreTooMany) {
    // Use simple, valid values for all required constructor parameters.
    return new FetchContext(
        FetchContextOptions.builder()
            .limits(maxOut, Long.MAX_VALUE, 1024 * 1024)
            .archiveLimits(8, 4, 8, false)
            .retryLimits(0, 0, 0)
            .splitfileLimits(true, 0, 0)
            .behavior(true, false, false)
            .clientOptions(new SimpleEventProducer(), ignoreTooMany, true)
            .filterOverrides(null, null, null)
            .build());
  }

  @BeforeEach
  void setup() {
    lenient().when(parent.persistent()).thenReturn(false);
    lenient().when(clientContext.getBucketFactory(false)).thenReturn(bucketFactory);
    lenient().when(clientContext.getJobRunner(false)).thenReturn(jobRunner);
  }

  private SingleFileFetcher newFetcher(
      List<String> metaStrings, int addedMetaStrings, boolean isFinal, FetchContext ctx, long token)
      throws Exception {
    // Minimal URI (no metastrings) is fine for these paths.
    FreenetURI uri = new FreenetURI("CHK", null);
    when(key.getURI()).thenReturn(uri);

    SingleFileFetcher.InitParams p = new SingleFileFetcher.InitParams();
    p.parent = parent;
    p.cb = cb;
    p.metadata = null; /* clientMetadata */
    p.key = key;
    p.metaStrings = new ArrayList<>(metaStrings);
    p.origURI = uri;
    p.addedMetaStrings = addedMetaStrings;
    p.ctx = ctx;
    p.deleteFetchContext = false;
    p.actx = null;
    p.ah = null;
    p.archiveMetadata = null;
    p.policy = new SingleFileFetcher.CreationPolicy(0, 0, false, false, isFinal, false);
    p.runtime = new SingleFileFetcher.CreationRuntime(clientContext, false, token);
    p.topDontCompress = false;
    p.topCompatibilityMode = (short) 0;
    return new SingleFileFetcher(p);
  }

  @Test
  void onSuccess_whenTooManyPathComponentsAndFinal_reportsTooManyPathComponents() throws Exception {
    FetchContext ctx = newCtx(1024, false /* ignoreTooMany */);
    SingleFileFetcher f = newFetcher(List.of("extra"), 0, true, ctx, 123L);

    Bucket original = mock(Bucket.class);
    ClientMetadata md = new ClientMetadata("text/plain");

    FetchResult result = FetchResult.create(md, original);
    f.onSuccess(result, clientContext);

    verify(cb).onFailure(fetchExceptionCaptor.capture(), eq(f), eq(clientContext));
    assertEquals(
        FetchExceptionMode.TOO_MANY_PATH_COMPONENTS, fetchExceptionCaptor.getValue().getMode());
    verify(original).free();
  }

  @Test
  void onSuccess_whenAddedMetaStringsPositive_reportsInvalidMetadata() throws Exception {
    // ignoreTooMany=false so the metaStrings check applies
    FetchContext ctx = newCtx(1024, false);
    // Simulate metaStrings present and that they were added via redirects (addedMetaStrings > 0)
    SingleFileFetcher f = newFetcher(List.of("redir"), 1, true, ctx, 124L);

    Bucket original = mock(Bucket.class);
    ClientMetadata md = new ClientMetadata("text/plain");

    f.onSuccess(FetchResult.create(md, original), clientContext);

    verify(cb).onFailure(fetchExceptionCaptor.capture(), eq(f), eq(clientContext));
    assertEquals(FetchExceptionMode.INVALID_METADATA, fetchExceptionCaptor.getValue().getMode());
    verify(original).free();
  }

  @Test
  void onSuccess_whenResultTooBig_reportsTooBigAndFreesOriginal() throws Exception {
    FetchContext ctx = newCtx(5 /* maxOut */, true /* ignoreTooMany */);
    SingleFileFetcher f = newFetcher(List.of(), 0, true, ctx, 456L);

    Bucket original = mock(Bucket.class);
    when(original.size()).thenReturn(100L);
    ClientMetadata md = new ClientMetadata("application/octet-stream");

    FetchResult result = FetchResult.create(md, original);
    f.onSuccess(result, clientContext);

    verify(cb).onFailure(fetchExceptionCaptor.capture(), eq(f), eq(clientContext));
    assertEquals(FetchExceptionMode.TOO_BIG, fetchExceptionCaptor.getValue().getMode());
    verify(original).free();
  }

  @Test
  void onSuccess_whenCopyOk_queuesJobAndCallsCallbackWithStream() throws Exception {
    FetchContext ctx = newCtx(10_000, true);
    SingleFileFetcher f = newFetcher(List.of(), 0, true, ctx, 789L);

    Bucket original = mock(Bucket.class);
    when(original.size()).thenReturn(20L);
    RandomAccessBucket copy = mock(RandomAccessBucket.class);
    when(bucketFactory.makeBucket(20L)).thenReturn(copy);

    // Static mock for BucketTools.copy to avoid needing real streams.
    try (var _ = Mockito.mockStatic(BucketTools.class)) {
      ClientMetadata md = new ClientMetadata("text/plain");
      FetchResult result = FetchResult.create(md, original);

      // Execute job immediately when queued
      doAnswer(
              inv -> {
                PersistentJob job = inv.getArgument(0);
                job.run(clientContext);
                return null;
              })
          .when(jobRunner)
          .queueInternal(any(PersistentJob.class));

      f.onSuccess(result, clientContext);

      // Callback is invoked with a SingleFileStreamGenerator and same decompressors list reference
      verify(cb)
          .onSuccess(
              sgCaptor.capture(),
              metadataCaptor.capture(),
              decompressorsCaptor.capture(),
              eq(f),
              eq(clientContext));

      assertNotNull(sgCaptor.getValue());
      assertEquals(md, metadataCaptor.getValue());

      // Verify identity with internal 'decompressors' list via reflection
      Field field = SingleFileFetcher.class.getDeclaredField("decompressors");
      field.setAccessible(true);
      Object internalList = field.get(f);
      assertSame(internalList, decompressorsCaptor.getValue());

      // Original bucket must be freed after scheduling
      verify(original).free();
    }
  }

  @Test
  void onSuccess_whenBucketCopyFails_reportsBucketErrorAndFreesOriginal() throws Exception {
    FetchContext ctx = newCtx(10_000, true);
    SingleFileFetcher f = newFetcher(List.of(), 0, true, ctx, 101L);

    Bucket original = mock(Bucket.class);
    when(original.size()).thenReturn(20L);
    RandomAccessBucket copy = mock(RandomAccessBucket.class);
    when(bucketFactory.makeBucket(20L)).thenReturn(copy);

    try (MockedStatic<BucketTools> bt = Mockito.mockStatic(BucketTools.class)) {
      bt.when(() -> BucketTools.copy(eq(original), eq(copy)))
          .thenThrow(new IOException("copy fail"));

      ClientMetadata md = new ClientMetadata("text/plain");
      FetchResult result = FetchResult.create(md, original);

      f.onSuccess(result, clientContext);

      verify(cb).onFailure(fetchExceptionCaptor.capture(), eq(f), eq(clientContext));
      assertEquals(FetchExceptionMode.BUCKET_ERROR, fetchExceptionCaptor.getValue().getMode());
      verify(original).free();
    }
  }

  @Test
  void onSuccess_whenNotFinalAndMetaStringsRemain_stillSucceeds() throws Exception {
    FetchContext ctx = newCtx(10_000, false /* ignoreTooMany */);
    // metaStrings present but isFinal=false should allow success path
    SingleFileFetcher f = newFetcher(List.of("leftover"), 0, false, ctx, 102L);

    Bucket original = mock(Bucket.class);
    when(original.size()).thenReturn(20L);
    RandomAccessBucket copy = mock(RandomAccessBucket.class);
    when(bucketFactory.makeBucket(20L)).thenReturn(copy);

    try (var _ = Mockito.mockStatic(BucketTools.class)) {
      // Execute job immediately when queued
      doAnswer(
              inv -> {
                PersistentJob job = inv.getArgument(0);
                job.run(clientContext);
                return null;
              })
          .when(jobRunner)
          .queueInternal(any(PersistentJob.class));

      ClientMetadata md = new ClientMetadata("text/plain");
      f.onSuccess(FetchResult.create(md, original), clientContext);

      // We still should succeed because isFinal=false disables the TOO_MANY_PATH_COMPONENTS guard
      verify(cb)
          .onSuccess(
              sgCaptor.capture(),
              metadataCaptor.capture(),
              decompressorsCaptor.capture(),
              eq(f),
              eq(clientContext));
      assertNotNull(sgCaptor.getValue());
      assertEquals(md, metadataCaptor.getValue());
      verify(original).free();
    }
  }

  @Test
  void create_whenTrivialNoSplitNoRedirect_returnsSimpleFetcher() throws Exception {
    // Uri without metastrings
    FreenetURI uri = new FreenetURI("CHK", null);
    FetchContext ctx = newCtx(10_000, true /* ignoreTooMany */);
    ctx.setAllowSplitfiles(false);
    ctx.setFollowRedirects(false);

    ClientKey mockKey = mock(ClientKey.class);
    try (MockedStatic<BaseClientKey> bck = Mockito.mockStatic(BaseClientKey.class)) {
      bck.when(() -> BaseClientKey.getBaseKey(eq(uri))).thenReturn(mockKey);

      ClientGetState state =
          SingleFileFetcher.create(
              parent,
              cb,
              uri,
              ctx,
              null, /* actx */
              new SingleFileFetcher.CreationPolicy(
                  0, /* maxRetries */
                  0, /* recursionLevel */
                  false, /* dontTellClientGet */
                  false, /* isEssential */
                  true, /* isFinal */
                  false /* hasInitialMetadata */),
              new SingleFileFetcher.CreationRuntime(
                  clientContext, false, /* realTime */ 1L /* token */));

      assertInstanceOf(SimpleSingleFileFetcher.class, state);
    }
  }
}
