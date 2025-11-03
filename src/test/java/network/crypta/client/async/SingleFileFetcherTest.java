package network.crypta.client.async;

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

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
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
        maxOut, /* maxOutputLength */
        Long.MAX_VALUE, /* maxTempLength */
        1024 * 1024, /* maxMetadataSize */
        8, /* maxRecursionLevel */
        4, /* maxArchiveRestarts */
        8, /* maxArchiveLevels */
        false, /* dontEnterImplicitArchives */
        0, /* maxSplitfileBlockRetries */
        0, /* maxNonSplitfileRetries */
        0, /* maxUSKRetries */
        true, /* allowSplitfiles */
        true, /* followRedirects */
        false, /* localRequestOnly */
        false, /* filterData */
        0, /* maxDataBlocksPerSegment */
        0, /* maxCheckBlocksPerSegment */
        null, /* bucketFactory (unused here) */
        new SimpleEventProducer(),
        ignoreTooMany, /* ignoreTooManyPathComponents */
        true, /* canWriteClientCache */
        null, /* charset */
        null, /* overrideMIME */
        null /* schemeHostAndPort */);
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

    return new SingleFileFetcher(
        parent,
        cb,
        null, /* clientMetadata */
        key,
        new ArrayList<>(metaStrings),
        uri,
        addedMetaStrings,
        ctx,
        false, /* deleteFetchContext */
        false, /* realTimeFlag */
        null, /* actx */
        null, /* ah */
        null, /* archiveMetadata */
        0, /* maxRetries */
        0, /* recursionLevel */
        false, /* dontTellClientGet */
        token,
        false, /* isEssential */
        isFinal,
        false, /* topDontCompress */
        (short) 0, /* topCompatibilityMode */
        clientContext,
        false /* hasInitialMetadata */);
  }

  @Test
  void onSuccess_whenTooManyPathComponentsAndFinal_reportsTooManyPathComponents() throws Exception {
    FetchContext ctx = newCtx(1024, false /* ignoreTooMany */);
    SingleFileFetcher f = newFetcher(List.of("extra"), 0, true, ctx, 123L);

    Bucket original = mock(Bucket.class);
    ClientMetadata md = new ClientMetadata("text/plain");

    FetchResult result = new FetchResult(md, original);
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

    f.onSuccess(new FetchResult(md, original), clientContext);

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

    FetchResult result = new FetchResult(md, original);
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
    try (MockedStatic<BucketTools> ignored = Mockito.mockStatic(BucketTools.class)) {
      ClientMetadata md = new ClientMetadata("text/plain");
      FetchResult result = new FetchResult(md, original);

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
      FetchResult result = new FetchResult(md, original);

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

    try (MockedStatic<BucketTools> ignored = Mockito.mockStatic(BucketTools.class)) {
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
      f.onSuccess(new FetchResult(md, original), clientContext);

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
    ctx.allowSplitfiles = false;
    ctx.followRedirects = false;

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
