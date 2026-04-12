package network.crypta.clients.http;

import java.lang.reflect.Field;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.HighLevelSimpleClientImpl;
import network.crypta.client.async.ClientContext;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FProxyFetchInProgressTest {

  @Test
  void fetchContextEquivalent_returnsTrueForIdenticalCopy() {
    FetchContext context = newFetchContext();
    FProxyFetchInProgress progress = newProgress(context);

    FetchContext identicalCopy = new FetchContext(context, FetchContext.IDENTICAL_MASK);

    assertTrue(progress.fetchContextEquivalent(identicalCopy));
  }

  @Test
  void fetchContextEquivalent_whenOverrideMimeDiff_returnsFalse() {
    FetchContext context = newFetchContext();
    FProxyFetchInProgress progress = newProgress(context);

    FetchContext different = new FetchContext(context, FetchContext.IDENTICAL_MASK);
    different.setOverrideMIME("text/plain");

    assertFalse(progress.fetchContextEquivalent(different));
  }

  @Test
  void canCancel_whenRecentlyTouchedWithoutImmediateCancel_returnsFalse() throws Exception {
    FProxyFetchInProgress progress = newProgress(newFetchContext());
    long now = System.currentTimeMillis();
    setField(progress, "lastTouched", now);

    assertFalse(progress.canCancel());
  }

  @Test
  void canCancel_whenImmediateCancelRequested_allowsCancellationDuringLifetime() throws Exception {
    FProxyFetchInProgress progress = newProgress(newFetchContext());
    setField(progress, "lastTouched", System.currentTimeMillis());

    progress.requestImmediateCancel();

    assertTrue(progress.canCancel());
  }

  @Test
  void getETA_whenInsufficientProgress_returnsMinusOne() throws Exception {
    FProxyFetchInProgress progress = newProgress(newFetchContext());
    setField(progress, "goneToNetwork", true);
    setField(progress, "requiredBlocks", 10);
    setField(progress, "fetchedBlocks", 3);
    setField(progress, "fetchedBlocksPreNetwork", 1);

    assertEquals(-1, progress.getETA());
  }

  @Test
  void getETA_whenProgressMade_returnsPositiveEstimate() throws Exception {
    FProxyFetchInProgress progress = newProgress(newFetchContext());
    setField(progress, "goneToNetwork", true);
    setField(progress, "requiredBlocks", 10);
    setField(progress, "fetchedBlocks", 7);
    setField(progress, "fetchedBlocksPreNetwork", 1);
    setField(progress, "timeStarted", System.currentTimeMillis() - 1000);

    long eta = progress.getETA();

    assertTrue(eta > 0);
  }

  @Test
  void notFinishedOrFatallyFinished_whenDataPresent_returnsFalse() {
    FProxyFetchInProgress progress = newProgress(newFetchContext());
    Bucket bucket = new ArrayBucket();
    FetchResult result = FetchResult.create(new ClientMetadata("text/plain"), bucket);

    progress.onSuccess(result, null);

    assertFalse(progress.notFinishedOrFatallyFinished());
    assertTrue(progress.hasData());
  }

  @Test
  void notFinishedOrFatallyFinished_whenFatalFailure_returnsTrue() {
    FProxyFetchInProgress progress = newProgress(newFetchContext());

    progress.onFailure(new FetchException(FetchExceptionMode.TOO_BIG));

    assertTrue(progress.notFinishedOrFatallyFinished());
  }

  @Test
  void notFinishedOrFatallyFinished_whenNonFatalFailureEventuallyReturnsFalse() throws Exception {
    FProxyFetchInProgress progress = newProgress(newFetchContext());

    progress.onFailure(new FetchException(FetchExceptionMode.DATA_NOT_FOUND));
    assertTrue(progress.notFinishedOrFatallyFinished());

    setField(progress, "timeFailed", System.currentTimeMillis() - 1500);
    setField(progress, "fetched", 2);

    assertFalse(progress.notFinishedOrFatallyFinished());
  }

  private static FProxyFetchInProgress newProgress(FetchContext context) {
    ClientContext clientContext = Mockito.mock(ClientContext.class);
    FProxyFetchTracker tracker = Mockito.mock(FProxyFetchTracker.class);
    RequestClient requestClient = Mockito.mock(RequestClient.class);
    FreenetURI uri = new FreenetURI("KSK", "doc");

    FProxyFetchCriteria criteria = new FProxyFetchCriteria(uri, 1024L, context);
    return new FProxyFetchInProgress(
        tracker, criteria, 1L, clientContext, requestClient, RefilterPolicy.ACCEPT_OLD);
  }

  private static FetchContext newFetchContext() {
    return HighLevelSimpleClientImpl.makeDefaultFetchContext(
        2048L, 4096L, new SimpleEventProducer());
  }

  private static void setField(Object target, String name, Object value) throws Exception {
    Field field = target.getClass().getDeclaredField(name);
    field.setAccessible(true);
    field.set(target, value);
  }
}
