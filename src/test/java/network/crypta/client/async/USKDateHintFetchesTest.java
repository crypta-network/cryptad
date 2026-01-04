package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.util.HashSet;
import java.util.Random;
import network.crypta.client.FetchContext;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.USK;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"java:S100", "java:S3011"})
class USKDateHintFetchesTest {

  @Test
  void hasOutstanding_whenNoAttempts_expectFalse()
      throws MalformedURLException, ReflectiveOperationException {
    FetchContext ctx = createFetchContext();
    FetchContext ctxDBR = createFetchContext();
    USKDateHintFetches fetches =
        new USKDateHintFetches(
            mock(USKFetcher.class),
            mock(USKManager.class),
            createUsk(),
            ctx,
            ctxDBR,
            mock(ClientRequester.class));

    boolean outstanding = fetches.hasOutstanding();

    assertFalse(outstanding);
    assertEquals(0, getAttempts(fetches).size());
  }

  @Test
  void maybeStart_whenIgnoreUSKDatehints_expectFalseAndNoAttempts()
      throws MalformedURLException, ReflectiveOperationException {
    FetchContext ctx = createFetchContext();
    ctx.setIgnoreUSKDatehints(true);
    FetchContext ctxDBR = createFetchContext();
    USKDateHintFetches fetches =
        new USKDateHintFetches(
            mock(USKFetcher.class),
            mock(USKManager.class),
            createUsk(),
            ctx,
            ctxDBR,
            mock(ClientRequester.class));

    boolean started = fetches.maybeStart(mock(ClientContext.class));

    assertFalse(started);
    assertFalse(fetches.hasOutstanding());
    assertEquals(0, getAttempts(fetches).size());
  }

  @Test
  void maybeStart_whenAlreadyScheduled_expectFalseAndNoAttempts()
      throws MalformedURLException, ReflectiveOperationException {
    FetchContext ctx = createFetchContext();
    FetchContext ctxDBR = createFetchContext();
    USKDateHintFetches fetches =
        new USKDateHintFetches(
            mock(USKFetcher.class),
            mock(USKManager.class),
            createUsk(),
            ctx,
            ctxDBR,
            mock(ClientRequester.class));
    setPrivateField(fetches, "scheduled", true);

    boolean started = fetches.maybeStart(mock(ClientContext.class));

    assertFalse(started);
    assertFalse(fetches.hasOutstanding());
    assertEquals(0, getAttempts(fetches).size());
  }

  @Test
  void maybeStart_whenHintsAvailable_expectAttemptsScheduledAndTracked()
      throws MalformedURLException, ReflectiveOperationException {
    FetchContext ctx = createFetchContext();
    FetchContext ctxDBR = createFetchContext();
    USKDateHintFetches fetches =
        new USKDateHintFetches(
            mock(USKFetcher.class),
            mock(USKManager.class),
            createUsk(),
            ctx,
            ctxDBR,
            mock(ClientRequester.class));
    ClientContext context = mockContextWithScheduler();
    ClientRequestScheduler scheduler = context.getSskFetchScheduler(false);

    boolean started = fetches.maybeStart(context);

    assertTrue(started);
    assertTrue(fetches.hasOutstanding());
    assertEquals(4, getAttempts(fetches).size());
    assertEquals(4, getIntField(fetches, "hintsStarted"));
    verify(scheduler, times(4)).register(any(), any(), anyBoolean(), any(), anyBoolean());
  }

  @Test
  @SuppressWarnings({"java:S2583", "ConstantValue"})
  void shouldAddRandomEditions_whenFirstLoop_expectFalse() throws MalformedURLException {
    USKDateHintFetches fetches =
        new USKDateHintFetches(
            mock(USKFetcher.class),
            mock(USKManager.class),
            createUsk(),
            createFetchContext(),
            createFetchContext(),
            mock(ClientRequester.class));

    Random random = mock(Random.class);

    boolean shouldAdd = fetches.shouldAddRandomEditions(random, true);

    assertFalse(shouldAdd);
  }

  @Test
  void shouldAddRandomEditions_whenRandomBelowFound_expectFalse()
      throws MalformedURLException, ReflectiveOperationException {
    USKDateHintFetches fetches =
        new USKDateHintFetches(
            mock(USKFetcher.class),
            mock(USKManager.class),
            createUsk(),
            createFetchContext(),
            createFetchContext(),
            mock(ClientRequester.class));
    setHints(fetches, 3, 2);

    Random random = mock(Random.class);
    when(random.nextInt(4)).thenReturn(1);

    boolean shouldAdd = fetches.shouldAddRandomEditions(random, false);

    assertFalse(shouldAdd);
  }

  @Test
  void shouldAddRandomEditions_whenRandomAtLeastFound_expectTrue()
      throws MalformedURLException, ReflectiveOperationException {
    USKDateHintFetches fetches =
        new USKDateHintFetches(
            mock(USKFetcher.class),
            mock(USKManager.class),
            createUsk(),
            createFetchContext(),
            createFetchContext(),
            mock(ClientRequester.class));
    setHints(fetches, 1, 0);

    Random random = mock(Random.class);
    when(random.nextInt(2)).thenReturn(2);

    boolean shouldAdd = fetches.shouldAddRandomEditions(random, false);

    assertTrue(shouldAdd);
  }

  @Test
  void handleHintFound_whenDayHint_expectCancelsLessPreciseAndUpdatesManager()
      throws MalformedURLException, ReflectiveOperationException {
    USKFetcher owner = mockOwnerForHintHandling();
    USKManager manager = mock(USKManager.class);
    FetchContext ctx = createFetchContext();
    FetchContext ctxDBR = createFetchContext();
    USKDateHintFetches fetches =
        new USKDateHintFetches(
            owner, manager, createUsk(), ctx, ctxDBR, mock(ClientRequester.class));
    ClientContext context = mockContextWithScheduler();
    ClientRequestScheduler scheduler = context.getSskFetchScheduler(false);

    fetches.maybeStart(context);
    Object attempt = findAttemptByType(fetches, USKDateHint.Type.DAY);
    Object yearAttempt = findAttemptByType(fetches, USKDateHint.Type.YEAR);
    assertNotNull(attempt);
    assertNotNull(yearAttempt);

    invokeHandleHintFound(yearAttempt, 41L, context);
    invokeHandleHintFound(attempt, 42L, context);

    assertEquals(2, getIntField(fetches, "hintsFound"));
    assertEquals(1, getAttempts(fetches).size());
    verify(owner, times(2)).refreshAndGetProgressPollPriority();
    ArgumentCaptor<FreenetURI> uriCaptor = ArgumentCaptor.forClass(FreenetURI.class);
    verify(manager, times(2)).hintUpdate(uriCaptor.capture(), eq(context), eq((short) 7));
    assertEquals(41L, uriCaptor.getAllValues().getFirst().getSuggestedEdition());
    assertEquals(42L, uriCaptor.getAllValues().getLast().getSuggestedEdition());
    verify(scheduler, times(3)).removePendingKeys(any(HasKeyListener.class), eq(false));
  }

  @Test
  void cancelAll_whenAttemptsPresent_expectClearsAndCancels()
      throws MalformedURLException, ReflectiveOperationException {
    USKFetcher owner = mock(USKFetcher.class);
    FetchContext ctx = createFetchContext();
    FetchContext ctxDBR = createFetchContext();
    USKDateHintFetches fetches =
        new USKDateHintFetches(
            owner, mock(USKManager.class), createUsk(), ctx, ctxDBR, mock(ClientRequester.class));
    ClientContext context = mockContextWithScheduler();
    ClientRequestScheduler scheduler = context.getSskFetchScheduler(false);

    fetches.maybeStart(context);
    assertTrue(fetches.hasOutstanding());

    fetches.cancelAll(context);

    assertFalse(fetches.hasOutstanding());
    assertEquals(0, getAttempts(fetches).size());
    verify(scheduler, times(4)).removePendingKeys(any(HasKeyListener.class), eq(false));
  }

  private static FetchContext createFetchContext() {
    return new FetchContext(
        1024,
        1024,
        1024,
        1,
        0,
        0,
        false,
        0,
        0,
        0,
        true,
        true,
        false,
        false,
        1,
        1,
        new SimpleEventProducer(),
        false,
        true,
        null,
        null,
        null);
  }

  private static USK createUsk() throws MalformedURLException {
    byte[] pubKeyHash = createDeterministicBytes(NodeSSK.PUBKEY_HASH_SIZE, 17);
    byte[] cryptoKey = createDeterministicBytes(ClientSSK.CRYPTO_KEY_LENGTH, 73);
    byte[] extra =
        new byte[] {
          (byte) NodeSSK.SSK_VERSION,
          0,
          Key.ALGO_AES_PCFB_256_SHA256,
          0,
          (byte) KeyBlock.HASH_SHA256
        };
    return new USK(pubKeyHash, cryptoKey, extra, "site", 1);
  }

  private static ClientContext mockContextWithScheduler() throws ReflectiveOperationException {
    ClientContext context = mock(ClientContext.class);
    ClientRequestScheduler scheduler = mock(ClientRequestScheduler.class);
    when(context.getSskFetchScheduler(anyBoolean())).thenReturn(scheduler);
    DatastoreChecker checker = mock(DatastoreChecker.class);
    setChecker(context, checker);
    return context;
  }

  private static USKFetcher mockOwnerForHintHandling() {
    USKFetcher owner = mock(USKFetcher.class);
    when(owner.refreshAndGetProgressPollPriority()).thenReturn((short) 7);
    when(owner.isFinished()).thenReturn(false);
    return owner;
  }

  private static HashSet<?> getAttempts(USKDateHintFetches fetches)
      throws ReflectiveOperationException {
    return getField(fetches, "attempts", HashSet.class);
  }

  private static int getIntField(USKDateHintFetches fetches, String field)
      throws ReflectiveOperationException {
    return getField(fetches, field, Integer.class);
  }

  private static void setHints(USKDateHintFetches fetches, int started, int found)
      throws ReflectiveOperationException {
    setPrivateField(fetches, "hintsStarted", started);
    setPrivateField(fetches, "hintsFound", found);
  }

  private static Object findAttemptByType(USKDateHintFetches fetches, USKDateHint.Type type)
      throws ReflectiveOperationException {
    for (Object attempt : getAttempts(fetches)) {
      USKDateHint.Type attemptType = getField(attempt, "type", USKDateHint.Type.class);
      if (attemptType == type) {
        return attempt;
      }
    }
    return null;
  }

  private static void invokeHandleHintFound(Object attempt, long hint, ClientContext context)
      throws ReflectiveOperationException {
    Method method =
        attempt.getClass().getDeclaredMethod("handleHintFound", long.class, ClientContext.class);
    method.setAccessible(true);
    method.invoke(attempt, hint, context);
  }

  private static void setChecker(ClientContext context, DatastoreChecker checker)
      throws ReflectiveOperationException {
    Field field = ClientContext.class.getDeclaredField("checker");
    field.setAccessible(true);
    field.set(context, checker);
  }

  private static void setPrivateField(Object target, String fieldName, Object value)
      throws ReflectiveOperationException {
    Field field = findField(target.getClass(), fieldName);
    field.setAccessible(true);
    field.set(target, value);
  }

  private static <T> T getField(Object target, String fieldName, Class<T> type)
      throws ReflectiveOperationException {
    Field field = findField(target.getClass(), fieldName);
    field.setAccessible(true);
    return type.cast(field.get(target));
  }

  private static Field findField(Class<?> type, String fieldName)
      throws ReflectiveOperationException {
    Class<?> current = type;
    while (current != null) {
      try {
        return current.getDeclaredField(fieldName);
      } catch (NoSuchFieldException _) {
        current = current.getSuperclass();
      }
    }
    throw new NoSuchFieldException(fieldName);
  }

  private static byte[] createDeterministicBytes(int length, int seed) {
    byte[] data = new byte[length];
    for (int i = 0; i < data.length; i++) {
      data[i] = (byte) (seed + i * 31);
    }
    return data;
  }
}
