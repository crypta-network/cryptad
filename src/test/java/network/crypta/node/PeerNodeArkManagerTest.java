package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyShort;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchResult;
import network.crypta.client.async.USKManager;
import network.crypta.client.async.USKRetriever;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.Key;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.USK;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings({"java:S100", "java:S3011"})
@ExtendWith(MockitoExtension.class)
class PeerNodeArkManagerTest {

  private static final String FIELD_MY_ARK = "myARK";

  @Mock PeerNode peer;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  Node node;

  @Mock NodeNetworkSubsystem network;
  @Mock NodeClientCore clientCore;
  @Mock USKManager uskManager;
  @Mock PriorityAwareExecutor executor;
  @Mock FetchContext fetchContext;
  @Mock RequestClient requestClient;
  @Mock USKRetriever arkRetriever;

  private PeerNodeArkManager manager;

  @BeforeEach
  void setUp() {
    manager = new PeerNodeArkManager(peer);
    setField(peer, "node", node);
    when(node.network()).thenReturn(network);
  }

  @Test
  void parseArk_whenComputeArkReturnsNull_expectFalse() {
    SimpleFieldSet fs = new SimpleFieldSet(true);

    try (MockedStatic<PeerNodeReferenceSupport> mocked =
        Mockito.mockStatic(PeerNodeReferenceSupport.class)) {
      mocked
          .when(
              () ->
                  PeerNodeReferenceSupport.computeArk(
                      any(), any(), anyBoolean(), anyBoolean(), any()))
          .thenReturn(null);

      boolean changed = manager.parseArk(fs, false, false);

      assertFalse(changed);
      assertNull(getMyArk(manager));
    }
  }

  @Test
  void parseArk_whenArkSetFirstTime_expectTrueAndAppendUsesEditionMinusOne() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    USK ark = newUsk(10);

    try (MockedStatic<PeerNodeReferenceSupport> mocked =
        Mockito.mockStatic(PeerNodeReferenceSupport.class)) {
      mocked
          .when(
              () ->
                  PeerNodeReferenceSupport.computeArk(
                      any(), any(), anyBoolean(), anyBoolean(), any()))
          .thenReturn(ark);

      boolean changed = manager.parseArk(fs, false, false);

      assertTrue(changed);
      SimpleFieldSet out = new SimpleFieldSet(true);
      manager.appendArkFields(out);
      assertEquals(9L, out.getLong(PeerNode.SFS_KEY_ARK_NUMBER, -1));
      assertEquals(ark.getBaseSSK().toString(false, false), out.get(PeerNode.SFS_KEY_ARK_PUBURI));
    }
  }

  @Test
  void parseArk_whenArkChanges_expectTrueAndUpdatesStoredArk() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    USK ark = newUsk(3);
    USK updated = newUsk(7);

    try (MockedStatic<PeerNodeReferenceSupport> mocked =
        Mockito.mockStatic(PeerNodeReferenceSupport.class)) {
      mocked
          .when(
              () ->
                  PeerNodeReferenceSupport.computeArk(
                      any(), any(), anyBoolean(), anyBoolean(), any()))
          .thenReturn(ark, updated);

      boolean first = manager.parseArk(fs, false, false);
      boolean second = manager.parseArk(fs, false, false);

      assertTrue(first);
      assertTrue(second);
      SimpleFieldSet out = new SimpleFieldSet(true);
      manager.appendArkFields(out);
      assertEquals(6L, out.getLong(PeerNode.SFS_KEY_ARK_NUMBER, -1));
    }
  }

  @Test
  void parseArk_whenArkEqual_expectFalseAndKeepsExisting() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    USK ark = newUsk("same-site", 5);
    USK equalArk = newUsk("same-site", 5);

    try (MockedStatic<PeerNodeReferenceSupport> mocked =
        Mockito.mockStatic(PeerNodeReferenceSupport.class)) {
      mocked
          .when(
              () ->
                  PeerNodeReferenceSupport.computeArk(
                      any(), any(), anyBoolean(), anyBoolean(), any()))
          .thenReturn(ark, equalArk);

      assertTrue(manager.parseArk(fs, false, false));
      boolean changed = manager.parseArk(fs, false, false);

      assertFalse(changed);
      assertSame(ark, getMyArk(manager));
    }
  }

  @Test
  void appendArkFields_whenMyArkMissing_expectNoFieldsAdded() {
    SimpleFieldSet fs = new SimpleFieldSet(true);

    manager.appendArkFields(fs);

    assertNull(fs.get(PeerNode.SFS_KEY_ARK_NUMBER));
    assertNull(fs.get(PeerNode.SFS_KEY_ARK_PUBURI));
  }

  @ParameterizedTest
  @CsvSource({"1,0", "10,9", "100,99"})
  void appendArkFields_whenArkPresent_expectDecrementedEdition(
      long suggestedEdition, long expectedNumber) {
    USK ark = newUsk(suggestedEdition);
    setField(manager, FIELD_MY_ARK, ark);
    SimpleFieldSet fs = new SimpleFieldSet(true);

    manager.appendArkFields(fs);

    assertEquals(expectedNumber, fs.getLong(PeerNode.SFS_KEY_ARK_NUMBER, -1));
    assertEquals(ark.getBaseSSK().toString(false, false), fs.get(PeerNode.SFS_KEY_ARK_PUBURI));
  }

  @Test
  void startFetcher_whenArksDisabled_expectNoSubscription() {
    when(node.isEnableARKs()).thenReturn(false);
    setField(manager, FIELD_MY_ARK, newUsk(1));

    manager.startFetcher();

    verify(uskManager, never())
        .subscribeContent(any(), any(), anyBoolean(), any(), anyShort(), any());
    assertFalse(manager.isFetching());
  }

  @Test
  void startFetcher_whenNoArk_expectNoSubscription() {
    when(node.isEnableARKs()).thenReturn(true);
    manager.startFetcher();

    verify(uskManager, never())
        .subscribeContent(any(), any(), anyBoolean(), any(), anyShort(), any());
    assertFalse(manager.isFetching());
  }

  @Test
  void startFetcher_whenFetcherNotRunning_expectSubscriptionAndIsFetching() {
    when(node.isEnableARKs()).thenReturn(true);
    stubArkSubscriptionDependencies();
    USK ark = newUsk(2);
    setField(manager, FIELD_MY_ARK, ark);
    when(uskManager.subscribeContent(
            ark,
            manager,
            true,
            fetchContext,
            RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
            requestClient))
        .thenReturn(arkRetriever);

    manager.startFetcher();

    verify(uskManager)
        .subscribeContent(
            ark,
            manager,
            true,
            fetchContext,
            RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
            requestClient);
    assertTrue(manager.isFetching());
  }

  @Test
  void startFetcher_whenAlreadyRunning_expectNoAdditionalSubscription() {
    when(node.isEnableARKs()).thenReturn(true);
    stubArkSubscriptionDependencies();
    USK ark = newUsk(2);
    setField(manager, FIELD_MY_ARK, ark);
    when(uskManager.subscribeContent(
            ark,
            manager,
            true,
            fetchContext,
            RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
            requestClient))
        .thenReturn(arkRetriever);

    manager.startFetcher();
    manager.startFetcher();

    verify(uskManager)
        .subscribeContent(
            ark,
            manager,
            true,
            fetchContext,
            RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
            requestClient);
    assertTrue(manager.isFetching());
  }

  @Test
  void startFetcher_whenArkChangesWhileRunning_expectResubscribeAndUnsubscribePrevious() {
    when(node.isEnableARKs()).thenReturn(true);
    stubArkSubscriptionDependencies();
    stubExecutor();
    USK firstArk = newUsk(2);
    USK secondArk = newUsk(3);
    USKRetriever secondRetriever = mock(USKRetriever.class);
    setField(manager, FIELD_MY_ARK, firstArk);
    when(uskManager.subscribeContent(
            firstArk,
            manager,
            true,
            fetchContext,
            RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
            requestClient))
        .thenReturn(arkRetriever);
    when(uskManager.subscribeContent(
            secondArk,
            manager,
            true,
            fetchContext,
            RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
            requestClient))
        .thenReturn(secondRetriever);

    manager.startFetcher();
    setField(manager, FIELD_MY_ARK, secondArk);
    manager.startFetcher();

    verify(uskManager)
        .subscribeContent(
            firstArk,
            manager,
            true,
            fetchContext,
            RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
            requestClient);
    verify(uskManager)
        .subscribeContent(
            secondArk,
            manager,
            true,
            fetchContext,
            RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
            requestClient);

    ArgumentCaptor<Runnable> taskCaptor = ArgumentCaptor.forClass(Runnable.class);
    verify(executor).execute(taskCaptor.capture());
    taskCaptor.getValue().run();
    verify(uskManager).unsubscribeContent(firstArk, arkRetriever, true);
    assertTrue(manager.isFetching());
  }

  @Test
  void stopFetcher_whenArksDisabled_expectNoUnsubscribe() {
    stubArkSubscriptionDependencies();
    USK ark = newUsk(3);
    setField(manager, FIELD_MY_ARK, ark);
    when(node.isEnableARKs()).thenReturn(true, false);
    when(uskManager.subscribeContent(
            ark,
            manager,
            true,
            fetchContext,
            RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
            requestClient))
        .thenReturn(arkRetriever);

    manager.startFetcher();
    manager.stopFetcher();

    verify(executor, never()).execute(any(Runnable.class));
    verify(uskManager, never()).unsubscribeContent(any(), any(), anyBoolean());
    assertTrue(manager.isFetching());
  }

  @Test
  void stopFetcher_whenNotRunning_expectNoUnsubscribe() {
    when(node.isEnableARKs()).thenReturn(true);
    manager.stopFetcher();

    verify(executor, never()).execute(any(Runnable.class));
    verify(uskManager, never()).unsubscribeContent(any(), any(), anyBoolean());
    assertFalse(manager.isFetching());
  }

  @Test
  void stopFetcher_whenRunning_expectUnsubscribeViaExecutorAndClearsFetcher() {
    when(node.isEnableARKs()).thenReturn(true);
    stubArkSubscriptionDependencies();
    stubExecutor();
    USK ark = newUsk(4);
    setField(manager, FIELD_MY_ARK, ark);
    when(uskManager.subscribeContent(
            ark,
            manager,
            true,
            fetchContext,
            RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
            requestClient))
        .thenReturn(arkRetriever);

    manager.startFetcher();
    manager.stopFetcher();

    assertFalse(manager.isFetching());
    ArgumentCaptor<Runnable> taskCaptor = ArgumentCaptor.forClass(Runnable.class);
    verify(executor).execute(taskCaptor.capture());
    taskCaptor.getValue().run();
    verify(uskManager).unsubscribeContent(ark, arkRetriever, true);
  }

  @Test
  void handleArkUpdate_whenNewerEdition_expectUpdatesEditionAndProcessesNoderef() throws Exception {
    USK ark = newUsk(2);
    setField(manager, FIELD_MY_ARK, ark);
    SimpleFieldSet fs = new SimpleFieldSet(true);

    manager.handleArkUpdate(fs, 5L);

    verify(peer).resetHandshakeCountAfterArkFetch();
    verify(peer).processNewNoderef(fs, true, false, false);
    SimpleFieldSet out = new SimpleFieldSet(true);
    manager.appendArkFields(out);
    assertEquals(5L, out.getLong(PeerNode.SFS_KEY_ARK_NUMBER, -1));
  }

  @Test
  void handleArkUpdate_whenEditionNotNewer_expectKeepsExistingEdition() throws Exception {
    USK ark = newUsk(10);
    setField(manager, FIELD_MY_ARK, ark);
    SimpleFieldSet fs = new SimpleFieldSet(true);

    manager.handleArkUpdate(fs, 5L);

    verify(peer).resetHandshakeCountAfterArkFetch();
    verify(peer).processNewNoderef(fs, true, false, false);
    SimpleFieldSet out = new SimpleFieldSet(true);
    manager.appendArkFields(out);
    assertEquals(9L, out.getLong(PeerNode.SFS_KEY_ARK_NUMBER, -1));
  }

  @Test
  void handleArkUpdate_whenProcessThrows_expectMarksHandshakeFailure() throws Exception {
    USK ark = newUsk(1);
    setField(manager, FIELD_MY_ARK, ark);
    SimpleFieldSet fs = new SimpleFieldSet(true);
    doThrow(new FSParseException("bad")).when(peer).processNewNoderef(fs, true, false, false);

    manager.handleArkUpdate(fs, 2L);

    verify(peer).resetHandshakeCountAfterArkFetch();
    verify(peer).markHandshakeCountAfterArkFailure();
  }

  @Test
  void getPollingPriorityNormal_whenCalled_expectImmediatePriority() {
    assertEquals(
        RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS, manager.getPollingPriorityNormal());
  }

  @Test
  void getPollingPriorityProgress_whenCalled_expectImmediatePriority() {
    assertEquals(
        RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS, manager.getPollingPriorityProgress());
  }

  @Test
  void onFound_whenArkMissing_expectNoHandleAndNoRead() throws Exception {
    PeerNodeArkManager spy = spy(manager);
    FetchResult result = mockFetchResult();

    spy.onFound(newUsk(1), 1L, result);

    verify(spy, never()).handleArkUpdate(any(SimpleFieldSet.class), anyLong());
    verify(result, never()).asByteArray();
    verify(result.asBucket()).close();
  }

  @Test
  void onFound_whenPeerConnected_expectNoHandleAndNoRead() throws Exception {
    PeerNodeArkManager spy = spy(manager);
    setField(spy, FIELD_MY_ARK, newUsk(1));
    when(peer.isConnected()).thenReturn(true);
    FetchResult result = mockFetchResult();

    spy.onFound(newUsk(1), 1L, result);

    verify(spy, never()).handleArkUpdate(any(SimpleFieldSet.class), anyLong());
    verify(result, never()).asByteArray();
    verify(result.asBucket()).close();
  }

  @Test
  void onFound_whenEditionOlderThanSuggested_expectNoHandleAndNoRead() throws Exception {
    PeerNodeArkManager spy = spy(manager);
    setField(spy, FIELD_MY_ARK, newUsk(10));
    FetchResult result = mockFetchResult();

    spy.onFound(newUsk(10), 5L, result);

    verify(spy, never()).handleArkUpdate(any(SimpleFieldSet.class), anyLong());
    verify(result, never()).asByteArray();
    verify(result.asBucket()).close();
  }

  @Test
  void onFound_whenAsByteArrayThrows_expectNoHandle() throws Exception {
    PeerNodeArkManager spy = spy(manager);
    setField(spy, FIELD_MY_ARK, newUsk(1));
    FetchResult result = mockFetchResult();
    when(result.asByteArray()).thenThrow(new IOException("boom"));

    spy.onFound(newUsk(1), 1L, result);

    verify(spy, never()).handleArkUpdate(any(SimpleFieldSet.class), anyLong());
    verify(result.asBucket()).close();
  }

  @Test
  void onFound_whenInvalidRef_expectNoHandle() {
    PeerNodeArkManager spy = spy(manager);
    setField(spy, FIELD_MY_ARK, newUsk(1));
    FetchResult result = fetchResultForRef("");

    spy.onFound(newUsk(1), 1L, result);

    verify(spy, never()).handleArkUpdate(any(SimpleFieldSet.class), anyLong());
  }

  @Test
  void onFound_whenValidRef_expectHandleArkUpdateCalled() {
    PeerNodeArkManager spy = spy(manager);
    setField(spy, FIELD_MY_ARK, newUsk(5));
    doNothing().when(spy).handleArkUpdate(any(SimpleFieldSet.class), anyLong());
    FetchResult result = fetchResultForRef("foo=bar\nEnd\n");

    spy.onFound(newUsk(5), 5L, result);

    ArgumentCaptor<SimpleFieldSet> fsCaptor = ArgumentCaptor.forClass(SimpleFieldSet.class);
    ArgumentCaptor<Long> editionCaptor = ArgumentCaptor.forClass(Long.class);
    verify(spy).handleArkUpdate(fsCaptor.capture(), editionCaptor.capture());
    assertEquals("bar", fsCaptor.getValue().get("foo"));
    assertEquals(5L, editionCaptor.getValue());
  }

  private static FetchResult mockFetchResult() {
    FetchResult result = mock(FetchResult.class);
    Bucket bucket = mock(Bucket.class);
    when(result.asBucket()).thenReturn(bucket);
    return result;
  }

  private static FetchResult fetchResultForRef(String ref) {
    byte[] data = ref.getBytes(StandardCharsets.UTF_8);
    return FetchResult.create(new ClientMetadata("text/plain"), new ArrayBucket(data));
  }

  private void stubArkSubscriptionDependencies() {
    when(node.services().clientCore()).thenReturn(clientCore);
    when(clientCore.getUskManager()).thenReturn(uskManager);
    when(node.network().arkFetcherContext()).thenReturn(fetchContext);
    when(node.getNonPersistentClientRT()).thenReturn(requestClient);
  }

  private void stubExecutor() {
    when(node.network().executor()).thenReturn(executor);
  }

  private static USK newUsk(long edition) {
    return newUsk("test-site", edition);
  }

  private static USK newUsk(String siteName, long edition) {
    byte[] pubKeyHash = new byte[NodeSSK.PUBKEY_HASH_SIZE];
    byte[] cryptoKey = new byte[ClientSSK.CRYPTO_KEY_LENGTH];
    return new TestUSK(pubKeyHash, cryptoKey, siteName, edition);
  }

  private static final class TestUSK extends USK {
    private TestUSK(byte[] pubKeyHash, byte[] cryptoKey, String siteName, long edition) {
      super(pubKeyHash, cryptoKey, siteName, edition, Key.ALGO_AES_PCFB_256_SHA256);
    }
  }

  private static void setField(Object target, String fieldName, Object value) {
    try {
      Field field = findField(target.getClass(), fieldName);
      field.setAccessible(true);
      if (AtomicReference.class.isAssignableFrom(field.getType())) {
        @SuppressWarnings("unchecked")
        AtomicReference<Object> ref = (AtomicReference<Object>) field.get(target);
        ref.set(value);
        return;
      }
      field.set(target, value);
    } catch (IllegalAccessException e) {
      throw new AssertionError("Unable to set field " + fieldName, e);
    }
  }

  private static USK getMyArk(Object target) {
    try {
      Field field = findField(target.getClass(), FIELD_MY_ARK);
      field.setAccessible(true);
      Object value = field.get(target);
      if (value instanceof AtomicReference<?> ref) {
        return (USK) ref.get();
      }
      return (USK) value;
    } catch (IllegalAccessException e) {
      throw new AssertionError("Unable to read field " + FIELD_MY_ARK, e);
    }
  }

  private static Field findField(Class<?> type, String fieldName) {
    Class<?> current = type;
    while (current != null) {
      try {
        return current.getDeclaredField(fieldName);
      } catch (NoSuchFieldException _) {
        current = current.getSuperclass();
      }
    }
    throw new AssertionError("Field not found: " + fieldName);
  }
}
