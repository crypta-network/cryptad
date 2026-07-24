package network.crypta.runtime.updater;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchContextOptions;
import network.crypta.client.FetchResult;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.USKFoundEdition;
import network.crypta.client.async.USKFoundEditionPayload;
import network.crypta.client.async.USKFoundEditionProgress;
import network.crypta.client.async.USKManager;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyShort;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class CoreSupportLifecycleUpdaterTest {
  @Mock NodeUpdateManager manager;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  Node node;

  @Mock NodeClientCore core;
  @Mock HighLevelSimpleClient client;
  @Mock CoreSupportLifecycleState lifecycleState;

  private CoreSupportLifecycleUpdater updater;

  @BeforeEach
  void setUp() throws Exception {
    when(manager.getNode()).thenReturn(node);
    when(node.services().clientCore()).thenReturn(core);
    when(core.makeClient(anyShort(), anyBoolean(), anyBoolean())).thenReturn(client);
    when(client.getFetchContext()).thenReturn(fetchContext());
    updater =
        new CoreSupportLifecycleUpdater(
            new NodeUpdaterParams(
                manager,
                new FreenetURI("USK@" + NodeUpdateManager.UPDATE_URI + "/support-lifecycle/0"),
                0,
                -1,
                Integer.MAX_VALUE,
                "support-lifecycle-",
                0),
            lifecycleState);
  }

  @Test
  void processSuccess_whenPersistenceKeepsFailing_expectSaturatingExponentialBackoff()
      throws Exception {
    FetchResult result = fetchedDescriptor();
    doThrow(new IOException("read-only store"))
        .when(lifecycleState)
        .accept(any(byte[].class), anyLong());
    long[] expectedDelays = {
      60_000L, 120_000L, 240_000L, 480_000L, 960_000L, 1_920_000L, 3_600_000L
    };

    for (long expectedDelay : expectedDelays) {
      assertFalse(updater.processSuccess(1, result, null));
      assertEquals(expectedDelay, updater.rejectedFetchRetryDelayMillis());
    }
    assertFalse(updater.processSuccess(1, result, null));

    assertEquals(3_600_000L, updater.rejectedFetchRetryDelayMillis());
  }

  @Test
  void processSuccess_whenDifferentEditionFailsPersistence_expectBackoffRestarts()
      throws Exception {
    FetchResult result = fetchedDescriptor();
    doThrow(new IOException("temporarily unavailable"))
        .when(lifecycleState)
        .accept(any(byte[].class), anyLong());
    updater.processSuccess(1, result, null);
    updater.processSuccess(1, result, null);

    assertFalse(updater.processSuccess(2, result, null));

    assertEquals(60_000L, updater.rejectedFetchRetryDelayMillis());
  }

  @Test
  void processSuccess_whenDescriptorIsAccepted_expectPackageTargetReconciled() throws Exception {
    FetchResult result = fetchedDescriptor();

    boolean accepted = updater.processSuccess(1, result, null);

    assertTrue(accepted);
    verify(manager).onSupportLifecycleAccepted();
  }

  @Test
  void managerState_whenOnlyPackageUpdaterIsBlown_expectLifecycleFetchRemainsAllowed() {
    when(manager.isUpdateKeyCompromised()).thenReturn(false);

    boolean blocked = updater.isFetchingBlockedByManagerState();

    assertFalse(blocked);
    verify(manager, never()).isBlown();
  }

  @Test
  void managerState_whenUpdateKeyIsCompromised_expectLifecycleFetchIsBlocked() {
    when(manager.isUpdateKeyCompromised()).thenReturn(true);

    boolean blocked = updater.isFetchingBlockedByManagerState();

    assertTrue(blocked);
  }

  @Test
  void constructor_whenLastKnownGoodEditionExists_expectAcceptedEditionIsNotFetchedAgain()
      throws Exception {
    when(lifecycleState.acceptedEditionSeed()).thenReturn(7);
    updater =
        new CoreSupportLifecycleUpdater(
            new NodeUpdaterParams(
                manager,
                new FreenetURI("USK@" + NodeUpdateManager.UPDATE_URI + "/support-lifecycle/7"),
                -1,
                -1,
                Integer.MAX_VALUE,
                "support-lifecycle-",
                7),
            lifecycleState);
    USK announcedKey =
        USK.create(new FreenetURI("USK@" + NodeUpdateManager.UPDATE_URI + "/support-lifecycle/7"));
    USKFoundEdition announcement =
        new USKFoundEdition(
            new USKFoundEditionPayload(7L, announcedKey, false, (short) 0, null),
            null,
            new USKFoundEditionProgress(false, true));

    updater.onFoundEdition(announcement);
    updater.maybeUpdate();

    assertEquals(7, updater.getFetchedVersion());
    verify(core, never()).getPersistentTempDir();
    verify(lifecycleState, never()).accept(any(byte[].class), anyLong());
  }

  @Test
  void onChangeURI_whenLastKnownGoodEditionExists_expectAcceptedEditionIsNotFetchedAgain()
      throws Exception {
    when(lifecycleState.acceptedEditionSeed()).thenReturn(7);
    updater =
        new CoreSupportLifecycleUpdater(
            new NodeUpdaterParams(
                manager,
                new FreenetURI("USK@" + NodeUpdateManager.UPDATE_URI + "/support-lifecycle/7"),
                -1,
                -1,
                Integer.MAX_VALUE,
                "support-lifecycle-",
                7),
            lifecycleState);
    when(core.getUskManager()).thenReturn(mock(USKManager.class));
    FreenetURI replacementUri =
        new FreenetURI("USK@" + NodeUpdateManager.UPDATE_URI + "/support-lifecycle/0");

    updater.onChangeURI(replacementUri, 7);
    USK announcedKey = USK.create(replacementUri.setSuggestedEdition(7));
    updater.onFoundEdition(
        new USKFoundEdition(
            new USKFoundEditionPayload(7L, announcedKey, false, (short) 0, null),
            null,
            new USKFoundEditionProgress(false, true)));
    updater.maybeUpdate();

    assertEquals(7, updater.getFetchedVersion());
    verify(core, never()).getPersistentTempDir();
    verify(lifecycleState, never()).accept(any(byte[].class), anyLong());
  }

  private static FetchResult fetchedDescriptor() throws IOException {
    byte[] bytes = "{}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    FetchResult result = mock(FetchResult.class);
    Bucket bucket = mock(Bucket.class);
    when(result.size()).thenReturn((long) bytes.length);
    when(result.asBucket()).thenReturn(bucket);
    when(bucket.getInputStream()).thenAnswer(_ -> new ByteArrayInputStream(bytes));
    return result;
  }

  private static FetchContext fetchContext() {
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
}
