package network.crypta.node.updater;

import java.io.File;
import java.net.MalformedURLException;
import java.nio.file.Path;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchContextOptions;
import network.crypta.client.FetchResult;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.USKManager;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.support.Ticker;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyShort;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class NodeUpdaterTest {

  private static final int CURRENT_VERSION = 1200;
  private static final int DEFAULT_SUBSCRIBE_SEED = 1325;
  private static final String BLOB_PREFIX = "core-info-";

  @TempDir Path tempDir;

  @Mock NodeUpdateManager manager;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  Node node;

  @Mock NodeClientCore core;
  @Mock USKManager uskManager;
  @Mock HighLevelSimpleClient highLevelSimpleClient;
  @Mock Ticker ticker;

  private TestNodeUpdater updater;

  @BeforeEach
  void setUp() throws Exception {
    when(manager.getNode()).thenReturn(node);

    when(node.services().clientCore()).thenReturn(core);
    when(node.network().ticker()).thenReturn(ticker);

    when(core.makeClient(anyShort(), anyBoolean(), anyBoolean())).thenReturn(highLevelSimpleClient);
    when(highLevelSimpleClient.getFetchContext()).thenReturn(createFetchContext());

    updater = new TestNodeUpdater(defaultParams());
  }

  @Test
  void start_whenSubscribeSeedProvided_expectSubscribeFromSeedEdition() {
    // Arrange
    when(core.getUskManager()).thenReturn(uskManager);

    // Act
    updater.start();

    // Assert
    ArgumentCaptor<USK> capturedUsk = ArgumentCaptor.forClass(USK.class);
    verify(uskManager).subscribe(capturedUsk.capture(), same(updater), eq(true), same(updater));
    assertEquals(1325L, capturedUsk.getValue().suggestedEdition);
  }

  @Test
  void onChangeURI_whenSeedProvided_expectUpdaterUriAndSubscribeUseSeed() throws Exception {
    // Arrange
    when(core.getUskManager()).thenReturn(uskManager);
    FreenetURI newUri = new FreenetURI("USK@" + NodeUpdateManager.UPDATE_URI + "/info/600");

    // Act
    updater.onChangeURI(newUri, 1450);

    // Assert
    assertEquals(1450L, updater.getUpdateKey().getSuggestedEdition());
    ArgumentCaptor<USK> capturedUsk = ArgumentCaptor.forClass(USK.class);
    verify(uskManager).subscribe(capturedUsk.capture(), same(updater), eq(true), same(updater));
    assertEquals(1450L, capturedUsk.getValue().suggestedEdition);
  }

  @Test
  void onSuccess_whenFetchedUriProvided_expectRecordSuccessfulFetchWithProvidedUri()
      throws Exception {
    // Arrange
    when(core.getPersistentTempDir()).thenReturn(tempDir.toFile());
    FetchResult result = mock(FetchResult.class);
    when(result.size()).thenReturn(1L);
    File tempBlobFile = File.createTempFile(BLOB_PREFIX, ".tmp", tempDir.toFile());
    FreenetURI fetchedUri = new FreenetURI("USK@" + NodeUpdateManager.UPDATE_URI + "/info/1433");

    // Act
    updater.onSuccess(result, tempBlobFile, 1433, fetchedUri);

    // Assert
    verify(manager).recordSuccessfulCoreInfoFetch(fetchedUri, 1433);
    assertTrue(updater.getBlobFile(1433).exists());
  }

  @Test
  void onSuccess_whenFetchedUriIsNull_expectRecordSuccessfulFetchWithCurrentUpdateKey()
      throws Exception {
    // Arrange
    when(core.getPersistentTempDir()).thenReturn(tempDir.toFile());
    FetchResult result = mock(FetchResult.class);
    when(result.size()).thenReturn(1L);
    File tempBlobFile = File.createTempFile(BLOB_PREFIX, ".tmp", tempDir.toFile());

    // Act
    updater.onSuccess(result, tempBlobFile, 1434, null);

    // Assert
    ArgumentCaptor<FreenetURI> recordedUri = ArgumentCaptor.forClass(FreenetURI.class);
    verify(manager).recordSuccessfulCoreInfoFetch(recordedUri.capture(), eq(1434));
    assertEquals(
        updater.getUpdateKey().toString(false, false),
        recordedUri.getValue().toString(false, false));
    assertTrue(updater.getBlobFile(1434).exists());
  }

  private NodeUpdaterParams defaultParams() throws MalformedURLException {
    return new NodeUpdaterParams(
        manager,
        new FreenetURI("USK@" + NodeUpdateManager.UPDATE_URI + "/info/" + CURRENT_VERSION),
        CURRENT_VERSION,
        -1,
        Integer.MAX_VALUE,
        BLOB_PREFIX,
        DEFAULT_SUBSCRIBE_SEED);
  }

  private static @NotNull FetchContext createFetchContext() {
    SimpleEventProducer eventProducer = new SimpleEventProducer();
    return new FetchContext(
        FetchContextOptions.builder()
            .limits(Long.MAX_VALUE, Long.MAX_VALUE, 1024 * 1024)
            .archiveLimits(1, 1, 1, false)
            .retryLimits(0, 0, 0)
            .splitfileLimits(true, 1, 1)
            .behavior(true, false, false)
            .clientOptions(eventProducer, false, true)
            .filterOverrides(null, null, null)
            .build());
  }

  private static class TestNodeUpdater extends NodeUpdater {

    private TestNodeUpdater(NodeUpdaterParams params) {
      super(params);
    }

    @Override
    public String artifactName() {
      return "core-info.json";
    }

    @Override
    protected void onStartFetching() {
      // No-op for testing.
    }

    @Override
    protected void processSuccess(int fetched, FetchResult result, File blobFile) {
      // No-op for testing.
    }

    @Override
    protected void maybeParseManifest(FetchResult result, int build) {
      // No-op for testing.
    }
  }
}
