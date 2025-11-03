package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Random;
import network.crypta.keys.NodeCHK;
import network.crypta.node.BaseSendableGet;
import network.crypta.node.KeysFetchingLocally;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SplitFileFetcherSegmentBlockChooserTest {

  @Mock private KeysFetchingLocally keysFetching;

  @Mock private SplitFileSegmentKeys segmentKeys;

  @Mock private SplitFileFetcherStorageCallback fetcherCallback;

  @Mock private PersistentJobRunner jobRunner;

  @Mock private BaseSendableGet sendableGet;

  // Avoid JDK-internal Unsafe; use regular reflection on project classes only.

  private static void setField(Object target, String fieldName, Object value) {
    try {
      Field f = target.getClass().getDeclaredField(fieldName);
      f.setAccessible(true);
      f.set(target, value);
    } catch (Exception e) {
      throw new AssertionError(
          "Failed to set field '" + fieldName + "' on " + target.getClass().getName(), e);
    }
  }

  private SplitFileFetcherStorage minimalParent() {
    // Create a lightweight mock instance; we will set needed fields via reflection.
    SplitFileFetcherStorage parent =
        Mockito.mock(SplitFileFetcherStorage.class, Mockito.withSettings().stubOnly());
    setField(parent, "jobRunner", jobRunner);
    setField(parent, "fetcher", fetcherCallback);
    // Not used by chooser directly, but some code paths may dereference segments length.
    setField(parent, "segments", new SplitFileFetcherSegmentStorage[1]);
    Mockito.lenient().when(fetcherCallback.getSendableGet()).thenReturn(sendableGet);
    return parent;
  }

  @Test
  void chooseKey_whenIgnoreLastBlock_excludesThatIndex() {
    // Arrange
    SplitFileFetcherStorage parent = minimalParent();
    SplitFileFetcherSegmentStorage seg =
        Mockito.mock(SplitFileFetcherSegmentStorage.class, Mockito.withSettings().stubOnly());
    setField(seg, "parent", parent);
    // ignore block 0 in a single-block chooser
    SplitFileFetcherSegmentBlockChooser chooser =
        new SplitFileFetcherSegmentBlockChooser(
            1,
            new Random(1234L), /*maxRetries*/
            3, /*cooldownTries*/
            0,
            /*cooldownTime*/ 0L,
            seg,
            keysFetching, /*ignoreLastBlock*/
            0);

    // Act
    int chosen = chooser.chooseKey();

    // Assert
    assertEquals(-1, chosen, "Ignored block must not be selected");
    Mockito.verifyNoInteractions(keysFetching);
  }

  @Test
  void chooseKey_whenKeyAlreadyFetching_skipsAndReturnsMinusOne() throws Exception {
    // Arrange
    SplitFileFetcherStorage parent = minimalParent();
    SplitFileFetcherSegmentStorage seg =
        Mockito.mock(SplitFileFetcherSegmentStorage.class, Mockito.withSettings().stubOnly());
    setField(seg, "parent", parent);

    // key for block 0
    byte[] rk = new byte[NodeCHK.KEY_LENGTH];
    rk[0] = 42; // deterministic content
    NodeCHK key0 = new NodeCHK(rk, (byte) 1);

    Mockito.when(
            segmentKeys.getNodeKey(Mockito.eq(0), ArgumentMatchers.isNull(), Mockito.eq(false)))
        .thenReturn(key0);
    Mockito.when(seg.getSegmentKeys()).thenReturn(segmentKeys);
    Mockito.when(keysFetching.hasKey(key0, sendableGet)).thenReturn(true);

    SplitFileFetcherSegmentBlockChooser chooser =
        new SplitFileFetcherSegmentBlockChooser(
            1, new Random(7L), /*maxRetries*/ 3, /*cooldownTries*/ 0, 0L, seg, keysFetching, -1);

    // Act
    int chosen = chooser.chooseKey();

    // Assert
    assertEquals(-1, chosen, "Block already in-flight must be skipped");
    Mockito.verify(keysFetching, Mockito.times(1)).hasKey(key0, sendableGet);
  }

  @Test
  void chooseKey_whenKeyNotFetching_returnsIndex() throws Exception {
    // Arrange
    SplitFileFetcherStorage parent = minimalParent();
    SplitFileFetcherSegmentStorage seg =
        Mockito.mock(SplitFileFetcherSegmentStorage.class, Mockito.withSettings().stubOnly());
    setField(seg, "parent", parent);

    byte[] rk = new byte[NodeCHK.KEY_LENGTH];
    rk[0] = 11;
    NodeCHK key0 = new NodeCHK(rk, (byte) 1);

    Mockito.when(
            segmentKeys.getNodeKey(Mockito.eq(0), ArgumentMatchers.isNull(), Mockito.eq(false)))
        .thenReturn(key0);
    Mockito.when(seg.getSegmentKeys()).thenReturn(segmentKeys);
    Mockito.when(keysFetching.hasKey(key0, sendableGet)).thenReturn(false);

    SplitFileFetcherSegmentBlockChooser chooser =
        new SplitFileFetcherSegmentBlockChooser(
            1, new Random(99L), /*maxRetries*/ 3, /*cooldownTries*/ 0, 0L, seg, keysFetching, -1);

    // Act
    int chosen = chooser.chooseKey();

    // Assert
    assertEquals(0, chosen, "Eligible block should be selected");
  }

  @Test
  void chooseKey_whenGetSegmentKeysThrows_queuesJobAndReturnsMinusOne() throws Exception {
    // Arrange
    SplitFileFetcherStorage parent = minimalParent();
    SplitFileFetcherSegmentStorage seg =
        Mockito.mock(SplitFileFetcherSegmentStorage.class, Mockito.withSettings().stubOnly());
    setField(seg, "parent", parent);

    IOException io = new IOException("boom");
    Mockito.doThrow(io).when(seg).getSegmentKeys();

    SplitFileFetcherSegmentBlockChooser chooser =
        new SplitFileFetcherSegmentBlockChooser(
            1, new Random(1L), /*maxRetries*/ 3, /*cooldownTries*/ 0, 0L, seg, keysFetching, -1);

    // Act
    int chosen = chooser.chooseKey();

    // Assert
    assertEquals(
        -1, chosen, "IOException obtaining keys should lead to no selection and a queued job");

    ArgumentCaptor<PersistentJob> jobCaptor = ArgumentCaptor.forClass(PersistentJob.class);
    Mockito.verify(jobRunner, Mockito.times(1)).queueNormalOrDrop(jobCaptor.capture());

    // The queued job is well-formed and returns a checkpoint request.
    boolean requestCheckpoint = jobCaptor.getValue().run(Mockito.mock(ClientContext.class));
    assertTrue(requestCheckpoint, "Disk error handling job should request checkpoint");
  }
}
