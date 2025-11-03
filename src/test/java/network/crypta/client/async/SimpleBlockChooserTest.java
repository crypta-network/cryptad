package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Random;
import network.crypta.keys.NodeCHK;
import network.crypta.support.io.StorageFormatException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SimpleBlockChooserTest {

  private static final class FixedRandom extends Random {
    private final int fixed;

    FixedRandom(int fixed) {
      this.fixed = fixed;
    }

    @Override
    public int nextInt(int bound) {
      if (bound <= 0) throw new IllegalArgumentException("bound must be > 0");
      int v = fixed % bound;
      return v < 0 ? v + bound : v;
    }
  }

  private static byte[] writeToBytes(SimpleBlockChooser chooser) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      chooser.write(dos);
    }
    return baos.toByteArray();
  }

  private static SimpleBlockChooser readFromBytes(byte[] data, int blocks, int maxRetries)
      throws IOException, StorageFormatException {
    SimpleBlockChooser readBack = new SimpleBlockChooser(blocks, new FixedRandom(0), maxRetries);
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data))) {
      readBack.read(dis);
    }
    return readBack;
  }

  private static final class TestBlockChooser extends SimpleBlockChooser {
    boolean completedAllCalled;

    TestBlockChooser(int blocks, Random random, int maxRetries) {
      super(blocks, random, maxRetries);
    }

    @Override
    protected void onCompletedAll() {
      completedAllCalled = true;
    }
  }

  @Test
  void chooseKey_whenMultipleCandidates_selectsUsingRandomAmongMinRetry() {
    SimpleBlockChooser chooser = new SimpleBlockChooser(5, new FixedRandom(0), 2);
    // Set higher retry count for some blocks so min-retry candidates are {0,2,4}
    chooser.onNonFatalFailure(1);
    chooser.onNonFatalFailure(3);

    int chosen = chooser.chooseKey();

    assertEquals(0, chosen, "Expected first candidate chosen when Random returns 0");
  }

  @Test
  void chooseKey_whenAllBlocksExceededMaxRetries_returnsMinusOne() {
    SimpleBlockChooser chooser = new SimpleBlockChooser(3, new FixedRandom(0), 0);
    // After one failure per block, retries[i] == 1 > maxRetries(0) so no candidates left
    for (int i = 0; i < 3; i++) {
      assertTrue(chooser.onNonFatalFailure(i));
    }

    assertEquals(-1, chooser.chooseKey());
  }

  @Test
  void onNonFatalFailure_whenIncrementing_returnsFatalOnlyWhenExceeds() {
    SimpleBlockChooser chooser = new SimpleBlockChooser(1, new FixedRandom(0), 2);

    assertFalse(chooser.onNonFatalFailure(0)); // retries = 1 <= 2
    assertEquals(1, chooser.getRetries(0));

    assertFalse(chooser.onNonFatalFailure(0)); // retries = 2 <= 2
    assertEquals(2, chooser.getRetries(0));

    assertTrue(chooser.onNonFatalFailure(0)); // retries = 3 > 2 → fatal
    assertEquals(3, chooser.getRetries(0));
  }

  @Test
  void onNonFatalFailure_whenUnlimitedRetries_neverFatal() {
    SimpleBlockChooser chooser = new SimpleBlockChooser(1, new FixedRandom(0), -1);
    for (int i = 0; i < 10; i++) {
      assertFalse(chooser.onNonFatalFailure(0));
      assertEquals(i + 1, chooser.getRetries(0));
    }
  }

  @Test
  void onSuccess_whenFirstTime_returnsTrue_andDuplicateReturnsFalse() {
    SimpleBlockChooser chooser = new SimpleBlockChooser(2, new FixedRandom(0), 2);

    assertTrue(chooser.onSuccess(0));
    assertEquals(1, chooser.successCount());
    assertTrue(chooser.hasSucceeded(0));

    assertFalse(chooser.onSuccess(0)); // duplicate
    assertEquals(1, chooser.successCount());
  }

  @Test
  void onSuccess_whenAllBlocksCompleted_invokesOnCompletedAll() {
    TestBlockChooser chooser = new TestBlockChooser(2, new FixedRandom(0), 2);
    assertTrue(chooser.onSuccess(0));
    assertFalse(chooser.completedAllCalled);

    assertTrue(chooser.onSuccess(1));
    assertTrue(chooser.completedAllCalled);
    assertTrue(chooser.hasSucceededAll());
  }

  @Test
  void onUnSuccess_whenPreviouslySuccessful_resetsState() {
    SimpleBlockChooser chooser = new SimpleBlockChooser(2, new FixedRandom(0), 2);
    assertTrue(chooser.onSuccess(0));
    assertEquals(1, chooser.successCount());
    assertTrue(chooser.hasSucceeded(0));

    chooser.onUnSuccess(0);
    assertEquals(0, chooser.successCount());
    assertFalse(chooser.hasSucceeded(0));

    // idempotent when already unsuccessful
    chooser.onUnSuccess(0);
    assertEquals(0, chooser.successCount());
  }

  @Test
  void replaceSuccesses_appliesMassToggleOfBlockStates() {
    SimpleBlockChooser chooser = new SimpleBlockChooser(5, new FixedRandom(0), 2);
    boolean[] used1 = new boolean[] {true, false, true, false, true};
    chooser.replaceSuccesses(used1);
    assertEquals(3, chooser.successCount());
    assertTrue(chooser.hasSucceeded(0));
    assertFalse(chooser.hasSucceeded(1));
    assertTrue(chooser.hasSucceeded(2));
    assertFalse(chooser.hasSucceeded(3));
    assertTrue(chooser.hasSucceeded(4));

    boolean[] used2 = new boolean[] {false, true, false, true, false};
    chooser.replaceSuccesses(used2);
    assertEquals(2, chooser.successCount());
    assertFalse(chooser.hasSucceeded(0));
    assertTrue(chooser.hasSucceeded(1));
    assertFalse(chooser.hasSucceeded(2));
    assertTrue(chooser.hasSucceeded(3));
    assertFalse(chooser.hasSucceeded(4));
  }

  @Test
  void getBlockNumber_delegatesToKeysWithCompletionMask() {
    SimpleBlockChooser chooser = new SimpleBlockChooser(4, new FixedRandom(0), 2);
    // Mark some successes to verify the mask passed to SplitFileSegmentKeys
    chooser.onSuccess(1);
    chooser.onSuccess(3);

    SplitFileSegmentKeys keys = Mockito.mock(SplitFileSegmentKeys.class);
    NodeCHK node = Mockito.mock(NodeCHK.class);

    Mockito.when(keys.getBlockNumber(Mockito.eq(node), Mockito.any(boolean[].class))).thenReturn(7);

    int ret = chooser.getBlockNumber(keys, node);
    assertEquals(7, ret);

    ArgumentCaptor<boolean[]> captor = ArgumentCaptor.forClass(boolean[].class);
    Mockito.verify(keys).getBlockNumber(Mockito.eq(node), captor.capture());
    boolean[] mask = captor.getValue();
    assertArrayEquals(new boolean[] {false, true, false, true}, mask);
  }

  @Test
  void write_and_read_roundTrip_withFiniteMaxRetries_restoresState()
      throws IOException, StorageFormatException {
    SimpleBlockChooser chooser = new SimpleBlockChooser(5, new FixedRandom(0), 3);
    chooser.onSuccess(0);
    chooser.onSuccess(2);
    chooser.onNonFatalFailure(1); // 1
    chooser.onNonFatalFailure(3); // 1
    chooser.onNonFatalFailure(3); // 2
    chooser.onNonFatalFailure(3); // 3
    chooser.onNonFatalFailure(3); // 4
    chooser.onNonFatalFailure(4); // 1
    chooser.onNonFatalFailure(4); // 2

    byte[] data = writeToBytes(chooser);
    SimpleBlockChooser readBack = readFromBytes(data, 5, 3);

    assertTrue(readBack.hasSucceeded(0));
    assertTrue(readBack.hasSucceeded(2));
    assertFalse(readBack.hasSucceeded(1));
    assertFalse(readBack.hasSucceeded(3));
    assertFalse(readBack.hasSucceeded(4));
    assertEquals(2, readBack.successCount());
    assertEquals(1, readBack.getRetries(1));
    assertEquals(4, readBack.getRetries(3));
    assertEquals(2, readBack.getRetries(4));
  }

  @Test
  void write_and_read_roundTrip_withUnlimitedMaxRetries_restoresCompletionsOnly()
      throws IOException, StorageFormatException {
    SimpleBlockChooser chooser = new SimpleBlockChooser(3, new FixedRandom(0), -1);
    chooser.onSuccess(1);
    // Record some retries; they should not be written/read when maxRetries == -1
    chooser.onNonFatalFailure(0);
    chooser.onNonFatalFailure(2);

    byte[] data = writeToBytes(chooser);
    SimpleBlockChooser readBack = readFromBytes(data, 3, -1);

    assertFalse(readBack.hasSucceeded(0));
    assertTrue(readBack.hasSucceeded(1));
    assertFalse(readBack.hasSucceeded(2));
    assertEquals(1, readBack.successCount());
    // retries are not persisted when maxRetries == -1
    assertEquals(0, readBack.getRetries(0));
    assertEquals(0, readBack.getRetries(2));
  }

  @Test
  void read_whenVersionMismatch_throwsStorageFormatException() {
    SimpleBlockChooser chooser = new SimpleBlockChooser(4, new FixedRandom(0), 2);
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      // Write an invalid version, nothing else required as read() checks version first
      dos.writeInt(999);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }

    byte[] data = baos.toByteArray();
    assertThrows(
        StorageFormatException.class,
        () -> {
          try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data))) {
            chooser.read(dis);
          }
        });
  }

  @Test
  void read_whenMaxRetriesMismatch_throwsStorageFormatException() throws IOException {
    // Write with maxRetries = 2
    SimpleBlockChooser writer = new SimpleBlockChooser(2, new FixedRandom(0), 2);
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      writer.write(dos);
    }

    byte[] data = baos.toByteArray();
    // Read with a different maxRetries value -> exception
    SimpleBlockChooser reader = new SimpleBlockChooser(2, new FixedRandom(0), 3);
    assertThrows(
        StorageFormatException.class,
        () -> {
          try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data))) {
            reader.read(dis);
          }
        });
  }

  @Test
  void countFailedBlocks_whenMixedCountsOnlyUncompletedWithRetriesOverLimit() {
    SimpleBlockChooser chooser = new SimpleBlockChooser(4, new FixedRandom(0), 1);
    // Block 0: 2 failures -> counts
    chooser.onNonFatalFailure(0);
    chooser.onNonFatalFailure(0);
    // Block 1: 1 failure -> not counted (== max)
    chooser.onNonFatalFailure(1);
    // Block 2: 3 failures but then success -> not counted (completed)
    chooser.onNonFatalFailure(2);
    chooser.onNonFatalFailure(2);
    chooser.onNonFatalFailure(2);
    chooser.onSuccess(2);
    // Block 3: no failures -> not counted

    assertEquals(1, chooser.countFailedBlocks());
  }

  @Test
  void copyDownloadedBlocks_returnsCloneNotView() {
    SimpleBlockChooser chooser = new SimpleBlockChooser(3, new FixedRandom(0), 2);
    chooser.onSuccess(1);

    boolean[] copy = chooser.copyDownloadedBlocks();
    assertArrayEquals(new boolean[] {false, true, false}, copy);
    assertNotSame(copy, chooser.copyDownloadedBlocks());

    // Mutating the copy must not affect the chooser's state
    copy[1] = false;
    assertTrue(chooser.hasSucceeded(1));
  }

  @Test
  void countFetchable_whenUnlimitedRetries_returnsZeroDueToCurrentImplementation() {
    // With maxRetries == -1 the current implementation checks `retries[x] >= maxRetries` which is
    // always true, so the method returns 0.
    SimpleBlockChooser chooser = new SimpleBlockChooser(3, new FixedRandom(0), -1);
    assertEquals(0, chooser.countFetchable());
  }
}
