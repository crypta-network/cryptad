package network.crypta.client.async;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Random;
import network.crypta.client.async.SplitFileInserterSegmentStorage.BlockInsert;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.support.io.StorageFormatException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SplitFileInserterSegmentBlockChooserTest {

  @Mock private KeysFetchingLocally keysFetching;

  private Random rnd;

  @BeforeEach
  void setup() {
    rnd = new Random(12345L);
  }

  @Test
  void onRNF_whenThresholdReached_marksBlockSucceeded() {
    // Arrange: enable RNF counting with threshold=3 for a single block
    int blocks = 1;
    int threshold = 3;
    SplitFileInserterSegmentStorage segment = Mockito.mock(SplitFileInserterSegmentStorage.class);
    SplitFileInserterSegmentBlockChooser chooser =
        new SplitFileInserterSegmentBlockChooser(
            segment, blocks, rnd, /* maxRetries= */ 5, keysFetching, threshold) {
          @Override
          protected int getMaxBlockNumber() {
            return blocks;
          }
        };

    // Act + Assert: first two RNFs do not succeed yet
    chooser.onRNF(0);
    assertFalse(chooser.hasSucceeded(0));
    chooser.onRNF(0);
    assertFalse(chooser.hasSucceeded(0));

    // Act: third RNF should mark success
    chooser.onRNF(0);

    // Assert
    assertTrue(chooser.hasSucceeded(0));
  }

  @Test
  void pushRNFs_whenApplied_incrementsRetriesAndSignalsExceedWhenOverMax() {
    // Arrange: threshold>0 enables RNF accounting; set maxRetries=2
    int blocks = 1;
    int threshold = 5;
    SplitFileInserterSegmentStorage segment = Mockito.mock(SplitFileInserterSegmentStorage.class);
    SplitFileInserterSegmentBlockChooser chooser =
        new SplitFileInserterSegmentBlockChooser(
            segment, blocks, rnd, /* maxRetries= */ 2, keysFetching, threshold) {
          @Override
          protected int getMaxBlockNumber() {
            return blocks;
          }
        };

    // Seed with 2 prior RNFs; pushing should increase retries to exactly 2 (not exceeding)
    assertNotNull(chooser.consecutiveRNFs);
    chooser.consecutiveRNFs[0] = 2;
    boolean exceeded = chooser.pushRNFs(0);
    assertFalse(exceeded);
    assertEquals(2, chooser.getRetries(0));
    assertEquals(0, chooser.consecutiveRNFs[0]);

    // Now one more RNF pending; pushing should exceed maxRetries (2 -> 3) and signal true
    chooser.consecutiveRNFs[0] = 1;
    boolean nowExceeded = chooser.pushRNFs(0);
    assertTrue(nowExceeded);
    assertEquals(3, chooser.getRetries(0));
    assertEquals(0, chooser.consecutiveRNFs[0]);
  }

  @Test
  void chooseKey_whenTokenInFlight_excludesItAndPicksAnother() {
    // Arrange: 3 blocks, with block #1 marked as in-flight via KeysFetchingLocally
    int blocks = 3;
    SplitFileInserterSegmentStorage segment = Mockito.mock(SplitFileInserterSegmentStorage.class);

    // Act: chooseKey() should not return 1, since it's reported in-flight; only 0 is eligible
    int chosen = chooseExcludingInFlightBlock(segment, blocks);

    // Assert
    assertEquals(0, chosen);

    // Also verify keysFetching was queried with a BlockInsert for block 1
    ArgumentCaptor<BlockInsert> captor = ArgumentCaptor.forClass(BlockInsert.class);
    // Called for block 0 (eligible) and 1 (excluded); block 2 is skipped early due to higher retry
    verify(keysFetching, times(2)).hasInsert(captor.capture());
    boolean sawBlock1 =
        captor.getAllValues().stream().anyMatch(bi -> bi.blockNumber == 1 && bi.segment == segment);
    assertTrue(sawBlock1);
  }

  @Test
  void chooseKey_whenAllInFlight_returnsMinusOne() {
    int blocks = 2;
    SplitFileInserterSegmentStorage segment = Mockito.mock(SplitFileInserterSegmentStorage.class);
    when(keysFetching.hasInsert(any())).thenReturn(true); // everything is in flight

    SplitFileInserterSegmentBlockChooser chooser =
        new SplitFileInserterSegmentBlockChooser(
            segment, blocks, rnd, /* maxRetries= */ 10, keysFetching, /* threshold= */ 0) {
          @Override
          protected int getMaxBlockNumber() {
            return blocks;
          }
        };

    int chosen = chooser.chooseKey();
    assertEquals(-1, chosen);
  }

  @Test
  void onCompletedAll_whenAllSucceeded_invokesSegmentCallback() {
    int blocks = 2;
    SplitFileInserterSegmentStorage segment = Mockito.mock(SplitFileInserterSegmentStorage.class);
    SplitFileInserterSegmentBlockChooser chooser =
        new SplitFileInserterSegmentBlockChooser(
            segment, blocks, rnd, /* maxRetries= */ 5, keysFetching, /* threshold= */ 0) {
          @Override
          protected int getMaxBlockNumber() {
            return blocks;
          }
        };

    // Act: mark both blocks as success
    assertTrue(chooser.onSuccess(0));
    assertTrue(chooser.onSuccess(1));

    // Assert: the subclass hook should be invoked exactly once
    verify(segment, times(1)).onInsertedAllBlocks();
  }

  @Test
  void serialization_roundTripWithRNFCounters_preservesState()
      throws IOException, StorageFormatException {
    int blocks = 4;
    int threshold = 10; // enable RNF accounting
    SplitFileInserterSegmentStorage segment = Mockito.mock(SplitFileInserterSegmentStorage.class);
    SplitFileInserterSegmentBlockChooser chooser =
        new SplitFileInserterSegmentBlockChooser(
            segment, blocks, rnd, /* maxRetries= */ 7, keysFetching, threshold) {
          @Override
          protected int getMaxBlockNumber() {
            return blocks;
          }
        };

    // Mutate state: mark some successes, some retries, and RNF counters
    chooser.onSuccess(0);
    chooser.onNonFatalFailure(1);
    chooser.onNonFatalFailure(1);
    chooser.onNonFatalFailure(2);
    assertNotNull(chooser.consecutiveRNFs);
    chooser.consecutiveRNFs[1] = 3;
    chooser.consecutiveRNFs[3] = 5;

    // Serialize
    ByteArrayOutputStream baos = serializeChooser(chooser);

    // Deserialize into a fresh chooser with identical configuration
    SplitFileInserterSegmentBlockChooser restored =
        restoreChooser(
            segment, blocks, /* maxRetries= */ 7, keysFetching, threshold, baos.toByteArray());

    // Assert: completion mask, retry counters, and RNF counters preserved
    assertTrue(restored.hasSucceeded(0));
    assertFalse(restored.hasSucceeded(1));
    assertFalse(restored.hasSucceeded(2));
    assertFalse(restored.hasSucceeded(3));
    assertEquals(2, restored.getRetries(1));
    assertEquals(1, restored.getRetries(2));
    assertArrayEquals(new int[] {0, 3, 0, 5}, restored.consecutiveRNFs);
  }

  @Test
  void serialization_roundTripWithoutRNFSection_ignoresRNFState()
      throws IOException, StorageFormatException {
    int blocks = 2;
    SplitFileInserterSegmentStorage segment = Mockito.mock(SplitFileInserterSegmentStorage.class);
    SplitFileInserterSegmentBlockChooser chooser =
        new SplitFileInserterSegmentBlockChooser(
            segment, blocks, rnd, /* maxRetries= */ 3, keysFetching, /* threshold= */ 0) {
          @Override
          protected int getMaxBlockNumber() {
            return blocks;
          }
        };

    chooser.onNonFatalFailure(0);
    chooser.onSuccess(1);

    // Serialize
    ByteArrayOutputStream baos = serializeChooser(chooser);

    // Deserialize into a fresh chooser with the same configuration
    SplitFileInserterSegmentBlockChooser restored =
        restoreChooser(
            segment,
            blocks,
            /* maxRetries= */ 3,
            keysFetching,
            /* threshold= */ 0,
            baos.toByteArray());

    // Assert: state restored; RNF array remains null when feature disabled
    assertEquals(1, restored.getRetries(0));
    assertTrue(restored.hasSucceeded(1));
    Assertions.assertNull(restored.consecutiveRNFs);
  }

  /**
   * Picks a block while excluding block {@code 1} as if it was already in-flight.
   *
   * <p>This helper encapsulates the test setup and selection logic used in {@code
   * chooseKey_whenTokenInFlight_excludesItAndPicksAnother}. It mocks the {@link
   * KeysFetchingLocally} to report block {@code 1} as in-flight for the provided segment, slightly
   * de-prioritizes block {@code 2} via a retry, and returns the chosen block number.
   *
   * @param segment the segment under test
   * @param blocks total number of blocks in the segment
   * @return the chosen eligible block index
   */
  private int chooseExcludingInFlightBlock(SplitFileInserterSegmentStorage segment, int blocks) {
    when(keysFetching.hasInsert(any()))
        .thenAnswer(
            invocation -> {
              Object arg = invocation.getArgument(0);
              if (arg instanceof BlockInsert bi) {
                return bi.blockNumber == 1 && bi.segment == segment;
              }
              return false;
            });

    SplitFileInserterSegmentBlockChooser chooser =
        new SplitFileInserterSegmentBlockChooser(
            segment, blocks, rnd, /* maxRetries= */ 10, keysFetching, /* threshold= */ 0) {
          @Override
          protected int getMaxBlockNumber() {
            return blocks;
          }
        };

    // Make block #2 less preferred by increasing its retry count
    chooser.onNonFatalFailure(2);
    return chooser.chooseKey();
  }

  /**
   * Serializes a chooser to a byte array output stream for later deserialization in tests.
   *
   * @param chooser the chooser to serialize
   * @return a {@link ByteArrayOutputStream} containing the serialized chooser state
   * @throws IOException if writing fails
   */
  private static ByteArrayOutputStream serializeChooser(
      SplitFileInserterSegmentBlockChooser chooser) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      chooser.write(dos);
    }
    return baos;
  }

  /**
   * Restores a chooser with the provided configuration from the serialized bytes.
   *
   * @param segment segment reference to embed in the restored chooser
   * @param blocks total number of blocks
   * @param maxRetries configured maximum retries
   * @param keysFetching keys in-flight tracker
   * @param threshold RNF threshold (0 disables the feature)
   * @param data serialized chooser state, as produced by {@link #serializeChooser}
   * @return a chooser populated with the serialized state
   * @throws IOException if reading fails
   * @throws StorageFormatException if the data is malformed
   */
  private static SplitFileInserterSegmentBlockChooser restoreChooser(
      SplitFileInserterSegmentStorage segment,
      int blocks,
      int maxRetries,
      KeysFetchingLocally keysFetching,
      int threshold,
      byte[] data)
      throws IOException, StorageFormatException {
    SplitFileInserterSegmentBlockChooser restored =
        new SplitFileInserterSegmentBlockChooser(
            segment, blocks, new Random(12345L), maxRetries, keysFetching, threshold) {
          @Override
          protected int getMaxBlockNumber() {
            return blocks;
          }
        };
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data))) {
      restored.read(dis);
    }
    return restored;
  }
}
