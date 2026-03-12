package network.crypta.client.async;

import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.NodeCHK;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class SplitFileFetcherStorageLayoutTest {

  @Test
  void accumulateSizes_whenMultipleSegmentsWithCrossChecks_returnsAggregatedSizes() {
    // Arrange
    SplitFileSegmentKeys[] segmentKeys =
        new SplitFileSegmentKeys[] {newSegmentKeys(5, 2, true), newSegmentKeys(7, 3, true)};
    int crossCheckBlocks = 1;
    boolean hasSplitfileSingleCryptoKey = true;
    int checksumLength = 4;
    int maxRetries = 3;
    boolean persistent = true;

    int expectedDataBlocks = (5 + 7) - (2 * crossCheckBlocks);
    int expectedCheckBlocks = 2 + 3;
    long expectedStoredKeysLength =
        expectedStoredKeysLength(5, 2, true, checksumLength)
            + expectedStoredKeysLength(7, 3, true, checksumLength);
    long expectedStoredSegmentStatusLength =
        expectedStoredSegmentStatusLength(4, 2, crossCheckBlocks, true, checksumLength)
            + expectedStoredSegmentStatusLength(6, 3, crossCheckBlocks, true, checksumLength);

    // Act
    SplitFileFetcherStorageLayout.AccumulatedSizes sizes =
        SplitFileFetcherStorageLayout.accumulateSizes(
            segmentKeys,
            crossCheckBlocks,
            hasSplitfileSingleCryptoKey,
            checksumLength,
            maxRetries,
            persistent);

    // Assert
    assertEquals(expectedDataBlocks, sizes.splitfileDataBlocks());
    assertEquals(expectedCheckBlocks, sizes.splitfileCheckBlocks());
    assertEquals(expectedStoredKeysLength, sizes.storedKeysLength());
    assertEquals(expectedStoredSegmentStatusLength, sizes.storedSegmentStatusLength());
  }

  @Test
  void accumulateSizes_whenRetriesDisabled_omitsRetryBytesInStatusLength() {
    // Arrange
    SplitFileSegmentKeys[] segmentKeys = new SplitFileSegmentKeys[] {newSegmentKeys(4, 1, false)};
    int crossCheckBlocks = 0;
    boolean hasSplitfileSingleCryptoKey = false;
    int checksumLength = 2;
    int maxRetries = -1;
    boolean persistent = true;

    int expectedDataBlocks = 4;
    int expectedCheckBlocks = 1;
    long expectedStoredKeysLength = expectedStoredKeysLength(4, 1, false, checksumLength);
    long expectedStoredSegmentStatusLength =
        expectedStoredSegmentStatusLength(4, 1, 0, false, checksumLength);

    // Act
    SplitFileFetcherStorageLayout.AccumulatedSizes sizes =
        SplitFileFetcherStorageLayout.accumulateSizes(
            segmentKeys,
            crossCheckBlocks,
            hasSplitfileSingleCryptoKey,
            checksumLength,
            maxRetries,
            persistent);

    // Assert
    assertEquals(expectedDataBlocks, sizes.splitfileDataBlocks());
    assertEquals(expectedCheckBlocks, sizes.splitfileCheckBlocks());
    assertEquals(expectedStoredKeysLength, sizes.storedKeysLength());
    assertEquals(expectedStoredSegmentStatusLength, sizes.storedSegmentStatusLength());
  }

  @Test
  void accumulateSizes_whenNonPersistent_returnsZeroStatusLength() {
    // Arrange
    SplitFileSegmentKeys[] segmentKeys =
        new SplitFileSegmentKeys[] {newSegmentKeys(2, 2, false), newSegmentKeys(1, 0, false)};
    int crossCheckBlocks = 0;
    boolean hasSplitfileSingleCryptoKey = false;
    int checksumLength = 3;
    int maxRetries = 2;
    boolean persistent = false;

    int expectedDataBlocks = 3;
    int expectedCheckBlocks = 2;
    long expectedStoredKeysLength =
        expectedStoredKeysLength(2, 2, false, checksumLength)
            + expectedStoredKeysLength(1, 0, false, checksumLength);

    // Act
    SplitFileFetcherStorageLayout.AccumulatedSizes sizes =
        SplitFileFetcherStorageLayout.accumulateSizes(
            segmentKeys,
            crossCheckBlocks,
            hasSplitfileSingleCryptoKey,
            checksumLength,
            maxRetries,
            persistent);

    // Assert
    assertEquals(expectedDataBlocks, sizes.splitfileDataBlocks());
    assertEquals(expectedCheckBlocks, sizes.splitfileCheckBlocks());
    assertEquals(expectedStoredKeysLength, sizes.storedKeysLength());
    assertEquals(0, sizes.storedSegmentStatusLength());
  }

  @Test
  void validateCheckLength_whenNotExceedingFinalLength_doesNotThrow() {
    // Arrange
    long checkLength = 100L;
    long finalLength = 100L;

    // Act + Assert
    assertDoesNotThrow(
        () -> SplitFileFetcherStorageLayout.validateCheckLength(checkLength, finalLength));
  }

  @Test
  void validateCheckLength_whenWithinTolerance_doesNotThrow() {
    // Arrange
    long finalLength = 100L;
    long checkLength = finalLength + CHKBlock.DATA_LENGTH;

    // Act + Assert
    assertDoesNotThrow(
        () -> SplitFileFetcherStorageLayout.validateCheckLength(checkLength, finalLength));
  }

  @Test
  void validateCheckLength_whenExceedsTolerance_throwsFetchException() {
    // Arrange
    long finalLength = 100L;
    long checkLength = finalLength + CHKBlock.DATA_LENGTH + 1L;

    // Act
    FetchException exception =
        assertThrows(
            FetchException.class,
            () -> SplitFileFetcherStorageLayout.validateCheckLength(checkLength, finalLength));

    // Assert
    assertEquals(FetchExceptionMode.INVALID_METADATA, exception.mode);
    assertTrue(
        exception.getMessage().contains("Splitfile is"),
        "Expected failure message to mention splitfile length");
  }

  @ParameterizedTest
  @ValueSource(ints = {0, -1})
  void validateSegmentCount_whenNonPositive_throwsAssertionError(int segmentCount) {
    // Arrange

    // Act
    AssertionError error =
        assertThrows(
            AssertionError.class,
            () -> SplitFileFetcherStorageLayout.validateSegmentCount(segmentCount));

    // Assert
    assertEquals("A splitfile has to have at least one segment", error.getMessage());
  }

  @Test
  void validateSegmentCount_whenPositive_doesNotThrow() {
    // Arrange

    // Act + Assert
    assertDoesNotThrow(() -> SplitFileFetcherStorageLayout.validateSegmentCount(1));
  }

  private static SplitFileSegmentKeys newSegmentKeys(
      int dataBlocks, int checkBlocks, boolean hasCommonKey) {
    byte[] commonKey = hasCommonKey ? new byte[32] : null;
    byte algorithm = (byte) 1;
    return new SplitFileSegmentKeys(dataBlocks, checkBlocks, commonKey, algorithm);
  }

  private static long expectedStoredKeysLength(
      int dataBlocks, int checkBlocks, boolean commonKey, int checksumLength) {
    long blocks = (long) dataBlocks + checkBlocks;
    long keyBytes;
    if (commonKey) {
      keyBytes = blocks * NodeCHK.KEY_LENGTH;
    } else {
      long perBlock = SplitFileSegmentKeys.EXTRA_BYTES_LENGTH + (long) NodeCHK.KEY_LENGTH * 2;
      keyBytes = blocks * perBlock;
    }
    return keyBytes + checksumLength;
  }

  private static long expectedStoredSegmentStatusLength(
      int dataBlocks,
      int checkBlocks,
      int crossCheckBlocks,
      boolean trackRetries,
      int checksumLength) {
    long fetchedBlocks = (long) dataBlocks + crossCheckBlocks;
    long totalBlocks = (long) dataBlocks + checkBlocks + crossCheckBlocks;
    long base = fetchedBlocks * 4L + (trackRetries ? totalBlocks * 4L : 0L);
    return base + checksumLength;
  }
}
