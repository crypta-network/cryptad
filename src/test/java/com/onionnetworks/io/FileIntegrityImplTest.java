package com.onionnetworks.io;

import com.onionnetworks.util.Buffer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class FileIntegrityImplTest {

  @Test
  void constructor_whenAlgorithmNull_expectNullPointerException() {
    Buffer fileHash = new Buffer(new byte[] {1});
    Buffer[] blockHashes = {new Buffer(new byte[] {2})};

    assertThrows(
        NullPointerException.class,
        () -> new FileIntegrityImpl(null, fileHash, blockHashes, 1L, 1));
  }

  @Test
  void constructor_whenFileHashNull_expectNullPointerException() {
    Buffer[] blockHashes = {new Buffer(new byte[] {2})};

    assertThrows(
        NullPointerException.class, () -> new FileIntegrityImpl("SHA-1", null, blockHashes, 1L, 1));
  }

  @Test
  void constructor_whenBlockHashesNull_expectNullPointerException() {
    Buffer fileHash = new Buffer(new byte[] {1});

    assertThrows(
        NullPointerException.class, () -> new FileIntegrityImpl("SHA-1", fileHash, null, 1L, 1));
  }

  @Test
  void constructor_whenFileSizeNegative_expectIllegalArgumentException() {
    Buffer fileHash = new Buffer(new byte[] {1});
    Buffer[] blockHashes = {new Buffer(new byte[] {2})};

    assertThrows(
        IllegalArgumentException.class,
        () -> new FileIntegrityImpl("SHA-1", fileHash, blockHashes, -1L, 1));
  }

  @Test
  void constructor_whenBlockSizeNegative_expectIllegalArgumentException() {
    Buffer fileHash = new Buffer(new byte[] {1});
    Buffer[] blockHashes = {new Buffer(new byte[] {2})};

    assertThrows(
        IllegalArgumentException.class,
        () -> new FileIntegrityImpl("SHA-1", fileHash, blockHashes, 1L, -1));
  }

  @Test
  void constructor_whenBlockHashesCountMismatch_expectIllegalArgumentException() {
    Buffer fileHash = new Buffer(new byte[] {1});
    Buffer[] blockHashes = {new Buffer(new byte[] {2})};

    assertThrows(
        IllegalArgumentException.class,
        () -> new FileIntegrityImpl("SHA-1", fileHash, blockHashes, 512L, 256));
  }

  @Test
  void constructor_whenBlockSizeZero_expectArithmeticException() {
    Buffer fileHash = new Buffer(new byte[] {1});
    Buffer[] blockHashes = new Buffer[0];

    assertThrows(
        ArithmeticException.class,
        () -> new FileIntegrityImpl("SHA-1", fileHash, blockHashes, 0L, 0));
  }

  @Test
  void getters_whenValidConstruction_returnSuppliedValues() {
    Buffer fileHash = new Buffer(new byte[] {1, 2, 3});
    Buffer[] blockHashes = {
      new Buffer(new byte[] {10}),
      new Buffer(new byte[] {11}),
      new Buffer(new byte[] {12}),
      new Buffer(new byte[] {13}),
      new Buffer(new byte[] {14})
    };

    FileIntegrityImpl integrity =
        new FileIntegrityImpl("SHA-256", fileHash, blockHashes, 1025L, 256);

    assertEquals("SHA-256", integrity.getAlgorithm());
    assertEquals(256, integrity.getBlockSize());
    assertEquals(1025L, integrity.getFileSize());
    assertEquals(5, integrity.getBlockCount());
    assertSame(fileHash, integrity.getFileHash());
  }

  @Test
  void getBlockHash_whenValidIndex_returnsCorrespondingBuffer() {
    Buffer[] blockHashes = {
      new Buffer(new byte[] {5}), new Buffer(new byte[] {6}), new Buffer(new byte[] {7})
    };
    FileIntegrityImpl integrity =
        new FileIntegrityImpl("SHA-1", new Buffer(new byte[] {1}), blockHashes, 3L, 1);

    Buffer result = integrity.getBlockHash(2);

    assertSame(blockHashes[2], result);
  }

  @ParameterizedTest
  @ValueSource(ints = {-1, 3})
  void getBlockHash_whenIndexOutOfRange_expectIllegalArgumentException(int index) {
    Buffer[] blockHashes = {
      new Buffer(new byte[] {5}), new Buffer(new byte[] {6}), new Buffer(new byte[] {7})
    };
    FileIntegrityImpl integrity =
        new FileIntegrityImpl("SHA-1", new Buffer(new byte[] {1}), blockHashes, 3L, 1);

    assertThrows(IllegalArgumentException.class, () -> integrity.getBlockHash(index));
  }

  @Test
  void constructor_whenFileSizeZeroAndNoBlocks_expectZeroBlockCount() {
    Buffer fileHash = new Buffer(new byte[] {0});
    Buffer[] blockHashes = new Buffer[0];

    FileIntegrityImpl integrity = new FileIntegrityImpl("SHA-1", fileHash, blockHashes, 0L, 1);

    assertEquals(0, integrity.getBlockCount());
  }
}
