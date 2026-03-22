package network.crypta.client.async;

import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import network.crypta.crypt.HashResult;
import network.crypta.crypt.HashType;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.api.ResumeContext;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Unit tests for {@link CompressionOutput}. */
@SuppressWarnings("java:S100") // test method naming: method_whenCondition_expectOutcome
class CompressionOutputTest {

  // ------------------ Helpers ------------------

  private static byte[] bytes(int len, byte value) {
    byte[] b = new byte[len];
    Arrays.fill(b, value);
    return b;
  }

  private static HashResult hr(HashType t, byte fill) {
    return new HashResult(t, bytes(t.hashLength, fill));
  }

  /**
   * Minimal deterministic {@link RandomAccessBucket} for equality/toString testing. Implements the
   * interface but all I/O methods throw {@link UnsupportedOperationException} as tests never call
   * them.
   */
  @SuppressWarnings("ClassCanBeRecord")
  private static final class FakeBucket implements RandomAccessBucket {
    private final String id;

    FakeBucket(String id) {
      this.id = id;
    }

    @Override
    public String toString() {
      return "FakeBucket(" + id + ")";
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (!(o instanceof FakeBucket other)) return false;
      return this.id.equals(other.id);
    }

    @Override
    public int hashCode() {
      return id.hashCode();
    }

    // ---- Bucket / RandomAccessBucket API (unused here) ----
    @Override
    public OutputStream getOutputStream() {
      throw new UnsupportedOperationException();
    }

    @Override
    public OutputStream getOutputStreamUnbuffered() {
      throw new UnsupportedOperationException();
    }

    @Override
    public InputStream getInputStream() {
      throw new UnsupportedOperationException();
    }

    @Override
    public InputStream getInputStreamUnbuffered() {
      throw new UnsupportedOperationException();
    }

    @Override
    public String getName() {
      return id;
    }

    @Override
    public long size() {
      return 0;
    }

    @Override
    public boolean isReadOnly() {
      return true;
    }

    @Override
    public void setReadOnly() {
      // Intentionally unused in tests; FakeBucket models an immutable, read-only bucket.
      // Throwing to surface accidental calls during future refactors.
      throw new UnsupportedOperationException();
    }

    @Override
    public void free() {
      // Intentionally unused in tests; nothing to release for the fake implementation.
      // Throwing to surface accidental calls during future refactors.
      throw new UnsupportedOperationException();
    }

    @Override
    public RandomAccessBucket createShadow() {
      return this;
    }

    @Override
    public LockableRandomAccessBuffer toRandomAccessBuffer() {
      throw new UnsupportedOperationException();
    }

    @Override
    public void onResume(ResumeContext context) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void storeTo(DataOutputStream dos) {
      throw new UnsupportedOperationException();
    }
  }

  // ------------------ equals/hashCode ------------------

  @Test
  void equals_whenAllFieldsEqual_expectTrueAndHashCodeEqual() {
    // Arrange
    RandomAccessBucket bucket = new FakeBucket("A");
    COMPRESSOR_TYPE codec = COMPRESSOR_TYPE.GZIP;
    HashResult hA = hr(HashType.SHA256, (byte) 1);
    HashResult hB = hr(HashType.SHA1, (byte) 2);
    // Use the SAME HashResult instances in both arrays to ensure element hashCodes match.
    HashResult[] h1 = new HashResult[] {hA, hB};
    HashResult[] h2 = new HashResult[] {hA, hB};

    CompressionOutput co1 = new CompressionOutput(bucket, codec, h1);
    CompressionOutput co2 = new CompressionOutput(bucket, codec, h2);

    // Act + Assert
    assertEquals(co1, co2);
    assertEquals(co1.hashCode(), co2.hashCode());
  }

  @Test
  void equals_whenEqualHashesDifferentInstances_expectTrue() {
    // Arrange
    RandomAccessBucket bucket = new FakeBucket("A");
    COMPRESSOR_TYPE codec = COMPRESSOR_TYPE.GZIP;
    HashResult[] h1 = new HashResult[] {hr(HashType.SHA256, (byte) 5), hr(HashType.SHA1, (byte) 6)};
    // New instances with same type/content
    HashResult[] h2 = new HashResult[] {hr(HashType.SHA256, (byte) 5), hr(HashType.SHA1, (byte) 6)};

    CompressionOutput co1 = new CompressionOutput(bucket, codec, h1);
    CompressionOutput co2 = new CompressionOutput(bucket, codec, h2);

    // Act + Assert
    assertEquals(co1, co2);
  }

  @Test
  void equals_whenDifferentData_expectFalse() {
    // Arrange
    CompressionOutput a =
        new CompressionOutput(
            new FakeBucket("A"),
            COMPRESSOR_TYPE.GZIP,
            new HashResult[] {hr(HashType.SHA1, (byte) 7)});
    CompressionOutput b =
        new CompressionOutput(
            new FakeBucket("B"),
            COMPRESSOR_TYPE.GZIP,
            new HashResult[] {hr(HashType.SHA1, (byte) 7)});

    // Act + Assert
    assertNotEquals(a, b);
  }

  @Test
  void equals_whenDifferentCodec_expectFalse() {
    // Arrange
    RandomAccessBucket bucket = new FakeBucket("Z");
    HashResult[] hashes = new HashResult[] {hr(HashType.SHA512, (byte) 3)};
    CompressionOutput a = new CompressionOutput(bucket, COMPRESSOR_TYPE.GZIP, hashes);
    CompressionOutput b = new CompressionOutput(bucket, COMPRESSOR_TYPE.BZIP2, hashes);

    // Act + Assert
    assertNotEquals(a, b);
  }

  @Test
  void equals_whenDifferentHashesContent_expectFalse() {
    // Arrange
    RandomAccessBucket bucket = new FakeBucket("Q");
    CompressionOutput a =
        new CompressionOutput(
            bucket, COMPRESSOR_TYPE.LZMA_NEW, new HashResult[] {hr(HashType.SHA256, (byte) 1)});
    CompressionOutput b =
        new CompressionOutput(
            bucket, COMPRESSOR_TYPE.LZMA_NEW, new HashResult[] {hr(HashType.SHA256, (byte) 2)});

    // Act + Assert
    assertNotEquals(a, b);
  }

  @Test
  void equals_whenSameHashesDifferentOrder_expectFalse() {
    // Arrange
    RandomAccessBucket bucket = new FakeBucket("Q");
    HashResult h1 = hr(HashType.SHA1, (byte) 1);
    HashResult h2 = hr(HashType.SHA256, (byte) 2);
    CompressionOutput a =
        new CompressionOutput(bucket, COMPRESSOR_TYPE.GZIP, new HashResult[] {h1, h2});
    CompressionOutput b =
        new CompressionOutput(bucket, COMPRESSOR_TYPE.GZIP, new HashResult[] {h2, h1});

    // Act + Assert
    assertNotEquals(a, b);
  }

  @Test
  void equals_whenBothHashesNull_expectTrueAndHashCodeEqual() {
    // Arrange
    CompressionOutput a = new CompressionOutput(null, null, null);
    CompressionOutput b = new CompressionOutput(null, null, null);

    // Act + Assert
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
  }

  @Test
  void equals_whenOneHashesNullOtherEmpty_expectFalse() {
    // Arrange
    CompressionOutput a = new CompressionOutput(new FakeBucket("X"), COMPRESSOR_TYPE.GZIP, null);
    CompressionOutput b =
        new CompressionOutput(new FakeBucket("X"), COMPRESSOR_TYPE.GZIP, new HashResult[0]);

    // Act + Assert
    assertNotEquals(a, b);
  }

  @Test
  void equals_whenComparedWithNullOrDifferentType_expectFalse() {
    // Arrange
    CompressionOutput a = new CompressionOutput(null, COMPRESSOR_TYPE.BZIP2, null);

    // Act + Assert
    assertNotEquals(null, a);
    assertNotEquals(new Object(), a);
  }

  // ------------------ toString ------------------

  @Test
  void toString_whenTypicalFields_expectContainsKeySegments() {
    // Arrange
    CompressionOutput out =
        new CompressionOutput(
            new FakeBucket("B1"),
            COMPRESSOR_TYPE.GZIP,
            new HashResult[] {hr(HashType.SHA256, (byte) 9), hr(HashType.SHA1, (byte) 8)});

    // Act
    String s = out.toString();

    // Assert (structure only; element toStrings may vary)
    assertNotNull(s);
    assertTrue(s.startsWith("CompressionOutput["));
    assertTrue(s.contains("data=FakeBucket(B1)"));
    assertTrue(s.contains("bestCodec=GZIP"));
    assertTrue(s.contains("hashes=["));
    assertTrue(s.endsWith("]"));
  }

  @Test
  void toString_whenNullFields_expectContainsNullIndicators() {
    // Arrange
    CompressionOutput out = new CompressionOutput(null, null, null);

    // Act
    String s = out.toString();

    // Assert
    assertTrue(s.contains("bestCodec=null"));
    assertTrue(s.contains("hashes=null"));
  }
}
