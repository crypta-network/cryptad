package network.crypta.support.io;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import network.crypta.crypt.AEADCryptBucket;
import network.crypta.crypt.EncryptedRandomAccessBucket;
import network.crypta.crypt.EncryptedRandomAccessBuffer;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.SHA256;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.api.RandomAccessBuffer;
import network.crypta.support.math.MersenneTwister;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility methods for working with {@link Bucket} and related buffer/bucket abstractions.
 *
 * <p>All methods are stateless and thread-safe with respect to this class, but callers are
 * responsible for ensuring that individual {@code Bucket}/{@code RandomAccessBuffer} instances are
 * not concurrently modified in ways that violate their contracts. Unless otherwise noted, I/O
 * operations use unbuffered streams obtained from the underlying objects and close them when
 * finished.
 */
public class BucketTools {
  private static final Logger LOG = LoggerFactory.getLogger(BucketTools.class);

  private static final int BUFFER_SIZE = 64 * 1024;
  private static final String MOVED_LITERAL = " (moved ";
  private static final String UNABLE_TO_READ_FROM_LITERAL = "): unable to read from ";
  // Remaining root-owned bucket/buffer implementations are restored reflectively during the
  // extraction so this leaf no longer compiles against root main sources.
  private static final String FILE_BUCKET_CLASS = "network.crypta.support.io.FileBucket";
  private static final String PERSISTENT_TEMP_FILE_BUCKET_CLASS =
      "network.crypta.support.io.PersistentTempFileBucket";
  private static final String DELAYED_FREE_BUCKET_CLASS =
      "network.crypta.support.io.DelayedFreeBucket";
  private static final String DELAYED_FREE_RANDOM_ACCESS_BUCKET_CLASS =
      "network.crypta.support.io.DelayedFreeRandomAccessBucket";
  private static final String NO_FREE_BUCKET_CLASS = "network.crypta.support.io.NoFreeBucket";
  private static final String PADDED_EPHEMERALLY_ENCRYPTED_BUCKET_CLASS =
      "network.crypta.support.io.PaddedEphemerallyEncryptedBucket";
  private static final String PADDED_BUCKET_CLASS = "network.crypta.support.io.PaddedBucket";
  private static final String PADDED_RANDOM_ACCESS_BUCKET_CLASS =
      "network.crypta.support.io.PaddedRandomAccessBucket";
  private static final String RAF_BUCKET_CLASS = "network.crypta.support.io.RAFBucket";
  private static final String POOLED_FILE_RANDOM_ACCESS_BUFFER_CLASS =
      "network.crypta.support.io.PooledFileRandomAccessBuffer";
  private static final String FILE_RANDOM_ACCESS_BUFFER_CLASS =
      "network.crypta.support.io.FileRandomAccessBuffer";
  private static final String READ_ONLY_RANDOM_ACCESS_BUFFER_CLASS =
      "network.crypta.support.io.ReadOnlyRandomAccessBuffer";
  private static final String DELAYED_FREE_RANDOM_ACCESS_BUFFER_CLASS =
      "network.crypta.support.io.DelayedFreeRandomAccessBuffer";
  private static final String PADDED_RANDOM_ACCESS_BUFFER_CLASS =
      "network.crypta.support.io.PaddedRandomAccessBuffer";

  private BucketTools() {}

  /**
   * Copies all data from {@code src}'s input stream to {@code dst}'s output stream.
   *
   * <p>This method reads until EOF on {@code src}. It does not attempt to verify the expected size
   * and does not truncate or pad the destination.
   *
   * @param src the source bucket to read from; must be readable
   * @param dst the destination bucket to write to; must be writable
   * @throws IOException if reading from {@code src} or writing to {@code dst} fails
   */
  public static void copy(Bucket src, Bucket dst) throws IOException {
    try (OutputStream out = dst.getOutputStreamUnbuffered();
        InputStream in = src.getInputStreamUnbuffered();
        ReadableByteChannel readChannel = Channels.newChannel(in);
        WritableByteChannel writeChannel = Channels.newChannel(out)) {

      // No benefit to allocateDirect() as streams are wrapped; using a direct buffer here would
      // provide no gain and risks unnecessary native memory retention.
      ByteBuffer buffer = ByteBuffer.allocate(BUFFER_SIZE);
      while (readChannel.read(buffer) != -1) {
        buffer.flip();
        while (buffer.hasRemaining()) writeChannel.write(buffer);
        buffer.clear();
      }
    }
  }

  /**
   * Writes {@code size} zero bytes to the end of the bucket.
   *
   * <p>The method opens an unbuffered output stream and writes zero-filled blocks until the
   * requested length is produced. It does not attempt to seek; callers decide where the bucket
   * writes go, according to the implementation.
   *
   * @param b the bucket to pad with zero bytes
   * @param size the number of zero bytes to write; must be non-negative
   * @throws IOException if writing to {@code b} fails
   * @throws IllegalArgumentException if {@code size} is negative
   */
  public static void zeroPad(Bucket b, long size) throws IOException {
    try (OutputStream out = b.getOutputStreamUnbuffered()) {
      // Initialized to zero by default.
      byte[] buffer = new byte[16384];

      long count = 0;
      while (count < size) {
        long nRequired = buffer.length;
        if (nRequired > size - count) {
          nRequired = size - count;
        }
        out.write(buffer, 0, (int) nRequired);
        count += nRequired;
      }
    }
  }

  /**
   * Copies {@code nBytes} from {@code from} to {@code to} and then pads with zeroes up to {@code
   * blockSize}.
   *
   * <p>The destination receives exactly {@code blockSize} bytes when the method returns. If the
   * source does not contain {@code nBytes} bytes, an {@link IOException} is thrown.
   *
   * @param from the source bucket
   * @param to the destination bucket
   * @param nBytes the number of bytes to copy from {@code from}; must be {@code <= blockSize}
   * @param blockSize the final size to reach by zero padding
   * @throws IllegalArgumentException if {@code nBytes > blockSize}
   * @throws IOException if reading from {@code from} or writing to {@code to} fails
   */
  public static void paddedCopy(Bucket from, Bucket to, long nBytes, int blockSize)
      throws IOException {

    if (nBytes > blockSize) {
      throw new IllegalArgumentException("nBytes > blockSize");
    }

    try (OutputStream out = to.getOutputStreamUnbuffered();
        InputStream in = from.getInputStreamUnbuffered()) {

      byte[] buffer = new byte[16384];

      long count = 0;
      while (count != nBytes) {
        long nRequired = nBytes - count;
        if (nRequired > buffer.length) {
          nRequired = buffer.length;
        }
        long nRead = in.read(buffer, 0, (int) nRequired);
        if (nRead == -1) {
          throw new IOException("Not enough data in source bucket.");
        }
        out.write(buffer, 0, (int) nRead);
        count += nRead;
      }

      if (count < blockSize) {
        writeZeroPadding(out, buffer, count, blockSize, nBytes);
      }
    }
  }

  /*
   * Writes zero padding to reach the requested block size.
   *
   * Private helper for {@link #paddedCopy(Bucket, Bucket, long, int)}. Assumes that {@code count}
   * is the number of bytes already written and fills the remainder with zeroes in chunks up to the
   * provided temporary buffer size.
   */
  private static void writeZeroPadding(
      OutputStream out, byte[] buffer, long count, long blockSize, long nBytes) throws IOException {
    long padLength = buffer.length;
    if (padLength > blockSize - nBytes) {
      padLength = blockSize - nBytes;
    }
    for (int i = 0; i < padLength; i++) {
      buffer[i] = 0;
    }

    while (count != blockSize) {
      long nRequired = blockSize - count;
      if (blockSize - count > buffer.length) {
        nRequired = buffer.length;
      }
      out.write(buffer, 0, (int) nRequired);
      count += nRequired;
    }
  }

  /**
   * Creates an array of new buckets of identical size.
   *
   * @param bf the factory used to create buckets
   * @param count the number of buckets to create; must be non-negative
   * @param size the size of each bucket, passed to the factory
   * @return an array of {@code count} buckets
   * @throws IOException if the factory fails to create a bucket
   * @throws IllegalArgumentException if {@code count} is negative
   */
  @SuppressWarnings({"java:S2095", "squid:S2095", "resource"})
  public static Bucket[] makeBuckets(BucketFactory bf, int count, int size) throws IOException {
    Bucket[] ret = new Bucket[count];
    for (int i = 0; i < count; i++) {
      ret[i] = bf.makeBucket(size);
    }
    return ret;
  }

  /**
   * Returns the indices of {@code null} entries in the given bucket array.
   *
   * @param array the array to scan; must not be {@code null}
   * @return a new int array containing the zero-based positions of all {@code null} elements, in
   *     ascending order
   */
  public static int[] nullIndices(Bucket[] array) {
    List<Integer> list = new ArrayList<>();
    for (int i = 0; i < array.length; i++) {
      if (array[i] == null) {
        list.add(i);
      }
    }

    int[] ret = new int[list.size()];
    for (int i = 0; i < ret.length; i++) {
      ret[i] = list.get(i);
    }
    return ret;
  }

  /**
   * Returns the indices of non-{@code null} entries in the given bucket array.
   *
   * @param array the array to scan; must not be {@code null}
   * @return a new int array containing the zero-based positions of all non-{@code null} elements,
   *     in ascending order
   */
  public static int[] nonNullIndices(Bucket[] array) {
    List<Integer> list = new ArrayList<>();
    for (int i = 0; i < array.length; i++) {
      if (array[i] != null) {
        list.add(i);
      }
    }

    int[] ret = new int[list.size()];
    for (int i = 0; i < ret.length; i++) {
      ret[i] = list.get(i);
    }
    return ret;
  }

  /**
   * Returns a new array containing only the non-{@code null} buckets from the input array.
   *
   * @param array the array to filter; must not be {@code null}
   * @return a compact array of the non-{@code null} elements, preserving order
   */
  public static Bucket[] nonNullBuckets(Bucket[] array) {
    List<Bucket> list = new ArrayList<>(array.length);
    for (Bucket bucket : array) {
      if (bucket != null) {
        list.add(bucket);
      }
    }

    Bucket[] ret = new Bucket[list.size()];
    return list.toArray(ret);
  }

  /**
   * Reads the entire bucket and returns its contents as a new byte array.
   *
   * <p>Use only for small data. Callers must ensure the bucket is not modified concurrently while
   * reading, otherwise the result is undefined.
   *
   * @throws IOException If there was an error reading from the bucket.
   * @throws OutOfMemoryError If it was not possible to allocate enough memory to contain the entire
   *     bucket.
   */
  public static byte[] toByteArray(Bucket bucket) throws IOException {
    long size = bucket.size();
    if (size > Integer.MAX_VALUE) throw new OutOfMemoryError();
    byte[] data = new byte[(int) size];
    try (InputStream is = bucket.getInputStreamUnbuffered();
        DataInputStream dis = new DataInputStream(is)) {
      dis.readFully(data);
    }
    return data;
  }

  /**
   * Reads the bucket into the provided output buffer.
   *
   * @param bucket the source bucket to read from
   * @param output the destination byte array; must have length at least {@code bucket.size()}
   * @return the number of bytes copied
   * @throws IllegalArgumentException if the bucket content does not fit into {@code output}
   * @throws IOException if reading from the bucket fails
   */
  public static int toByteArray(Bucket bucket, byte[] output) throws IOException {
    long size = bucket.size();
    if (size > output.length)
      throw new IllegalArgumentException("Data does not fit in provided buffer");
    try (InputStream is = bucket.getInputStreamUnbuffered()) {
      int moved = 0;
      while (true) {
        if (moved == size) return moved;
        int x = is.read(output, moved, (int) (size - moved));
        if (x == -1) return moved;
        moved += x;
      }
    }
  }

  /**
   * Creates a read-only {@link RandomAccessBucket} from the given byte array.
   *
   * @param bucketFactory factory used to allocate the bucket
   * @param data the bytes to copy into the bucket
   * @return a bucket containing {@code data} and marked read-only
   * @throws IOException if writing to the bucket fails
   */
  public static RandomAccessBucket makeImmutableBucket(BucketFactory bucketFactory, byte[] data)
      throws IOException {
    return makeImmutableBucket(bucketFactory, data, data.length);
  }

  /**
   * Creates a read-only {@link RandomAccessBucket} from the first {@code length} bytes of a byte
   * array.
   *
   * @param bucketFactory factory used to allocate the bucket
   * @param data the source byte array
   * @param length the number of bytes to copy from {@code data}
   * @return a bucket containing the selected bytes and marked read-only
   * @throws IOException if writing to the bucket fails
   * @throws IndexOutOfBoundsException if {@code length} is negative or greater than {@code
   *     data.length}
   */
  public static RandomAccessBucket makeImmutableBucket(
      BucketFactory bucketFactory, byte[] data, int length) throws IOException {
    return makeImmutableBucket(bucketFactory, data, 0, length);
  }

  /**
   * Creates a read-only {@link RandomAccessBucket} from a range of byte arrays.
   *
   * @param bucketFactory factory used to allocate the bucket
   * @param data the source array
   * @param offset the starting index in {@code data}
   * @param length the number of bytes to copy starting at {@code offset}
   * @return a bucket containing the selected range and marked read-only
   * @throws IOException if writing to the bucket fails
   * @throws IndexOutOfBoundsException if the range is invalid
   */
  public static RandomAccessBucket makeImmutableBucket(
      BucketFactory bucketFactory, byte[] data, int offset, int length) throws IOException {
    RandomAccessBucket bucket = bucketFactory.makeBucket(length);
    try (OutputStream os = bucket.getOutputStreamUnbuffered()) {
      os.write(data, offset, length);
    }
    bucket.setReadOnly();
    return bucket;
  }

  /**
   * Computes the SHA-256 hash of the content of a bucket.
   *
   * @param data the bucket to hash
   * @return the 32-byte SHA-256 digest
   * @throws IOException if reading from {@code data} fails
   */
  public static byte[] hash(Bucket data) throws IOException {
    try (InputStream is = data.getInputStreamUnbuffered()) {
      MessageDigest md = SHA256.getMessageDigest();
      long bucketLength = data.size();
      long bytesRead = 0;
      byte[] buf = new byte[BUFFER_SIZE];
      while ((bytesRead < bucketLength) || (bucketLength == -1)) {
        int readBytes = is.read(buf);
        if (readBytes < 0) break;
        bytesRead += readBytes;
        if (readBytes > 0) md.update(buf, 0, readBytes);
      }
      if ((bytesRead < bucketLength) && (bucketLength > 0)) throw new EOFException();
      if ((bytesRead != bucketLength) && (bucketLength > 0))
        throw new IOException(
            "Read " + bytesRead + " but bucket length " + bucketLength + " on " + data + '!');
      return md.digest();
    }
  }

  /**
   * Copies up to {@code truncateLength} bytes from a bucket to an {@link OutputStream}.
   *
   * <p>If {@code truncateLength} is negative, all data is copied until EOF. If a positive limit is
   * specified but fewer bytes are available, an {@link IOException} is thrown.
   *
   * @param decodedData the source bucket
   * @param os the destination stream
   * @param truncateLength the maximum number of bytes to move; negative to copy all
   * @return the number of bytes written to {@code os}
   * @throws IOException if reading from the bucket or writing to the stream fails
   */
  public static long copyTo(Bucket decodedData, OutputStream os, long truncateLength)
      throws IOException {
    if (truncateLength == 0) return 0;
    if (truncateLength < 0) truncateLength = Long.MAX_VALUE;
    try (InputStream is = decodedData.getInputStreamUnbuffered()) {
      int bufferSize = BUFFER_SIZE;
      if (truncateLength < bufferSize) bufferSize = (int) truncateLength;
      byte[] buf = new byte[bufferSize];
      long moved = 0;
      while (moved < truncateLength) {
        // Keep the (int) cast outside Math.min(): casting a large long inside can wrap to a
        // negative value.
        int bytes = (int) Math.min(buf.length, truncateLength - moved);
        if (bytes <= 0)
          throw new IllegalStateException(
              "bytes=" + bytes + ", truncateLength=" + truncateLength + ", moved=" + moved);
        bytes = is.read(buf, 0, bytes);
        if (bytes <= 0) {
          if (truncateLength == Long.MAX_VALUE) break;
          throw new IOException(
              "Could not move required quantity of data in copyTo: "
                  + bytes
                  + MOVED_LITERAL
                  + moved
                  + " of "
                  + truncateLength
                  + UNABLE_TO_READ_FROM_LITERAL
                  + is);
        }
        os.write(buf, 0, bytes);
        moved += bytes;
      }
      os.flush();
      return moved;
    }
  }

  /**
   * Copies up to {@code truncateLength} bytes from an {@link InputStream} into a {@link Bucket}.
   *
   * <p>If {@code truncateLength} is negative, the method copies until EOF.
   *
   * @param bucket the destination bucket to write into
   * @param is the source stream
   * @param truncateLength maximum number of bytes to copy; negative to copy all
   * @throws IOException if reading from {@code is} or writing to {@code bucket} fails
   */
  public static void copyFrom(Bucket bucket, InputStream is, long truncateLength)
      throws IOException {
    try (OutputStream os = bucket.getOutputStreamUnbuffered()) {
      byte[] buf = new byte[BUFFER_SIZE];
      if (truncateLength < 0) truncateLength = Long.MAX_VALUE;
      long moved = 0;
      while (moved < truncateLength) {
        // Keep the (int) cast outside Math.min(): casting a large long inside can wrap to a
        // negative value.
        int bytes = (int) Math.min(buf.length, truncateLength - moved);
        if (bytes <= 0)
          throw new IllegalStateException(
              "bytes=" + bytes + ", truncateLength=" + truncateLength + ", moved=" + moved);
        bytes = is.read(buf, 0, bytes);
        if (bytes <= 0) {
          if (truncateLength == Long.MAX_VALUE) break;
          throw new IOException(
              "Could not move required quantity of data in copyFrom: "
                  + bytes
                  + MOVED_LITERAL
                  + moved
                  + " of "
                  + truncateLength
                  + UNABLE_TO_READ_FROM_LITERAL
                  + is);
        }
        os.write(buf, 0, bytes);
        moved += bytes;
      }
    }
  }

  /**
   * Splits a bucket into a sequence of read-only chunk buckets.
   *
   * <p>When {@code origData} is a {@code FileBucket} and {@code persistent} is {@code true}, the
   * method uses the underlying file and returns efficient {@code ReadOnlyFileSliceBucket}s. In all
   * other cases it creates new buckets via {@code bf} and copies the data into them.
   *
   * <p>This method allocates a temporary buffer of size {@code splitSize}.
   *
   * @param origData the source bucket
   * @param splitSize the number of bytes per resulting bucket; the last bucket may be smaller
   * @param bf the factory used for creating new buckets when copying is required
   * @param freeData whether to call {@link Bucket#free()} on {@code origData} after splitting
   * @param persistent if {@code true} and {@code origData} is a {@code FileBucket}, returns file
   *     slice buckets; otherwise new buckets are created and populated
   * @return an array of buckets covering the full content of {@code origData}
   * @throws IllegalArgumentException if the computed number of buckets overflows an int
   * @throws IOException if reading from {@code origData} or writing to a created bucket fails
   */
  @SuppressWarnings({"java:S2095", "squid:S2095", "resource"})
  public static Bucket[] split(
      Bucket origData, int splitSize, BucketFactory bf, boolean freeData, boolean persistent)
      throws IOException {
    if (isReflectiveInstance(origData, FILE_BUCKET_CLASS)) {
      if (freeData) {
        LOG.error(
            "Asked to free data when splitting a FileBucket ?!?!? Not freeing as this would clobber"
                + " the split result...");
      }
      Bucket[] buckets =
          invokeBucketArrayMethod(origData, "split", new Class<?>[] {int.class}, splitSize);
      if (persistent) return buckets;
    }
    long length = origData.size();
    if (length > ((long) Integer.MAX_VALUE) * splitSize)
      throw new IllegalArgumentException("Way too big!: " + length + " for " + splitSize);
    int bucketCount = (int) (length / splitSize);
    if (length % splitSize > 0) bucketCount++;
    if (LOG.isDebugEnabled())
      LOG.debug("Splitting bucket {} of size {} into {} buckets", origData, length, bucketCount);
    Bucket[] buckets = new Bucket[bucketCount];
    try (InputStream is = origData.getInputStreamUnbuffered();
        DataInputStream dis = new DataInputStream(is)) {
      long remainingLength = length;
      byte[] buf = new byte[splitSize];
      for (int i = 0; i < bucketCount; i++) {
        int len = (int) Math.min(splitSize, remainingLength);
        Bucket bucket = bf.makeBucket(len);
        buckets[i] = bucket;
        dis.readFully(buf, 0, len);
        remainingLength -= len;
        try (OutputStream os = bucket.getOutputStreamUnbuffered()) {
          os.write(buf, 0, len);
        }
      }
    }
    if (freeData) origData.free();
    return buckets;
  }

  /**
   * Pads a bucket to {@code blockLength} by appending deterministic pseudo-random bytes.
   *
   * <p>The padding bytes are generated by seeding a {@link MersenneTwister} with the SHA-256 of the
   * original content. This is not cryptographically secure and is intended only to fill the block
   * with non-zero-looking data.
   *
   * @param oldBucket the source bucket to copy from
   * @param blockLength the final size of the returned bucket
   * @param bf factory used to create the destination bucket
   * @param length the number of bytes to copy from {@code oldBucket} before padding
   * @return a new bucket of size {@code blockLength}
   * @throws IOException if reading from {@code oldBucket} or writing to the destination fails
   */
  public static Bucket pad(Bucket oldBucket, int blockLength, BucketFactory bf, int length)
      throws IOException {
    byte[] hash = BucketTools.hash(oldBucket);
    Bucket b = bf.makeBucket(blockLength);
    MersenneTwister mt = MersenneTwister.createUnsynchronized(hash);
    try (OutputStream os = b.getOutputStreamUnbuffered()) {
      BucketTools.copyTo(oldBucket, os, length);
      byte[] buf = new byte[BUFFER_SIZE];
      int x = length;
      while (x < blockLength) {
        int remaining = blockLength - x;
        int thisCycle = Math.min(remaining, buf.length);
        mt.nextBytes(buf);
        os.write(buf, 0, thisCycle);
        x += thisCycle;
      }
    }
    if (b.size() != blockLength)
      throw new IllegalStateException(
          "The bucket's size is " + b.size() + " whereas it should be " + blockLength + '!');
    return b;
  }

  static final ArrayBucketFactory ARRAY_FACTORY = new ArrayBucketFactory();

  /**
   * Pads a byte array to {@code blockSize} using the same algorithm as {@link #pad(Bucket, int,
   * BucketFactory, int)} and returns the new bytes.
   *
   * @param orig the original bytes
   * @param blockSize the final size
   * @param length the number of bytes from {@code orig} to copy before padding
   * @return a new array of size {@code blockSize}
   * @throws IOException if an underlying bucket operation fails
   */
  public static byte[] pad(byte[] orig, int blockSize, int length) throws IOException {
    ArrayBucket b = new ArrayBucket(orig);
    Bucket ret = BucketTools.pad(b, blockSize, ARRAY_FACTORY, length);
    return BucketTools.toByteArray(ret);
  }

  /**
   * Compares two buckets for bytewise equality.
   *
   * @param a the first bucket
   * @param b the second bucket
   * @return {@code true} if both buckets have the same size and identical content
   * @throws IOException if reading either bucket fails
   */
  public static boolean equalBuckets(Bucket a, Bucket b) throws IOException {
    if (a.size() != b.size()) return false;
    long size = a.size();
    try (InputStream aIn = a.getInputStreamUnbuffered();
        InputStream bIn = b.getInputStreamUnbuffered()) {
      return equalStreams(aIn, bIn, size);
    }
  }

  // Note: Random-based test helpers live under src/test (FileTestUtils).

  private static final SecureRandom FILL_SEED_GENERATOR = new SecureRandom();

  /**
   * Fills a bucket with pseudo-random bytes.
   *
   * <p>Uses the legacy Mersenne-Twister-backed filler to write {@code length} bytes. The data is
   * suitable for testing or obfuscating patterns but is not cryptographically secure.
   *
   * @param bucket the destination bucket
   * @param length the number of bytes to write
   * @throws IOException if writing fails
   */
  public static void fill(Bucket bucket, long length) throws IOException {
    try (OutputStream os = bucket.getOutputStreamUnbuffered()) {
      fill(os, length);
    }
  }

  /**
   * Copies up to {@code truncateLength} bytes from a bucket to a {@link RandomAccessBuffer} at a
   * given offset.
   *
   * @param bucket the source bucket
   * @param raf the destination random access buffer
   * @param fileOffset the starting offset within {@code raf}
   * @param truncateLength the maximum number of bytes to transfer, or -1 to copy all available
   * @return the number of bytes written
   * @throws IOException if reading from the bucket or writing to the buffer fails
   */
  public static long copyTo(
      Bucket bucket, RandomAccessBuffer raf, long fileOffset, long truncateLength)
      throws IOException {
    if (truncateLength == 0) return 0;
    if (truncateLength < 0) truncateLength = Long.MAX_VALUE;
    try (InputStream is = bucket.getInputStreamUnbuffered()) {
      int bufferSize = BUFFER_SIZE;
      if (truncateLength < bufferSize) bufferSize = (int) truncateLength;
      byte[] buf = new byte[bufferSize];
      long moved = 0;
      while (moved < truncateLength) {
        // Keep the (int) cast outside Math.min(): casting a large long inside can wrap to a
        // negative value.
        int bytes = (int) Math.min(buf.length, truncateLength - moved);
        if (bytes <= 0)
          throw new IllegalStateException(
              "bytes=" + bytes + ", truncateLength=" + truncateLength + ", moved=" + moved);
        bytes = is.read(buf, 0, bytes);
        if (bytes <= 0) {
          if (truncateLength == Long.MAX_VALUE) break;
          throw new IOException(
              "Could not move required quantity of data in copyTo: "
                  + bytes
                  + MOVED_LITERAL
                  + moved
                  + " of "
                  + truncateLength
                  + UNABLE_TO_READ_FROM_LITERAL
                  + is);
        }
        raf.pwrite(fileOffset, buf, 0, bytes);
        moved += bytes;
        fileOffset += bytes;
      }
      return moved;
    }
  }

  private static void fill(OutputStream os, long length) throws IOException {
    byte[] seed = new byte[16];
    FILL_SEED_GENERATOR.nextBytes(seed);
    writeRandomBytes(os, MersenneTwister.createUnsynchronized(seed), length);
  }

  private static void writeRandomBytes(OutputStream os, Random random, long length)
      throws IOException {
    byte[] buffer = new byte[(int) Math.min(length, BUFFER_SIZE)];
    long remaining = length;
    while (remaining > 0) {
      random.nextBytes(buffer);
      int writeLength = (int) Math.min(remaining, BUFFER_SIZE);
      os.write(buffer, 0, writeLength);
      remaining -= writeLength;
    }
  }

  private static boolean equalStreams(InputStream a, InputStream b, long size) throws IOException {
    byte[] aBuffer = new byte[BUFFER_SIZE];
    byte[] bBuffer = new byte[BUFFER_SIZE];
    DataInputStream aIn = new DataInputStream(a);
    DataInputStream bIn = new DataInputStream(b);
    long checked = 0;
    while (checked < size) {
      int toRead = (int) Math.min(BUFFER_SIZE, size - checked);
      aIn.readFully(aBuffer, 0, toRead);
      bIn.readFully(bBuffer, 0, toRead);
      if (!MessageDigest.isEqual(aBuffer, bBuffer)) return false;
      checked += toRead;
    }
    return true;
  }

  private static boolean isReflectiveInstance(Object value, String className) {
    for (Class<?> type = value.getClass(); type != null; type = type.getSuperclass()) {
      if (type.getName().equals(className)) {
        return true;
      }
    }
    return false;
  }

  private static boolean magicMatches(String className, int magic) {
    try {
      Field magicField = loadClass(className).getDeclaredField("MAGIC");
      magicField.setAccessible(true);
      return magicField.getInt(null) == magic;
    } catch (ReflectiveOperationException e) {
      return false;
    }
  }

  private static Class<?> loadClass(String className) throws ClassNotFoundException {
    return Class.forName(className, true, BucketTools.class.getClassLoader());
  }

  private static Bucket[] invokeBucketArrayMethod(
      Object target, String methodName, Class<?>[] parameterTypes, Object... args)
      throws IOException {
    return invokeReflectiveMethod(target, methodName, Bucket[].class, parameterTypes, args);
  }

  private static RandomAccessBucket invokeRandomAccessBucketMethod(
      Object target, String methodName, Class<?>[] parameterTypes, Object... args)
      throws IOException {
    return invokeReflectiveMethod(
        target, methodName, RandomAccessBucket.class, parameterTypes, args);
  }

  private static <T> T invokeReflectiveMethod(
      Object target,
      String methodName,
      Class<T> expectedType,
      Class<?>[] parameterTypes,
      Object... args)
      throws IOException {
    try {
      Method method = target.getClass().getMethod(methodName, parameterTypes);
      method.setAccessible(true);
      return expectedType.cast(method.invoke(target, args));
    } catch (InvocationTargetException e) {
      rethrowIoCause(target.getClass().getName() + "#" + methodName, e.getCause());
      throw new IllegalStateException("Unreachable");
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(
          "Failed to invoke " + methodName + " on " + target.getClass().getName(), e);
    }
  }

  private static Bucket instantiateBucket(
      String className, Class<?>[] parameterTypes, Object... args)
      throws IOException, StorageFormatException, ResumeFailedException {
    return instantiateReflectively(className, Bucket.class, parameterTypes, args);
  }

  private static LockableRandomAccessBuffer instantiateRandomAccessBuffer(
      String className, Class<?>[] parameterTypes, Object... args)
      throws IOException, StorageFormatException, ResumeFailedException {
    return instantiateReflectively(
        className, LockableRandomAccessBuffer.class, parameterTypes, args);
  }

  private static <T> T instantiateReflectively(
      String className, Class<T> expectedType, Class<?>[] parameterTypes, Object... args)
      throws IOException, StorageFormatException, ResumeFailedException {
    try {
      Constructor<?> constructor = loadClass(className).getDeclaredConstructor(parameterTypes);
      constructor.setAccessible(true);
      return expectedType.cast(constructor.newInstance(args));
    } catch (InvocationTargetException e) {
      rethrowReflectiveCause(className, e.getCause());
      throw new IllegalStateException("Unreachable");
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("Failed to instantiate " + className, e);
    }
  }

  private static void rethrowIoCause(String description, Throwable cause) throws IOException {
    if (cause instanceof IOException ioException) {
      throw ioException;
    }
    if (cause instanceof RuntimeException runtimeException) {
      throw runtimeException;
    }
    if (cause instanceof Error error) {
      throw error;
    }
    throw new IllegalStateException("Failed to invoke " + description, cause);
  }

  private static void rethrowReflectiveCause(String className, Throwable cause)
      throws IOException, StorageFormatException, ResumeFailedException {
    if (cause instanceof IOException ioException) {
      throw ioException;
    }
    if (cause instanceof StorageFormatException storageFormatException) {
      throw storageFormatException;
    }
    if (cause instanceof ResumeFailedException resumeFailedException) {
      throw resumeFailedException;
    }
    if (cause instanceof RuntimeException runtimeException) {
      throw runtimeException;
    }
    if (cause instanceof Error error) {
      throw error;
    }
    throw new IllegalStateException("Failed to instantiate " + className, cause);
  }

  /**
   * Restores a {@link Bucket} from a binary stream written by {@code Bucket.storeTo()}.
   *
   * <p>The method reads a type {@code magic} value and dispatches to the appropriate bucket
   * implementation for deserialization.
   *
   * @param dis the input stream to read from
   * @param fg filename generator used by file-backed buckets
   * @param persistentFileTracker tracker used to manage persistent files
   * @param masterKey master secret used to decrypt encrypted buckets when required
   * @return the restored bucket instance
   * @throws IOException if reading from the stream fails
   * @throws StorageFormatException if the stream contains an unknown or invalid format
   * @throws ResumeFailedException if resuming a persistent artifact fails
   */
  public static Bucket restoreFrom(
      DataInputStream dis,
      FilenameGenerator fg,
      PersistentFileTracker persistentFileTracker,
      MasterSecret masterKey)
      throws IOException, StorageFormatException, ResumeFailedException {
    int magic = dis.readInt();
    if (magic == AEADCryptBucket.MAGIC) {
      return new AEADCryptBucket(dis, fg, persistentFileTracker, masterKey);
    }
    if (magicMatches(FILE_BUCKET_CLASS, magic)) {
      return instantiateBucket(FILE_BUCKET_CLASS, new Class<?>[] {DataInputStream.class}, dis);
    }
    if (magicMatches(PERSISTENT_TEMP_FILE_BUCKET_CLASS, magic)) {
      return instantiateBucket(
          PERSISTENT_TEMP_FILE_BUCKET_CLASS, new Class<?>[] {DataInputStream.class}, dis);
    }
    if (magicMatches(DELAYED_FREE_BUCKET_CLASS, magic)) {
      return instantiateBucket(
          DELAYED_FREE_BUCKET_CLASS,
          new Class<?>[] {
            DataInputStream.class,
            FilenameGenerator.class,
            PersistentFileTracker.class,
            MasterSecret.class
          },
          dis,
          fg,
          persistentFileTracker,
          masterKey);
    }
    if (magicMatches(DELAYED_FREE_RANDOM_ACCESS_BUCKET_CLASS, magic)) {
      return instantiateBucket(
          DELAYED_FREE_RANDOM_ACCESS_BUCKET_CLASS,
          new Class<?>[] {
            DataInputStream.class,
            FilenameGenerator.class,
            PersistentFileTracker.class,
            MasterSecret.class
          },
          dis,
          fg,
          persistentFileTracker,
          masterKey);
    }
    if (magicMatches(NO_FREE_BUCKET_CLASS, magic)) {
      return instantiateBucket(
          NO_FREE_BUCKET_CLASS,
          new Class<?>[] {
            DataInputStream.class,
            FilenameGenerator.class,
            PersistentFileTracker.class,
            MasterSecret.class
          },
          dis,
          fg,
          persistentFileTracker,
          masterKey);
    }
    if (magicMatches(PADDED_EPHEMERALLY_ENCRYPTED_BUCKET_CLASS, magic)) {
      return instantiateBucket(
          PADDED_EPHEMERALLY_ENCRYPTED_BUCKET_CLASS,
          new Class<?>[] {
            DataInputStream.class,
            FilenameGenerator.class,
            PersistentFileTracker.class,
            MasterSecret.class
          },
          dis,
          fg,
          persistentFileTracker,
          masterKey);
    }
    if (magic == ReadOnlyFileSliceBucket.MAGIC) {
      return new ReadOnlyFileSliceBucket(dis);
    }
    if (magicMatches(PADDED_BUCKET_CLASS, magic)) {
      return instantiateBucket(
          PADDED_BUCKET_CLASS,
          new Class<?>[] {
            DataInputStream.class,
            FilenameGenerator.class,
            PersistentFileTracker.class,
            MasterSecret.class
          },
          dis,
          fg,
          persistentFileTracker,
          masterKey);
    }
    if (magicMatches(PADDED_RANDOM_ACCESS_BUCKET_CLASS, magic)) {
      return instantiateBucket(
          PADDED_RANDOM_ACCESS_BUCKET_CLASS,
          new Class<?>[] {
            DataInputStream.class,
            FilenameGenerator.class,
            PersistentFileTracker.class,
            MasterSecret.class
          },
          dis,
          fg,
          persistentFileTracker,
          masterKey);
    }
    if (magicMatches(RAF_BUCKET_CLASS, magic)) {
      return instantiateBucket(
          RAF_BUCKET_CLASS,
          new Class<?>[] {
            DataInputStream.class,
            FilenameGenerator.class,
            PersistentFileTracker.class,
            MasterSecret.class
          },
          dis,
          fg,
          persistentFileTracker,
          masterKey);
    }
    if (magic == EncryptedRandomAccessBucket.MAGIC) {
      return new EncryptedRandomAccessBucket(dis, fg, persistentFileTracker, masterKey);
    }
    throw new StorageFormatException("Unknown magic value for bucket " + magic);
  }

  /**
   * Restores a {@link LockableRandomAccessBuffer} from a stream written by {@code storeTo()}.
   *
   * @param dis the input stream to read from
   * @param fg filename generator used by file-backed buffers
   * @param persistentFileTracker tracker used to manage persistent files
   * @param masterSecret master key used by encrypted buffers
   * @return the restored buffer
   * @throws IOException if reading from the stream fails
   * @throws StorageFormatException if the stream contains an unknown or invalid format
   * @throws ResumeFailedException if resuming a persistent artifact fails
   */
  public static LockableRandomAccessBuffer restoreRAFFrom(
      DataInputStream dis,
      FilenameGenerator fg,
      PersistentFileTracker persistentFileTracker,
      MasterSecret masterSecret)
      throws IOException, StorageFormatException, ResumeFailedException {
    int magic = dis.readInt();
    if (magicMatches(POOLED_FILE_RANDOM_ACCESS_BUFFER_CLASS, magic)) {
      return instantiateRandomAccessBuffer(
          POOLED_FILE_RANDOM_ACCESS_BUFFER_CLASS,
          new Class<?>[] {
            DataInputStream.class, PersistentFilenameGenerator.class, PersistentFileTracker.class
          },
          dis,
          fg,
          persistentFileTracker);
    }
    if (magicMatches(FILE_RANDOM_ACCESS_BUFFER_CLASS, magic)) {
      return instantiateRandomAccessBuffer(
          FILE_RANDOM_ACCESS_BUFFER_CLASS, new Class<?>[] {DataInputStream.class}, dis);
    }
    if (magicMatches(READ_ONLY_RANDOM_ACCESS_BUFFER_CLASS, magic)) {
      return instantiateRandomAccessBuffer(
          READ_ONLY_RANDOM_ACCESS_BUFFER_CLASS,
          new Class<?>[] {
            DataInputStream.class,
            FilenameGenerator.class,
            PersistentFileTracker.class,
            MasterSecret.class
          },
          dis,
          fg,
          persistentFileTracker,
          masterSecret);
    }
    if (magicMatches(DELAYED_FREE_RANDOM_ACCESS_BUFFER_CLASS, magic)) {
      return instantiateRandomAccessBuffer(
          DELAYED_FREE_RANDOM_ACCESS_BUFFER_CLASS,
          new Class<?>[] {
            DataInputStream.class,
            FilenameGenerator.class,
            PersistentFileTracker.class,
            MasterSecret.class
          },
          dis,
          fg,
          persistentFileTracker,
          masterSecret);
    }
    if (magic == EncryptedRandomAccessBuffer.MAGIC) {
      return EncryptedRandomAccessBuffer.create(dis, fg, persistentFileTracker, masterSecret);
    }
    if (magicMatches(PADDED_RANDOM_ACCESS_BUFFER_CLASS, magic)) {
      return instantiateRandomAccessBuffer(
          PADDED_RANDOM_ACCESS_BUFFER_CLASS,
          new Class<?>[] {
            DataInputStream.class,
            FilenameGenerator.class,
            PersistentFileTracker.class,
            MasterSecret.class
          },
          dis,
          fg,
          persistentFileTracker,
          masterSecret);
    }
    throw new StorageFormatException("Unknown magic value for RAF " + magic);
  }

  /**
   * Ensures a {@link Bucket} is a {@link RandomAccessBucket}, copying if necessary.
   *
   * <p>If the bucket already supports random access, it is returned as-is. If it is a {@code
   * DelayedFreeBucket}, the method first asks it to provide a random-access view. Otherwise, a new
   * random-access bucket is created via {@code bf}, the content is copied, and the original bucket
   * is freed.
   *
   * @param bucket the source bucket
   * @param bf the factory used to create a new random-access bucket when required
   * @return a random-access bucket with the same content as {@code bucket}
   * @throws IOException if copying fails
   */
  public static RandomAccessBucket toRandomAccessBucket(Bucket bucket, BucketFactory bf)
      throws IOException {
    if (bucket instanceof RandomAccessBucket accessBucket) return accessBucket;
    if (isReflectiveInstance(bucket, DELAYED_FREE_BUCKET_CLASS)) {
      RandomAccessBucket ret =
          invokeRandomAccessBucketMethod(bucket, "toRandomAccessBucket", new Class<?>[0]);
      if (ret != null) return ret;
    }
    RandomAccessBucket ret = bf.makeBucket(bucket.size());
    BucketTools.copy(bucket, ret);
    bucket.free();
    return ret;
  }
}
