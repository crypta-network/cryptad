package network.crypta.support;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.ref.Cleaner;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.util.Random;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import network.crypta.support.math.MersenneTwister;

/**
 * Abstract base for Bloom filter implementations.
 *
 * <p>This class provides the concurrency, hashing, and fork/merge orchestration common to the
 * binary ({@link BinaryBloomFilter}) and counting ({@link CountingBloomFilter}) variants. The
 * underlying bit/counter storage resides in a {@link ByteBuffer} supplied or created by subclasses.
 * Implementations must provide bit-level access via {@link #getBit(int)}, {@link #setBit(int)}, and
 * {@link #unsetBit(int)}.
 *
 * <h2>Threading</h2>
 *
 * <p>Instances use an internal {@link ReadWriteLock} to coordinate updates and membership checks:
 * write operations acquire the write lock; checks acquire the read lock. Callers do not need to
 * perform external synchronization for the provided methods.
 *
 * <h2>Lifecycle</h2>
 *
 * <p>This type implements {@link AutoCloseable}. For file-backed implementations, {@link #close()}
 * forces outstanding changes to disk and releases references. A {@link Cleaner} is registered as a
 * safety net, but callers should still close instances deterministically (e.g., with
 * try-with-resources).
 */
public abstract class BloomFilter implements AutoCloseable {
  private static final Cleaner cleaner = Cleaner.create();

  /** Backing buffer for the filter’s bytes (bits or counters), owned by subclasses. */
  protected ByteBuffer filter;

  /** Number of hash functions to apply per key; immutable after construction. */
  protected final int k;

  /** Filter length in bits (rounded down to a multiple of 8 by the constructor). */
  protected final int length;

  /** Read/write lock guarding read and update operations. */
  protected ReadWriteLock lock = new ReentrantReadWriteLock();

  // Cleaner action for safety net resource cleanup
  private final Cleaner.Cleanable cleanable;

  // Cleaner action implemented as a static nested class to avoid retaining a reference to the
  // outer BloomFilter instance. It only holds the buffer to allow the best‑effort force on cleanup.
  private static class FilterCleanup implements Runnable {
    private ByteBuffer filter;

    FilterCleanup(BloomFilter bloomFilter) {
      this.filter = bloomFilter.filter;
    }

    @Override
    public void run() {
      // Safety net cleanup; close() should usually handle this. For mapped buffers, force any
      // outstanding changes to the storage device before dropping our reference.
      if (filter instanceof MappedByteBuffer buffer) {
        buffer.force();
      }
      filter = null;
    }
  }

  /**
   * Re-initializes the lock for deserialized or freshly constructed instances.
   *
   * <p>Some callers may reconstruct an instance and subsequently call this method to ensure the
   * lock is in a known state. Subclasses should call this if their lifecycle requires it.
   */
  public void init() {
    lock = new ReentrantReadWriteLock();
  }

  /**
   * Creates an in-memory Bloom filter.
   *
   * @param length length in bits; rounded down to the nearest multiple of 8; {@code 0} produces a
   *     {@link NullBloomFilter} which always returns positive membership
   * @param k number of hash functions; must be non-negative; coerced to {@code 0} when {@code
   *     length == 0}
   * @param counting when {@code true}, returns a {@link CountingBloomFilter}; otherwise a {@link
   *     BinaryBloomFilter}
   * @return a new filter instance
   * @throws IllegalArgumentException if {@code length < 0} or {@code k < 0}
   */
  public static BloomFilter createFilter(int length, int k, boolean counting) {
    validateFactoryArgs(length, k);
    if (length == 0) return new NullBloomFilter(length, k);
    if (counting) return new CountingBloomFilter(length, k);
    else return new BinaryBloomFilter(length, k);
  }

  /**
   * Creates a file-backed Bloom filter using a memory-mapped {@link ByteBuffer} when applicable.
   *
   * <p>When the on-disk file is missing or has an unexpected size, subclasses set an internal
   * one-shot {@link #needRebuild} flag which callers can query via {@link #needRebuild()}.
   *
   * @param file target file to back the filter; created or resized as needed by implementations
   * @param length length in bits; rounded down to the nearest multiple of 8; {@code 0} produces a
   *     {@link NullBloomFilter}
   * @param k number of hash functions; must be non-negative; coerced to {@code 0} when {@code
   *     length == 0}
   * @param counting when {@code true}, returns a {@link CountingBloomFilter}; otherwise a {@link
   *     BinaryBloomFilter}
   * @return a new filter instance backed by {@code file}
   * @throws IOException if the file cannot be created or mapped
   * @throws IllegalArgumentException if {@code length < 0} or {@code k < 0}
   */
  public static BloomFilter createFilter(File file, int length, int k, boolean counting)
      throws IOException {
    validateFactoryArgs(length, k);
    if (length == 0) return new NullBloomFilter(length, k);
    if (counting) return new CountingBloomFilter(file, length, k);
    else return new BinaryBloomFilter(file, length, k);
  }

  protected static int requireNonNegativeLength(int length) {
    if (length < 0) {
      throw new IllegalArgumentException("Filter must have positive or zero length");
    }
    return length;
  }

  protected static int requireNonNegativeHashCount(int k) {
    if (k < 0) {
      throw new IllegalArgumentException("Filter must have positive or zero hashes");
    }
    return k;
  }

  private static void validateFactoryArgs(int length, int k) {
    requireNonNegativeLength(length);
    requireNonNegativeHashCount(k);
  }

  /**
   * Constructs a Bloom filter skeleton.
   *
   * <p>Rounds {@code length} down to a multiple of 8 and coerces {@code k} to {@code 0} when the
   * resulting length is {@code 0}. Registers a {@link Cleaner} action for best-effort resource
   * cleanup.
   *
   * @param length requested length in bits (may be {@code 0})
   * @param k number of hash functions (non-negative)
   */
  protected BloomFilter(int length, int k) {
    if (length < 0) {
      length = 0;
    }
    if (k < 0) {
      k = 0;
    }

    if (length % 8 != 0) length -= length % 8;

    if (length == 0) {
      // Zero-length filters produce 100% false positives, no need for hashing.
      // This makes sure that length is strictly positive when k is strictly
      // positive as well, so nextInt(length) can safely be used.
      k = 0;
    }

    this.length = length;
    this.k = k;

    // Register cleaner for safety net (will be cleaned up when close() is called properly)
    this.cleanable = cleaner.register(this, new FilterCleanup(this));
  }

  // -- Core
  /**
   * Adds a key to the filter.
   *
   * <p>Derives {@code k} positions from the key via a deterministic {@link MersenneTwister} seeded
   * from {@code key} and sets the corresponding bits/counters. If a fork is active (see {@link
   * #fork(int)}), the update is also applied to the forked filter.
   *
   * <p>Thread-safe: acquires the write lock for the duration of the update.
   *
   * @param key key material; length must be a multiple of 4 bytes
   * @throws NullPointerException if {@code key} is null
   * @throws IllegalArgumentException if {@code key.length} is not a multiple of 4
   */
  public void addKey(byte[] key) {
    Random hashes = getHashes(key);
    lock.writeLock().lock();
    try {
      for (int i = 0; i < k; i++) setBit(hashes.nextInt(length));
    } finally {
      lock.writeLock().unlock();
    }

    if (forkedFilter != null) forkedFilter.addKey(key);
  }

  /**
   * Adds a key only to the active fork, if present.
   *
   * <p>Use to stage changes in the fork without affecting the main filter prior to {@link
   * #merge()}.
   *
   * @param key key material; length must be a multiple of 4 bytes
   * @see #fork(int)
   */
  public void addKeyForked(byte[] key) {
    if (forkedFilter != null) forkedFilter.addKey(key);
  }

  /**
   * Tests whether all {@code k} hashed positions for {@code key} are present.
   *
   * <p>Returns {@code true} for possible membership (false positives are possible) and {@code
   * false} for definite absence. Thread-safe: acquires the read lock.
   *
   * @param key key material; length must be a multiple of 4 bytes
   * @return {@code true} if the filter may contain {@code key}; {@code false} if it does not
   * @throws NullPointerException if {@code key} is null
   * @throws IllegalArgumentException if {@code key.length} is not a multiple of 4
   */
  public boolean checkFilter(byte[] key) {
    Random hashes = getHashes(key);
    lock.readLock().lock();
    try {
      for (int i = 0; i < k; i++) if (!getBit(hashes.nextInt(length))) return false;
    } finally {
      lock.readLock().unlock();
    }
    return true;
  }

  /**
   * Removes a key from the filter.
   *
   * <p>For counting implementations, decrements the counters for the hashed positions (bounded at
   * zero). For binary implementations, the operation may be a no-op. If a fork is active, the
   * update is mirrored to the fork as well. Thread-safe: acquires the write lock.
   *
   * @param key key material; length must be a multiple of 4 bytes
   * @throws NullPointerException if {@code key} is null
   * @throws IllegalArgumentException if {@code key.length} is not a multiple of 4
   */
  public void removeKey(byte[] key) {
    Random hashes = getHashes(key);
    lock.writeLock().lock();
    try {
      for (int i = 0; i < k; i++) unsetBit(hashes.nextInt(length));
    } finally {
      lock.writeLock().unlock();
    }

    if (forkedFilter != null) forkedFilter.removeKey(key);
  }

  // -- Bits and Hashes
  /**
   * Returns whether the bit/counter at a given position indicates presence.
   *
   * @param offset position in {@code [0, length)}
   * @return {@code true} if the position is set (non-zero for counting); {@code false} otherwise
   */
  protected abstract boolean getBit(int offset);

  /** Sets the bit/counter at {@code offset}. Implementations handle overflow as needed. */
  protected abstract void setBit(int offset);

  /** Clears or decrements the position at {@code offset}. Implementations handle underflow. */
  protected abstract void unsetBit(int offset);

  // Unusual implementations should override for efficiency.
  public void unsetAll() {
    int x = filter.limit();
    for (int i = 0; i < x; i++) filter.put(i, (byte) 0);
  }

  /**
   * Returns a {@link Random} seeded from {@code key} for position generation.
   *
   * <p>By default, this uses a non-synchronized {@link MersenneTwister} seeded with {@code
   * key}-derived integers. Subclasses may override to change the hashing scheme.
   *
   * @param key key material; length must be a multiple of 4 bytes
   * @return a deterministic pseudo-random generator for hashing
   */
  protected Random getHashes(byte[] key) {
    return MersenneTwister.createUnsynchronized(key);
  }

  // -- Fork & Merge
  /** Active forked filter; when non-null, updates are mirrored to it. */
  protected BloomFilter forkedFilter;

  /**
   * Creates an empty, in-memory copy (the fork) and starts mirroring updates to it.
   *
   * <p>The fork captures staged changes. On {@link #merge()}, the fork’s buffer replaces the main
   * buffer atomically under the write lock. On {@link #discard()}, the fork is dropped.
   *
   * @param k number of hash functions to use in the fork (typically the same as {@link #k})
   */
  public abstract void fork(int k);

  /**
   * Replaces the main buffer with the fork’s buffer and closes the fork.
   *
   * <p>Thread-safe: acquires the write lock on both the main and forked filters. If no fork is
   * active, the method returns immediately.
   */
  public void merge() {
    lock.writeLock().lock();
    try {
      if (forkedFilter == null) return;

      Lock forkedLock = forkedFilter.lock.writeLock();
      forkedLock.lock();
      try {
        filter.position(0);
        forkedFilter.filter.position(0);

        filter.put(forkedFilter.filter);

        filter.position(0);
        forkedFilter.close();
        forkedFilter = null;
      } finally {
        forkedLock.unlock();
      }
    } finally {
      lock.writeLock().unlock();
    }
  }

  /**
   * Discards the active fork without applying its changes.
   *
   * <p>Thread-safe and idempotent.
   */
  public void discard() {
    lock.writeLock().lock();
    try {
      if (forkedFilter == null) return;
      forkedFilter.close();
      forkedFilter = null;
    } finally {
      lock.writeLock().unlock();
    }
  }

  // -- Misc.
  /**
   * Computes an approximate optimal number of hash functions.
   *
   * <p>Uses {@code round(ln(2) * m / n)} with {@code m = filterLength} (in bits) and {@code n =
   * maxKey}. The result is clamped to {@code [1, 64]}. Returns {@code 0} when {@code filterLength
   * == 0}.
   *
   * @param filterLength filter length in bits
   * @param maxKey expected maximum distinct keys (must be positive for meaningful results)
   * @return the recommended {@code k}
   */
  public static int optimalK(int filterLength, long maxKey) {
    if (filterLength == 0) {
      // There's no point hashing when the filter is of zero length.
      return 0;
    }

    long k = Math.round(Math.log(2) * filterLength / maxKey);

    if (k > 64) k = 64;
    if (k < 1) k = 1;

    return (int) k;
  }

  public int getK() {
    return k;
  }

  /**
   * One-shot flag set by file-backed implementations when backing storage was missing or resized.
   */
  protected boolean needRebuild;

  /**
   * Returns and clears the {@link #needRebuild} flag.
   *
   * @return {@code true} if a rebuild was requested since the last call; otherwise {@code false}
   */
  public boolean needRebuild() {
    boolean previousNeedRebuild = needRebuild;
    needRebuild = false;
    return previousNeedRebuild;
  }

  /**
   * Forces pending changes to the underlying storage if the buffer is memory-mapped.
   *
   * <p>No effect for heap buffers.
   */
  public void force() {
    if (filter instanceof MappedByteBuffer buffer) {
      buffer.force();
    }
  }

  /**
   * Flushes resources and unregisters the cleaner.
   *
   * <p>For mapped buffers, calls {@link #force()} and then releases references to the buffer and
   * the fork. This method is safe to call multiple times.
   */
  @Override
  public void close() {
    if (filter != null) {
      force();
    }
    filter = null;
    forkedFilter = null;

    // Clean up the cleaner since we've properly closed resources
    if (cleanable != null) {
      cleanable.clean();
    }
  }

  /**
   * Returns the size of the backing buffer in bytes.
   *
   * @return buffer capacity in bytes
   */
  public int getSizeBytes() {
    return filter.capacity();
  }

  /**
   * Returns the logical filter length in bits.
   *
   * @return number of addressable positions
   */
  public int getLength() {
    return length;
  }

  /**
   * Counts the number of set positions across the entire filter.
   *
   * <p>For counting filters, any non-zero counter is considered set. This operation runs in {@code
   * O(length)} and may be expensive for large filters.
   *
   * @return the number of set positions
   */
  public int getFilledCount() {
    int count = 0;
    for (int i = 0; i < length; i++) if (getBit(i)) count++;
    return count;
  }

  /**
   * Copies the entire backing buffer into {@code buf} starting at {@code offset}.
   *
   * <p>Thread-safe: acquires the read lock for the duration of the copy.
   *
   * @param buf destination array
   * @param offset starting index in {@code buf}
   * @return number of bytes copied (the buffer capacity)
   * @throws NullPointerException if {@code buf} is null
   * @throws IndexOutOfBoundsException if the copy would exceed {@code buf} bounds
   */
  public int copyTo(byte[] buf, int offset) {
    lock.readLock().lock();
    try {
      int capacity = filter.capacity();
      System.arraycopy(filter.array(), filter.arrayOffset(), buf, offset, capacity);
      return capacity;
    } finally {
      lock.readLock().unlock();
    }
  }

  /**
   * Writes the entire backing buffer to the given stream.
   *
   * @param cos destination stream
   * @throws IOException if the write fails
   */
  public void writeTo(OutputStream cos) throws IOException {
    cos.write(filter.array(), filter.arrayOffset(), filter.capacity());
  }
}
