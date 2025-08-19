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

public abstract class BloomFilter implements AutoCloseable {
  private static final Cleaner cleaner = Cleaner.create();

  protected ByteBuffer filter;

  /** Number of hash functions */
  protected final int k;

  protected final int length;

  protected transient ReadWriteLock lock = new ReentrantReadWriteLock();

  // Cleaner action for safety net resource cleanup
  private final Cleaner.Cleanable cleanable;

  // Static nested class for cleaner action to avoid holding reference to the BloomFilter instance
  private static class FilterCleanup implements Runnable {
    private ByteBuffer filter;

    FilterCleanup(BloomFilter bloomFilter) {
      this.filter = bloomFilter.filter;
    }

    @Override
    public void run() {
      // Safety net cleanup - this should rarely be called if close() is used properly
      if (filter instanceof MappedByteBuffer buffer) {
        buffer.force();
      }
      filter = null;
    }
  }

  public void init() {
    lock = new ReentrantReadWriteLock();
  }

  public static BloomFilter createFilter(int length, int k, boolean counting) {
    if (length == 0) return new NullBloomFilter(length, k);
    if (counting) return new CountingBloomFilter(length, k);
    else return new BinaryBloomFilter(length, k);
  }

  public static BloomFilter createFilter(File file, int length, int k, boolean counting)
      throws IOException {
    if (length == 0) return new NullBloomFilter(length, k);
    if (counting) return new CountingBloomFilter(file, length, k);
    else return new BinaryBloomFilter(file, length, k);
  }

  protected BloomFilter(int length, int k) {
    if (length < 0) {
      throw new IllegalArgumentException("Filter must have postitive or zero length");
    }
    if (k < 0) {
      throw new IllegalArgumentException("Filter must have postitive or zero hashes");
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

  // add to the forked filter only
  public void addKeyForked(byte[] key) {
    if (forkedFilter != null) forkedFilter.addKey(key);
  }

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
  protected abstract boolean getBit(int offset);

  protected abstract void setBit(int offset);

  protected abstract void unsetBit(int offset);

  // Wierd impl's should override
  public void unsetAll() {
    int x = filter.limit();
    for (int i = 0; i < x; i++) filter.put(i, (byte) 0);
  }

  protected Random getHashes(byte[] key) {
    return new MersenneTwister(key);
  }

  // -- Fork & Merge
  protected BloomFilter forkedFilter;

  /**
   * Create an empty, in-memory copy of bloom filter. New updates are written to both filters. This
   * is written back to disk on #merge()
   */
  public abstract void fork(int k);

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
   * Calculate optimal K value
   *
   * @param filterLength filter length in bits
   * @param maxKey
   * @return optimal K
   */
  public static int optimialK(int filterLength, long maxKey) {
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

  protected boolean needRebuild;

  public boolean needRebuild() {
    boolean _needRebuild = needRebuild;
    needRebuild = false;
    return _needRebuild;
  }

  public void force() {
    if (filter instanceof MappedByteBuffer buffer) {
      buffer.force();
    }
  }

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

  public int getSizeBytes() {
    return filter.capacity();
  }

  public int getLength() {
    return length;
  }

  public int getFilledCount() {
    int x = 0;
    for (int i = 0; i < length; i++) if (getBit(i)) x++;
    return x;
  }

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

  public void writeTo(OutputStream cos) throws IOException {
    cos.write(filter.array(), filter.arrayOffset(), filter.capacity());
  }
}
