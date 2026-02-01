package network.crypta.support.io;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serial;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Random;
import network.crypta.client.async.ClientContext;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.PCFBMode;
import network.crypta.crypt.RandomSource;
import network.crypta.crypt.UnsupportedCipherException;
import network.crypta.crypt.ciphers.Rijndael;
import network.crypta.support.api.Bucket;
import network.crypta.support.math.MersenneTwister;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link Bucket} decorator that encrypts written data with an ephemeral key and pads the stored
 * length to a power-of-two boundary.
 *
 * <p>Purpose: conceal the plaintext and obscure the exact content length by padding to the next
 * power-of-two (subject to a configured minimum). The encryption layer uses PCFB over 256-bit
 * Rijndael (AES) with a per-instance random key. When an initialization vector (IV) is present, it
 * is used; otherwise a legacy zero-IV PCFB variant is used. The key is random and unique per
 * instance and can be retrieved via {@link #getKey()} for later decryption by this wrapper.
 *
 * <p>Threading: instances are not intended for concurrent write access. The implementation guards
 * against multiple active output streams and ensures only the most recent stream performs padding
 * on {@code close()}. Reads decrypt up to the logical data length; padding bytes are never exposed
 * through the public {@link InputStream}.
 *
 * <p>Serialization: the wrapped bucket reference is {@code transient}. Runtime persistence is
 * provided via {@link #storeTo(DataOutputStream)} and the matching restoring constructor. Java
 * serialization also writes the underlying bucket when it is {@link java.io.Serializable};
 * otherwise a {@link java.io.NotSerializableException} is thrown.
 */
public class PaddedEphemerallyEncryptedBucket implements Bucket, Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(PaddedEphemerallyEncryptedBucket.class);

  /**
   * Serial version for Java serialization. Bumped to 2 to reflect the change in the on-wire Java
   * serialization layout (custom writeObject/readObject with a transient underlying bucket).
   */
  @Serial private static final long serialVersionUID = 2L;

  // Wrapped bucket may not be java.io.Serializable; keep transient and persist via storeTo/restore
  private transient Bucket bucket;
  private final int minPaddedSize;

  /** The decryption key. */
  private final byte[] key;

  private final byte[] iv;
  private transient byte[] randomSeed;
  private long dataLength;
  private boolean readOnly;
  private transient int lastOutputStream;

  // No static initialization required

  /**
   * Creates an encrypted, padding-aware wrapper over an empty underlying bucket.
   *
   * <p>The constructor derives a random 256-bit key and IV from {@code strongPRNG} and seeds a
   * secondary non-cryptographic PRNG with {@code weakPRNG} for generating padding bytes later. The
   * wrapper begins in a writable state and records the logical plaintext length as data is written.
   *
   * @param bucket the underlying destination; must report {@code size()==0}
   * @param minSize minimum padded size in bytes applied at close; must be non-negative
   * @param strongPRNG cryptographically strong source for key/IV material
   * @param weakPRNG weaker source used only for padding bytes (not for keys)
   * @throws IllegalArgumentException if {@code bucket} is not empty
   */
  public PaddedEphemerallyEncryptedBucket(
      Bucket bucket, int minSize, RandomSource strongPRNG, Random weakPRNG) {
    this.bucket = bucket;
    if (bucket.size() != 0) throw new IllegalArgumentException("Bucket must be empty");
    byte[] tempKey = new byte[32];
    randomSeed = new byte[32];
    weakPRNG.nextBytes(randomSeed);
    strongPRNG.nextBytes(tempKey);
    this.key = tempKey;
    this.iv = new byte[32];
    strongPRNG.nextBytes(iv);
    this.minPaddedSize = minSize;
    readOnly = false;
    lastOutputStream = 0;
    dataLength = 0;
  }

  /**
   * Creates a read-only shadow that shares the encryption key and logical length with the original
   * instance.
   *
   * <p>The new wrapper marks itself read-only and wraps {@code newBucket} as its underlying store.
   * The IV is copied when available to preserve decryption behavior.
   *
   * @param orig original wrapper to clone keying material and lengths from
   * @param newBucket underlying storage used by the shadow wrapper
   */
  public PaddedEphemerallyEncryptedBucket(PaddedEphemerallyEncryptedBucket orig, Bucket newBucket) {
    this.dataLength = orig.dataLength;
    this.key = orig.key.clone();
    this.randomSeed = null; // Will be read-only
    setReadOnly();
    this.bucket = newBucket;
    this.minPaddedSize = orig.minPaddedSize;
    if (orig.iv != null) {
      iv = Arrays.copyOf(orig.iv, 32);
    } else {
      iv = null;
    }
  }

  /**
   * No-arg constructor for Java serialization frameworks.
   *
   * <p>Do not use directly in application code. Fields are initialized during deserialization.
   */
  @SuppressWarnings("unused")
  protected PaddedEphemerallyEncryptedBucket() {
    // For serialization only.
    bucket = null;
    minPaddedSize = 0;
    key = null;
    iv = null;
    randomSeed = null;
  }

  /**
   * Opens a buffered {@link OutputStream} positioned at the start and resets the logical length.
   *
   * <p>The stream encrypts bytes on the fly and, upon close, pads the underlying store to {@link
   * #paddedLength()} if it is still the most recent output stream. If the wrapper is marked
   * read-only, this method throws.
   *
   * @return a buffered stream that encrypts and writes from offset 0
   * @throws IOException if the wrapper is read-only or the underlying bucket rejects the request
   */
  @Override
  public OutputStream getOutputStream() throws IOException {
    return new BufferedOutputStream(getOutputStreamUnbuffered());
  }

  /**
   * Opens an unbuffered {@link OutputStream} positioned at the start and resets the logical
   * plaintext length.
   *
   * <p>Callers that will add their own buffering or perform large contiguous writes can prefer this
   * accessor. The returned stream encrypts and writes exactly what is provided; padding and
   * finalization occur on close by the most recent stream only.
   *
   * @return an unbuffered stream for encrypted writes
   * @throws IOException if the wrapper is read-only or the underlying bucket rejects the request
   */
  @Override
  public OutputStream getOutputStreamUnbuffered() throws IOException {
    if (readOnly) throw new IOException("Read only");
    OutputStream os = bucket.getOutputStreamUnbuffered();
    synchronized (this) {
      dataLength = 0;
    }
    return new PaddedEphemerallyEncryptedOutputStream(os, ++lastOutputStream);
  }

  private class PaddedEphemerallyEncryptedOutputStream extends OutputStream {

    final PCFBMode pcfb;
    final OutputStream out;
    final int streamNumber;
    private boolean closed;

    public PaddedEphemerallyEncryptedOutputStream(OutputStream out, int streamNumber) {
      this.out = out;
      dataLength = 0;
      this.streamNumber = streamNumber;
      pcfb = getPCFB();
    }

    @Override
    public void write(int b) throws IOException {
      synchronized (PaddedEphemerallyEncryptedBucket.this) {
        if (closed) throw new IOException("Already closed!");
        if (streamNumber != lastOutputStream)
          throw new IllegalStateException("Writing to old stream in " + getName());
      }
      int toWrite = pcfb.encipher(b);
      synchronized (PaddedEphemerallyEncryptedBucket.this) {
        out.write(toWrite);
        dataLength++;
      }
    }

    // Override this or FOS will use write(int)
    @Override
    public void write(byte @NotNull [] buf) throws IOException {
      synchronized (PaddedEphemerallyEncryptedBucket.this) {
        if (closed) throw new IOException("Already closed!");
        if (streamNumber != lastOutputStream)
          throw new IllegalStateException("Writing to old stream in " + getName());
      }
      write(buf, 0, buf.length);
    }

    @Override
    public void write(byte @NotNull [] buf, int offset, int length) throws IOException {
      synchronized (PaddedEphemerallyEncryptedBucket.this) {
        if (closed) throw new IOException("Already closed!");
        if (streamNumber != lastOutputStream)
          throw new IllegalStateException("Writing to old stream in " + getName());
      }
      if (length == 0) return;
      byte[] enc = Arrays.copyOfRange(buf, offset, offset + length);
      pcfb.blockEncipher(enc, 0, enc.length);
      synchronized (PaddedEphemerallyEncryptedBucket.this) {
        out.write(enc, 0, enc.length);
        dataLength += enc.length;
      }
    }

    @Override
    @SuppressWarnings("cast")
    public void close() throws IOException {
      try {
        Random random = MersenneTwister.createUnsynchronized(randomSeed);
        synchronized (PaddedEphemerallyEncryptedBucket.this) {
          if (closed) return;
          if (streamNumber != lastOutputStream) {
            LOG.info("Not padding out to length because have been superceded: {}", getName());
            return;
          }
          long finalLength = paddedLength();
          long padding = finalLength - dataLength;
          int sz = 65536;
          if (padding < (long) sz) sz = (int) padding;
          byte[] buf = new byte[sz];
          long writtenPadding = 0;
          while (writtenPadding < padding) {
            int left = (int) Math.min(padding - writtenPadding, buf.length);
            random.nextBytes(buf);
            out.write(buf, 0, left);
            writtenPadding += left;
          }
        }
      } finally {
        closed = true;
        out.flush();
        out.close();
      }
    }
  }

  /**
   * Opens a buffered {@link InputStream} that decrypts up to the logical plaintext length.
   *
   * <p>Padding bytes are never exposed. End-of-stream is reported after exactly {@link #size()}
   * bytes of plaintext.
   *
   * @return a buffered stream for decrypted reads
   * @throws IOException if the underlying bucket rejects the request
   */
  @Override
  public InputStream getInputStream() throws IOException {
    return new BufferedInputStream(getInputStreamUnbuffered());
  }

  /**
   * Opens an unbuffered {@link InputStream} that decrypts up to the logical plaintext length.
   *
   * @return an unbuffered stream for decrypted reads
   * @throws IOException if the underlying bucket rejects the request
   */
  @Override
  public InputStream getInputStreamUnbuffered() throws IOException {
    return new PaddedEphemerallyEncryptedInputStream(bucket.getInputStreamUnbuffered());
  }

  private class PaddedEphemerallyEncryptedInputStream extends InputStream {

    final InputStream in;
    final PCFBMode pcfb;
    long ptr;

    public PaddedEphemerallyEncryptedInputStream(InputStream in) {
      this.in = in;
      pcfb = getPCFB();
      ptr = 0;
    }

    @Override
    public int read() throws IOException {
      if (ptr >= dataLength) return -1;
      int x = in.read();
      if (x == -1) return x;
      ptr++;
      return pcfb.decipher(x);
    }

    @Override
    public final int available() {
      int x = (int) Math.min(dataLength - ptr, Integer.MAX_VALUE);
      return Math.max(x, 0);
    }

    @Override
    public int read(byte[] buf, int offset, int length) throws IOException {
      // Explicit bounds validation matching InputStream contract
      if ((length + offset > buf.length) || (offset < 0) || (length < 0))
        throw new ArrayIndexOutOfBoundsException(
            "a=" + offset + ", b=" + length + ", length " + buf.length);
      int x = available();
      if (x <= 0) return -1;
      length = Math.min(length, x);
      int readBytes = in.read(buf, offset, length);
      if (readBytes <= 0) return readBytes;
      ptr += readBytes;
      pcfb.blockDecipher(buf, offset, readBytes);
      return readBytes;
    }

    @Override
    public int read(byte @NotNull [] buf) throws IOException {
      return read(buf, 0, buf.length);
    }

    @Override
    public long skip(long bytes) throws IOException {
      byte[] buf = new byte[(int) Math.min(4096, bytes)];
      long skipped = 0;
      while (skipped < bytes) {
        int x = read(buf, 0, (int) Math.min(bytes - skipped, buf.length));
        if (x <= 0) return skipped;
        skipped += x;
      }
      return skipped;
    }

    @Override
    public void close() throws IOException {
      in.close();
    }
  }

  /**
   * Returns the final padded length for the current logical length.
   *
   * <p>The value is at least {@code minPaddedSize}. If the logical size exceeds that minimum, the
   * returned value is the next power-of-two boundary above the minimum that encloses the logical
   * size.
   *
   * @return padded length in bytes
   */
  public synchronized long paddedLength() {
    return paddedLength(dataLength, minPaddedSize);
  }

  /** Minimum default padded size in bytes ({@value}). */
  public static final int MIN_PADDED_SIZE = 1024;

  /**
   * Computes the padded length for an arbitrary logical size and minimum.
   *
   * <p>Algorithm: clamp {@code dataLength} to at least {@code minPaddedSize}; if equal, return the
   * minimum. Otherwise, double {@code minPaddedSize} until the clamped value is within the current
   * {@code [min, 2*min]} window, then return the upper bound of that window.
   *
   * @param dataLength logical plaintext length in bytes
   * @param minPaddedSize minimum padded size in bytes
   * @return padded length in bytes
   * @throws IllegalStateException if overflow or inconsistent bounds are detected
   */
  public static long paddedLength(long dataLength, long minPaddedSize) {
    long size = dataLength;
    if (size < minPaddedSize) size = minPaddedSize;
    if (size == minPaddedSize) return size;
    long min = minPaddedSize;
    long max = minPaddedSize << 1;
    while (true) {
      if (max < 0)
        throw new IllegalStateException(
            "Impossible size: " + size + " - min=" + min + ", max=" + max);
      if (size <= max) {
        if (LOG.isDebugEnabled()) LOG.debug("Padded: {} was: {}", max, dataLength);
        return max;
      }
      min = max;
      max = max << 1;
    }
  }

  private synchronized Rijndael getRijndael() {
    Rijndael aes;
    try {
      aes = new Rijndael(256, 256);
    } catch (UnsupportedCipherException e) {
      throw new IllegalStateException("Rijndael(256,256) unavailable", e);
    }
    aes.initialize(key);
    return aes;
  }

  /**
   * Creates a PCFB cipher instance configured with this bucket's key and IV.
   *
   * <p>When an IV is present, uses the IV-based constructor; otherwise uses a legacy zero-IV
   * variant. Callers should prefer the IV form when available.
   *
   * @return a PCFB mode instance bound to this bucket's key material
   */
  public PCFBMode getPCFB() {
    Rijndael aes = getRijndael();
    if (iv != null) return PCFBMode.create(aes, iv);
    // Crypto note: when iv==null we fall back to zero-IV PCFB; keys are unique per bucket.
    byte[] zeroIv = new byte[PCFBMode.lengthIV(aes)];
    return PCFBMode.create(aes, zeroIv);
  }

  /**
   * Returns a human-readable name for diagnostics.
   *
   * @return the underlying name prefixed with {@code "Encrypted:"}
   */
  @Override
  public String getName() {
    return "Encrypted:" + bucket.getName();
  }

  /** Returns a debug-oriented string including the underlying bucket. */
  @Override
  public String toString() {
    return super.toString() + ':' + bucket;
  }

  /**
   * Returns the logical plaintext size in bytes.
   *
   * @return number of plaintext bytes written via the current output stream
   */
  @Override
  public synchronized long size() {
    return dataLength;
  }

  /**
   * Indicates whether the wrapper currently allows opening new output streams.
   *
   * @return {@code true} when read-only
   */
  @Override
  public boolean isReadOnly() {
    return readOnly;
  }

  /** Marks the wrapper read-only. The change is irreversible for this instance. */
  @Override
  public void setReadOnly() {
    readOnly = true;
  }

  /** Returns the underlying bucket reference for advanced scenarios. */
  public Bucket getUnderlying() {
    return bucket;
  }

  /**
   * Frees the underlying bucket. After this call, streams obtained from the underlying may fail.
   */
  @Override
  public void free() {
    bucket.free();
  }

  /**
   * Returns the 256-bit symmetric key used to encrypt and decrypt the data.
   *
   * @return a 32-byte key array (defensive copy not returned)
   */
  public byte[] getKey() {
    return key;
  }

  /**
   * Creates a read-only shadow copy that exposes the same plaintext through a different underlying
   * bucket.
   *
   * <p>The shadow shares keying material with the original but uses a separate underlying storage
   * returned by {@link Bucket#createShadow()}.
   *
   * @return a new read-only wrapper, or {@code null} if the underlying cannot provide a shadow
   */
  @Override
  public Bucket createShadow() {
    return wrapShadow(bucket.createShadow());
  }

  private Bucket wrapShadow(Bucket newUnderlying) {
    if (newUnderlying == null) return null;
    try {
      return new PaddedEphemerallyEncryptedBucket(this, newUnderlying);
    } catch (RuntimeException e) {
      try {
        newUnderlying.free();
      } catch (RuntimeException suppressed) {
        e.addSuppressed(suppressed);
      }
      throw e;
    }
  }

  /**
   * Reattaches runtime state after a restart.
   *
   * <p>Seeds the padding PRNG and delegates resume to the underlying bucket.
   *
   * @param context runtime client context providing PRNGs and trackers
   * @throws ResumeFailedException if the underlying bucket fails to resume
   */
  @Override
  public void onResume(ClientContext context) throws ResumeFailedException {
    randomSeed = new byte[32];
    context.fastWeakRandom.nextBytes(randomSeed);
    bucket.onResume(context);
  }

  public static final int MAGIC = 0x66c71fc9;
  static final int VERSION = 1;

  /* ===== Java serialization support (pattern patterned after DelayedFreeBucket) ===== */

  /* Writes default state and, when possible, the underlying bucket for Java serialization. */
  @Serial
  private void writeObject(ObjectOutputStream out) throws IOException {
    out.defaultWriteObject();
    if (bucket instanceof Serializable serializable) {
      out.writeObject(serializable);
    } else {
      throw new NotSerializableException(
          bucket == null ? "nullBucket" : bucket.getClass().getName());
    }
  }

  /* Restores default state and the underlying bucket written by {@link #writeObject}. */
  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    bucket = (Bucket) in.readObject();
  }

  /**
   * Writes the minimal state necessary to reconstruct this wrapper using the restoring constructor.
   *
   * <p>Format: {@link #MAGIC} (int), {@link #VERSION} (int), {@code minPaddedSize} (int), key (32
   * bytes), IV present flag (boolean), IV bytes when present, {@code dataLength} (long), {@code
   * readOnly} (boolean), then the underlying bucket via {@link Bucket#storeTo}.
   *
   * @param dos destination stream
   * @throws IOException if writing fails
   */
  @Override
  public void storeTo(DataOutputStream dos) throws IOException {
    dos.writeInt(MAGIC);
    dos.writeInt(VERSION);
    dos.writeInt(minPaddedSize);
    dos.write(key);
    if (iv != null) {
      dos.writeBoolean(true);
      dos.write(iv);
    } else {
      dos.writeBoolean(false);
    }
    // randomSeed should be recovered in onResume().
    dos.writeLong(dataLength);
    dos.writeBoolean(readOnly);
    bucket.storeTo(dos);
  }

  /**
   * Restores an instance previously written by {@link #storeTo(DataOutputStream)}.
   *
   * <p>The caller must have already consumed {@link #MAGIC}. This constructor validates the stored
   * {@link #VERSION} and restores the underlying bucket via {@link BucketTools#restoreFrom}.
   *
   * @param dis source positioned at the version field
   * @param fg filename generator for nested bucket reconstruction
   * @param persistentFileTracker tracker used by nested bucket types
   * @param masterKey master secret used by encrypted buckets if present
   * @throws StorageFormatException if the stored format version is unknown or malformed
   * @throws IOException on I/O errors
   * @throws ResumeFailedException if nested buckets cannot be resumed
   */
  protected PaddedEphemerallyEncryptedBucket(
      DataInputStream dis,
      FilenameGenerator fg,
      PersistentFileTracker persistentFileTracker,
      MasterSecret masterKey)
      throws StorageFormatException, IOException, ResumeFailedException {
    int version = dis.readInt();
    if (version != VERSION) throw new StorageFormatException("Bad version");
    minPaddedSize = dis.readInt();
    key = new byte[32];
    dis.readFully(key);
    if (dis.readBoolean()) {
      iv = new byte[32];
      dis.readFully(iv);
    } else {
      iv = null;
    }
    dataLength = dis.readLong();
    readOnly = dis.readBoolean();
    bucket = BucketTools.restoreFrom(dis, fg, persistentFileTracker, masterKey);
  }
}
