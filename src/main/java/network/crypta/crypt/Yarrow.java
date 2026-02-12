package network.crypta.crypt;

import static java.util.concurrent.TimeUnit.HOURS;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serial;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Cryptographically secure pseudo‑random number generator implementing Yarrow‑160.
 *
 * <p>This class implements the Yarrow‑160 design by John Kelsey, Bruce Schneier, and Niels
 * Ferguson. It follows the published design with a few pragmatic adaptations:
 *
 * <ul>
 *   <li>Rijndael (AES) is used as the generator cipher instead of 3DES.
 *   <li>The size‑adapter function ({@code h'}) described in the paper is not used. Key material is
 *       derived via {@link Util#makeKey}.
 *   <li>Entropy estimation uses a conservative third‑order delta heuristic and applies caller‑
 *       supplied guesses and bias factors as suggested by the design.
 * </ul>
 *
 * <p>The generator rekeys periodically to limit state compromise extension and supports persistence
 * of seed material across restarts via {@link PersistentRandomSource}.
 *
 * <p>Threading: generation and entropy accounting use internal synchronization consistent with
 * {@link java.util.Random}'s synchronized methods.
 *
 * @author Scott G. Miller <scgmille@indiana.edu>
 */
public final class Yarrow extends RandomSource implements PersistentRandomSource {
  private static final Logger LOG = LoggerFactory.getLogger(Yarrow.class);

  @Serial private static final long serialVersionUID = -1;

  /** Security parameters */
  private static final boolean DEBUG = false;

  private static final int PG = 10;
  private static final String DEFAULT_CIPHER = "Rijndael";
  private static final String DEV_HWRNG = "/dev/hwrng";
  private static final String DEV_URANDOM = "/dev/urandom";
  private static final String DEV_RANDOM = "/dev/random";
  private final SecureRandom sr;

  /**
   * Destination file for persisting seed material.
   *
   * <p>When configured (non‑{@code null}), {@link #writeSeed(boolean)} periodically writes fresh
   * generator output to this file so future instances can bootstrap with additional entropy. The
   * file may be {@code null} when persistence is disabled or when the configured path points to a
   * non‑file device (for example, {@code /dev/urandom}).
   */
  public final File seedfile;

  // Remember chosen algorithms so we can rebuild transient fields on deserialization
  private final String digestName;
  private final String cipherName;

  /**
   * Creates a generator using default algorithms and a seed file named {@code prng.seed} in the
   * current working directory.
   *
   * <p>On Unix‑like systems it collects startup entropy from the environment and non‑blocking
   * system devices. On Windows it uses {@link SecureRandom#generateSeed(int)}.
   *
   * @throws IllegalStateException if the requested digest or cipher is unavailable.
   */
  public Yarrow() {
    this("prng.seed", "SHA1", DEFAULT_CIPHER, true, true);
  }

  /**
   * Creates a generator with default algorithms and a configurable blocking policy.
   *
   * @param canBlock when {@code true}, may read from blocking sources (for example, {@code
   *     /dev/random} and {@link SecureRandom#generateSeed(int)}); when {@code false}, prefers
   *     non‑blocking sources only.
   * @throws IllegalStateException if the requested digest or cipher is unavailable.
   */
  @SuppressWarnings("unused")
  public Yarrow(boolean canBlock) {
    this("prng.seed", "SHA1", DEFAULT_CIPHER, true, canBlock);
  }

  /**
   * Creates a generator using the given seed file path and default algorithms.
   *
   * @param seed file used to persist and restore seed material.
   * @throws IllegalStateException if the requested digest or cipher is unavailable.
   */
  public Yarrow(File seed) {
    this(seed, "SHA1", DEFAULT_CIPHER, true, true);
  }

  /**
   * Creates a generator with a fully specified configuration.
   *
   * @param seed path to the seed file (string form).
   * @param digest message digest algorithm used by the entropy pools (for example, {@code SHA1}).
   * @param cipher block cipher used by the generator (for example, {@code Rijndael}).
   * @param updateSeed whether to persist seed material periodically.
   * @param canBlock whether blocking entropy sources may be used during initialization.
   * @throws IllegalStateException if {@code digest} or {@code cipher} is unavailable.
   */
  public Yarrow(String seed, String digest, String cipher, boolean updateSeed, boolean canBlock) {
    this(new File(seed), digest, cipher, updateSeed, canBlock);
  }

  /**
   * Creates a generator with a fully specified configuration.
   *
   * @param seed seed file used for persistence and bootstrap.
   * @param digest message digest algorithm used by the entropy pools.
   * @param cipher block cipher used by the generator.
   * @param updateSeed whether to persist seed material periodically.
   * @param canBlock whether blocking entropy sources may be used during initialization.
   * @throws IllegalStateException if {@code digest} or {@code cipher} is unavailable.
   */
  public Yarrow(File seed, String digest, String cipher, boolean updateSeed, boolean canBlock) {
    this(seed, digest, cipher, updateSeed, canBlock, true);
  }

  // unset reseedOnStartup only in unit test
  Yarrow(
      File seed,
      String digest,
      String cipher,
      boolean updateSeed,
      boolean canBlock,
      boolean reseedOnStartup) {
    SecureRandom s;
    try {
      s = SecureRandom.getInstance("SHA1PRNG");
    } catch (NoSuchAlgorithmException _) {
      s = null;
    }
    sr = s;
    try {
      // Persist algorithm choices for future (de)serialization re-initialization
      this.digestName = digest;
      this.cipherName = cipher;
      accumulatorInit(digest);
      reseedInit(digest);
      generatorInit(cipher);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(
          "Cannot initialize Yarrow (digest='" + digest + "', cipher='" + cipher + "')", e);
    }

    if (updateSeed
        && !seed.toString()
            .equals(DEV_URANDOM)) // Don't try to update the seed file if we know it won't be
      // possible anyway
      seedfile = seed;
    else seedfile = null;
    if (reseedOnStartup) {
      entropyInit(seed);
      seedFromExternalStuff(canBlock);
      /*
       * If we do not reseed at this point, the generator would be predictable because startup
       * entropy alone might not cross the reseeding thresholds.
       */
      fastPoolReseed();
      slowPoolReseed();
    } else {
      readSeed(seed);
    }
  }

  private void seedFromExternalStuff(boolean canBlock) {
    byte[] buf = new byte[32];
    if (File.separatorChar == '/') {
      File hwrng = new File(DEV_HWRNG);
      if (hwrng.exists() && hwrng.canRead()) {
        tryReadDevice(hwrng, buf);
      }

      // Read some bits from /dev/urandom
      boolean urandomOk = readDevice(DEV_URANDOM, buf);
      if (!urandomOk) {
        // We can't read it; let's skip /dev/random and seed from SecureRandom.generateSeed()
        canBlock = true;
      }
      if (canBlock) {
        // Read some bits from /dev/random
        readDevice(DEV_RANDOM, buf);
      }
    } else {
      // Force generateSeed(), since we cannot read random data from anywhere else.
      // On Windows the CAPI-backed SecureRandom does not block.
      canBlock = true;
    }
    if (canBlock) {
      // SecureRandom likely acts as a proxy for CAPI on Windows
      buf = sr.generateSeed(32);
      consumeBytes(buf);
      buf = sr.generateSeed(32);
      consumeBytes(buf);
    }
    // Mix in a few more environment‑dependent bits
    consumeString(Long.toHexString(Runtime.getRuntime().freeMemory()));
    consumeString(Long.toHexString(Runtime.getRuntime().totalMemory()));
  }

  private void tryReadDevice(File device, byte[] buf) {
    try (FileInputStream fis = new FileInputStream(device);
        DataInputStream dis = new DataInputStream(fis)) {
      readTwoBlocks(dis, buf);
    } catch (Exception t) {
      LOG.info("Can't read {} even though exists and is readable", device, t);
    }
  }

  private boolean readDevice(String path, byte[] buf) {
    try (FileInputStream fis = new FileInputStream(path);
        DataInputStream dis = new DataInputStream(fis)) {
      readTwoBlocks(dis, buf);
      return true;
    } catch (Exception t) {
      LOG.info("Can't read {}: {}", path, t, t);
      return false;
    }
  }

  private void readTwoBlocks(DataInputStream dis, byte[] buf) throws IOException {
    dis.readFully(buf);
    consumeBytes(buf);
    dis.readFully(buf);
    consumeBytes(buf);
  }

  private void entropyInit(File seed) {
    Properties sys = System.getProperties();
    EntropySource startupEntropy = new EntropySource();

    // Consume the system properties list
    for (Enumeration<?> enu = sys.propertyNames(); enu.hasMoreElements(); ) {
      String key = (String) enu.nextElement();
      consumeString(key);
      consumeString(sys.getProperty(key));
    }

    // Consume the local IP address
    try {
      consumeString(InetAddress.getLocalHost().toString());
    } catch (Exception _) {
      // Ignore
    }
    readStartupEntropy(startupEntropy);

    readSeed(seed);
  }

  /**
   * Mixes basic JVM and system measurements into the entropy pools.
   *
   * <p>Current wall‑clock time, monotonic time, and memory statistics are sampled and credited with
   * conservative estimates. Subclasses may extend this to add more sources.
   *
   * @param startupEntropy logical source tracked for estimator state.
   */
  protected void readStartupEntropy(EntropySource startupEntropy) {
    // Consume the current time
    acceptEntropy(startupEntropy, System.currentTimeMillis(), 0);
    acceptEntropy(startupEntropy, System.nanoTime(), 0);
    // Free memory
    acceptEntropy(startupEntropy, Runtime.getRuntime().freeMemory(), 0);
    // Total memory
    acceptEntropy(startupEntropy, Runtime.getRuntime().totalMemory(), 0);
  }

  /**
   * Reads previously persisted seed material from the given file and mixes it into the pools.
   *
   * <p>The method reads up to 32 {@code long} values and credits a conservative amount of entropy
   * for each sample. End‑of‑file is treated as normal, and I/O errors are logged. A fast‑pool
   * reseeding is attempted after processing the file.
   *
   * @param filename seed file to read; must not be {@code null}.
   */
  @Override
  public void readSeed(File filename) {
    try (FileInputStream fis = new FileInputStream(filename);
        BufferedInputStream bis = new BufferedInputStream(fis);
        DataInputStream dis = new DataInputStream(bis)) {

      EntropySource seedFile = new EntropySource();
      for (int i = 0; i < 32; i++) acceptEntropy(seedFile, dis.readLong(), 64);
    } catch (EOFException _) {
      // End of file is acceptable; treat as a short seed file.
    } catch (IOException e) {
      LOG.error("IOE trying to read the seedfile from disk : {}", e.getMessage());
    }
    fastPoolReseed();
  }

  private long timeLastWroteSeed = -1;

  private void writeSeed(File filename) {
    writeSeed(filename, false);
  }

  /**
   * Persists seed material to the configured {@link #seedfile}.
   *
   * <p>When {@code force} is {@code false}, writes are rate‑limited to at most once per hour. When
   * {@code true}, the method writes immediately. The file must be configured at construction time.
   * Errors are logged and do not propagate.
   *
   * @param force request that the writing bypass rate‑limiting.
   */
  @Override
  public void writeSeed(boolean force) {
    writeSeed(seedfile, force);
  }

  private void writeSeed(File filename, boolean force) {
    if (!force)
      synchronized (this) {
        long now = System.currentTimeMillis();
        if (now - timeLastWroteSeed <= HOURS.toMillis(1) /* once per hour */) return;
        else timeLastWroteSeed = now;
      }

    try (FileOutputStream fos = new FileOutputStream(filename);
        BufferedOutputStream bos = new BufferedOutputStream(fos);
        DataOutputStream dos = new DataOutputStream(bos)) {

      for (int i = 0; i < 32; i++) dos.writeLong(nextLong());

      dos.flush();
    } catch (IOException e) {
      LOG.error("IOE while saving the seed file! : {}", e.getMessage());
    }
  }

  /** 5.1 Generation mechanism */
  private transient BlockCipher cipherCtx;

  private byte[] outputBuffer;
  private byte[] counter;
  private byte[] allZeroString;
  private byte[] tmp;
  // Persist the current generator key for serialization support.
  // This mirrors the last key passed to rekey(...) and allows restoring the cipher after
  // deserialization. Security note: this increases key exposure duration in memory compared to
  // holding it only inside the cipher; required for functional serialization.
  private byte[] generatorKey;
  private int outputCount;
  private int fetchCounter;

  private synchronized void generatorInit(String cipher) {
    cipherCtx = Util.getCipherByName(cipher);
    if (cipherCtx == null) {
      throw new IllegalStateException("Unsupported cipher: '" + cipher + "'");
    }
    outputBuffer = new byte[cipherCtx.getBlockSize() / 8];
    counter = new byte[cipherCtx.getBlockSize() / 8];
    allZeroString = new byte[cipherCtx.getBlockSize() / 8];
    tmp = new byte[cipherCtx.getKeySize() / 8];

    fetchCounter = outputBuffer.length;
  }

  private void counterInc() {
    for (int i = counter.length - 1; i >= 0; i--) if (++counter[i] != 0) break;
  }

  private synchronized void generateOutput() {
    counterInc();

    outputBuffer = new byte[counter.length];
    cipherCtx.encipher(counter, outputBuffer);

    if (outputCount++ > PG) {
      outputCount = 0;
      nextBytes(tmp);
      rekey(tmp);
    }
  }

  private synchronized void rekey(byte[] key) {
    // Keep a copy for serialization so we can restore the generator state after deserialization.
    // The input buffer is wiped immediately below.
    generatorKey = Arrays.copyOf(key, key.length);
    cipherCtx.initialize(key);
    counter = new byte[allZeroString.length];
    cipherCtx.encipher(allZeroString, counter);
    Arrays.fill(key, (byte) 0);
  }

  // Fetches {@code count} bytes of randomness into the shared buffer and returns the starting
  // offset into {@link #outputBuffer}. Generates a new block when the buffer is exhausted.
  private synchronized int getBytes(int count) {

    if (fetchCounter + count > outputBuffer.length) {
      fetchCounter = 0;
      generateOutput();
      return getBytes(count);
    }

    int rv = fetchCounter;
    fetchCounter += count;
    return rv;
  }

  static final int[][] bitTable = {
    {0, 0x0},
    {1, 0x1},
    {1, 0x3},
    {1, 0x7},
    {1, 0xf},
    {1, 0x1f},
    {1, 0x3f},
    {1, 0x7f},
    {1, 0xff},
    {2, 0x1ff},
    {2, 0x3ff},
    {2, 0x7ff},
    {2, 0xfff},
    {2, 0x1fff},
    {2, 0x3fff},
    {2, 0x7fff},
    {2, 0xffff},
    {3, 0x1ffff},
    {3, 0x3ffff},
    {3, 0x7ffff},
    {3, 0xfffff},
    {3, 0x1fffff},
    {3, 0x3fffff},
    {3, 0x7fffff},
    {3, 0xffffff},
    {4, 0x1ffffff},
    {4, 0x3ffffff},
    {4, 0x7ffffff},
    {4, 0xfffffff},
    {4, 0x1fffffff},
    {4, 0x3fffffff},
    {4, 0x7fffffff},
    {4, 0xffffffff}
  };

  // This may look more complicated than it is, but it is loop‑unrolled and optimized for cache and
  // arithmetic efficiency. Do not "simplify" unless you carefully re‑check statistical properties.
  // The method is synchronized to avoid repeats that occurred under concurrent access in the past.
  /**
   * Generates up to {@code bits} random bits using the Yarrow generator output.
   *
   * <p>This method draws from a block‑cipher stream constructed from an internal counter and
   * periodically rekeys the cipher to limit backtracking. The method is synchronized to preserve
   * {@link java.util.Random}'s thread‑safety guarantees.
   *
   * @param bits number of bits requested, typically in {@code [0,32]}.
   * @return the requested number of low‑order random bits.
   */
  @Override
  protected synchronized int next(int bits) {
    int[] parameters = bitTable[bits];
    int offset = getBytes(parameters[0]);

    int val = outputBuffer[offset] & 0xFF;

    if (parameters[0] == 4)
      val +=
          ((outputBuffer[offset + 1] & 0xFF) << 24)
              + ((outputBuffer[offset + 2] & 0xFF) << 16)
              + ((outputBuffer[offset + 3] & 0xFF) << 8);
    else if (parameters[0] == 3)
      val += ((outputBuffer[offset + 1] & 0xFF) << 16) + ((outputBuffer[offset + 2] & 0xFF) << 8);
    else if (parameters[0] == 2) val += (outputBuffer[offset + 1] & 0xFF) << 8;

    return val & parameters[1];
  }

  /** 5.2 Entropy accumulator */
  private transient MessageDigest fastPool;

  private transient MessageDigest slowPool;

  private int fastEntropy;
  private int slowEntropy;
  private boolean fastSelect;
  private transient Map<EntropySource, int[]> entropySeen;

  private synchronized void accumulatorInit(String digest) throws NoSuchAlgorithmException {
    fastPool = MessageDigest.getInstance(digest, Util.mdProviders.get(digest));
    slowPool = MessageDigest.getInstance(digest, Util.mdProviders.get(digest));
    entropySeen = new HashMap<>();
  }

  /**
   * {@inheritDoc}
   *
   * <p>Yarrow bounds credited entropy per sample and mixes data into alternating fast/slow pools.
   * Reseed may be triggered when pool thresholds are exceeded, which can also cause a seed file
   * writing if configured.
   */
  @Override
  public int acceptEntropy(EntropySource source, long data, int entropyGuess) {
    return acceptEntropy(source, data, entropyGuess, 1.0);
  }

  /**
   * {@inheritDoc}
   *
   * <p>Bytes are folded into 64‑bit chunks and processed as individual samples with the supplied
   * bias factor.
   */
  @Override
  public int acceptEntropyBytes(
      EntropySource source, byte[] buf, int offset, int length, double bias) {
    int totalRealEntropy = 0;
    for (int i = 0; i < length; i += 8) {
      long thingy = 0;
      int bytes = 0;
      for (int j = 0; j < Math.min(length, i + 8); j++) {
        thingy = (thingy << 8) + (buf[j] & 0xFF);
        bytes++;
      }
      totalRealEntropy += acceptEntropy(source, thingy, bytes * 8, bias);
    }
    return totalRealEntropy;
  }

  private int acceptEntropy(EntropySource source, long data, int entropyGuess, double bias) {
    return acceptEntropyInternal(
        data,
        source,
        (int) (bias * Math.min(32, Math.min(estimateEntropy(source, data), entropyGuess))));
  }

  private int acceptEntropyInternal(long data, EntropySource source, int actualEntropy) {

    boolean performedPoolReseed;
    byte[] b =
        new byte[] {
          (byte) data,
          (byte) (data >> 8),
          (byte) (data >> 16),
          (byte) (data >> 24),
          (byte) (data >> 32),
          (byte) (data >> 40),
          (byte) (data >> 48),
          (byte) (data >> 56)
        };

    synchronized (this) {
      fastSelect = !fastSelect;
      MessageDigest pool = (fastSelect ? fastPool : slowPool);
      pool.update(b);

      performedPoolReseed =
          fastSelect ? handleFastPath(actualEntropy) : handleSlowPath(source, actualEntropy);

      if (DEBUG) LOG.debug("Fast pool: {}\tSlow pool: {}", fastEntropy, slowEntropy);
    }
    if (performedPoolReseed && (seedfile != null)) {
      // Do not perform disk I/O while holding the monitor; opening files can be surprisingly slow
      // on Windows.
      if (LOG.isDebugEnabled()) LOG.debug("Writing seedfile");
      writeSeed(seedfile);
      if (LOG.isDebugEnabled()) LOG.debug("Written seedfile");
    }

    return actualEntropy;
  }

  private boolean handleFastPath(int actualEntropy) {
    fastEntropy += actualEntropy;
    if (fastEntropy > FAST_THRESHOLD) {
      fastPoolReseed();
      return true;
    }
    return false;
  }

  private boolean handleSlowPath(EntropySource source, int actualEntropy) {
    slowEntropy += actualEntropy;
    if (source != null) {
      updateSourceEntropy(source, actualEntropy);
      if (slowEntropy >= (SLOW_THRESHOLD * 2) && hasEnoughHighEntropySources()) {
        slowPoolReseed();
        return true;
      }
    }
    return false;
  }

  private void updateSourceEntropy(EntropySource source, int actualEntropy) {
    int[] contributedEntropy = entropySeen.get(source);
    if (contributedEntropy == null) {
      entropySeen.put(source, new int[] {actualEntropy});
    } else {
      contributedEntropy[0] += actualEntropy;
    }
  }

  private boolean hasEnoughHighEntropySources() {
    int kc = 0;
    for (Map.Entry<EntropySource, int[]> e : entropySeen.entrySet()) {
      EntropySource key = e.getKey();
      int[] v = e.getValue();
      if (DEBUG) LOG.info("Key: <{}> {}", key, v);
      if (v[0] > SLOW_THRESHOLD) {
        kc++;
        if (kc >= SLOW_K) {
          return true;
        }
      }
    }
    return false;
  }

  private int estimateEntropy(EntropySource source, long newVal) {
    int delta = (int) (newVal - source.lastVal);
    int delta2 = delta - source.lastDelta;
    source.lastDelta = delta;

    int delta3 = delta2 - source.lastDelta2;
    source.lastDelta2 = delta2;

    if (delta < 0) delta = -delta;
    if (delta2 < 0) delta2 = -delta2;
    if (delta3 < 0) delta3 = -delta3;
    if (delta > delta2) delta = delta2;
    if (delta > delta3) delta = delta3;

    /*
     * delta now holds the minimum absolute delta. Round down by one bit as a conservative
     * adjustment and limit the entropy estimate to 12 bits.
     */
    delta >>= 1;
    delta &= (1 << 12) - 1;

    /* Smear the most‑significant set bit to the right to make an n‑bit mask. */
    delta |= delta >> 8;
    delta |= delta >> 4;
    delta |= delta >> 2;
    delta |= delta >> 1;
    /* Remove one bit to approximate log2. */
    delta >>= 1;
    /* Count the set bits (population count). */
    delta -= (delta >> 1) & 0x555;
    delta = (delta & 0x333) + ((delta >> 2) & 0x333);
    delta += (delta >> 4);
    delta += (delta >> 8);

    source.lastVal = newVal;

    return delta & 15;
  }

  /**
   * {@inheritDoc}
   *
   * <p>Measures elapsed wall‑clock time since the previous sample from {@code timer} and treats it
   * as a 32‑bit sample subject to the estimator and biasing rules.
   */
  @Override
  public int acceptTimerEntropy(EntropySource timer) {
    return acceptTimerEntropy(timer, 1.0);
  }

  /**
   * {@inheritDoc}
   *
   * <p>The bias scales the contribution credited to the pools.
   */
  @Override
  public int acceptTimerEntropy(EntropySource timer, double bias) {
    long now = System.currentTimeMillis();
    return acceptEntropy(timer, now - timer.lastVal, 32, bias);
  }

  /** 5.3 Reseed mechanism */
  private static final int PT = 5;

  private transient MessageDigest reseedCtx;

  private synchronized void reseedInit(String digest) throws NoSuchAlgorithmException {
    reseedCtx = MessageDigest.getInstance(digest, Util.mdProviders.get(digest));
  }

  private synchronized void fastPoolReseed() {
    byte[] v0 = fastPool.digest();
    byte[] vi = v0;

    for (byte i = 0; i < PT; i++) {
      reseedCtx.update(vi, 0, vi.length);
      reseedCtx.update(v0, 0, v0.length);
      reseedCtx.update(i);
      vi = reseedCtx.digest();
    }

    // vPt=vi
    Util.makeKey(vi, tmp, 0, tmp.length);
    rekey(tmp);
    Arrays.fill(v0, (byte) 0); // Actively wipe intermediate state for security
    fastEntropy = 0;
  }

  private synchronized void slowPoolReseed() {
    byte[] slowHash = slowPool.digest();
    fastPool.update(slowHash, 0, slowHash.length);

    fastPoolReseed();
    slowEntropy = 0;

    entropySeen.clear();
  }

  /**
   * Custom serialization to rebuild transient crypto state after deserialization.
   *
   * <p>Persisted fields record the selected digest and cipher, along with enough generator states
   * to restore the cipher. Upon deserialization, transient pools and the cipher context are
   * recreated and reinitialized.
   */
  @Serial
  private void writeObject(ObjectOutputStream out) throws IOException {
    out.defaultWriteObject();
  }

  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    // Provide sensible defaults if older serialized forms lacked these fields
    String d = (digestName != null) ? digestName : "SHA1";
    String c = (cipherName != null) ? cipherName : DEFAULT_CIPHER;
    try {
      // Rebuild accumulator/reseed contexts (transient) with empty digests.
      accumulatorInit(d);
      reseedInit(d);

      // Recreate only the cipher instance and reinitialize it with the previously serialized key.
      // Do NOT clobber the serialized generator state (counter/outputBuffer/tmp/fetch counters).
      cipherCtx =
          Objects.requireNonNull(Util.getCipherByName(c), "Unsupported cipher: '" + c + "'");

      int blockBytes = cipherCtx.getBlockSize() / 8;
      int keyBytes = cipherCtx.getKeySize() / 8;

      // Backward/defensive: ensure arrays exist and match sizes; create if missing.
      if (outputBuffer == null || outputBuffer.length != blockBytes) {
        outputBuffer = new byte[blockBytes];
      }
      if (counter == null || counter.length != blockBytes) {
        counter = new byte[blockBytes];
      }
      if (allZeroString == null || allZeroString.length != blockBytes) {
        allZeroString = new byte[blockBytes];
      }
      if (tmp == null || tmp.length != keyBytes) {
        tmp = new byte[keyBytes];
      }

      // Restore the key into cipher. Prefer the explicitly persisted generatorKey; fall back to
      // 'tmp'
      // for backward compatibility with snapshots taken before this field existed.
      byte[] keyForInit =
          (generatorKey != null && generatorKey.length == keyBytes) ? generatorKey : tmp;
      cipherCtx.initialize(keyForInit);

      // Sanity for the fetch pointer after custom streams or old snapshots.
      if (fetchCounter <= 0 || fetchCounter > outputBuffer.length) {
        fetchCounter = outputBuffer.length;
      }

      // Entropy accounting must reflect that pools are empty after deserialization.
      fastEntropy = 0;
      slowEntropy = 0;
      // 'entropySeen' was reinitialized in accumulatorInit(); 'fastSelect' can remain as-is.
    } catch (NoSuchAlgorithmException e) {
      throw new IOException("Failed to reinitialize Yarrow after deserialization", e);
    }
  }

  /** 5.4 Reseed control parameters */
  private static final int FAST_THRESHOLD = 100;

  private static final int SLOW_THRESHOLD = 160;
  private static final int SLOW_K = 2;

  /**
   * Releases resources held by this generator.
   *
   * <p>This implementation does not hold external resources and performs no action.
   */
  @Override
  public void close() {
    // Intentionally blank: no external resources to close.
  }

  private void consumeString(String str) {
    consumeBytes(str.getBytes(StandardCharsets.UTF_8));
  }

  private synchronized void consumeBytes(byte[] bytes) {
    if (fastSelect) fastPool.update(bytes, 0, bytes.length);
    else slowPool.update(bytes, 0, bytes.length);
    // Alternate pools to distribute contributions across fast/slow accumulators.
    fastSelect = !fastSelect;
  }
}
