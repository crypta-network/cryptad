package network.crypta.crypt;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import network.crypta.support.Fields;
import network.crypta.support.Loader;
import network.crypta.support.math.MersenneTwister;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Miscellaneous cryptographic and binary utilities.
 *
 * <p>This class provides helpers for digest selection, byte/primitive conversions, MPI
 * (multi-precision integer) encoding, keyed material derivation, stream reads, and small math/array
 * operations commonly used across the cryptography package. All methods are stateless and
 * thread-safe unless otherwise noted.
 */
public class Util {
  private static final Logger LOG = LoggerFactory.getLogger(Util.class);

  // Crypto utility methods:
  /** Constant {@link BigInteger} value for 2. */
  public static final BigInteger TWO = BigInteger.valueOf(2);

  /**
   * Mapping from message-digest algorithm name to the selected {@link Provider}.
   *
   * <p>The map is populated during class initialization by benchmarking the default provider
   * against the JCE {@code SUN} provider (when available) for a small hashing workload. The faster
   * provider for each algorithm is recorded. The map is unmodifiable and safe for concurrent reads.
   *
   * <p>Keys use standard JCA names (for example, {@code "SHA1"}, {@code "MD5"}, {@code "SHA-256"},
   * {@code "SHA-384"}, {@code "SHA-512"}).
   */
  public static final Map<String, Provider> mdProviders;

  /** Utility class. */
  private Util() {
    throw new IllegalStateException("Utility class");
  }

  static {
    try {
      HashMap<String, Provider> mdProvidersInternal = new HashMap<>();

      for (String algo : new String[] {"SHA1", "MD5", "SHA-256", "SHA-384", "SHA-512"}) {
        final Provider sun = JceLoader.SUN;
        MessageDigest md = MessageDigest.getInstance(algo);
        md.digest();
        if (sun != null) {
          // Compare the default provider with SUN and keep the faster instance when possible.
          md = pickFasterDigest(algo, sun, md);
        }
        Provider mdProvider = md.getProvider();
        LOG.info("{}: using {}", algo, mdProvider);
        mdProvidersInternal.put(algo, mdProvider);
      }
      mdProviders = Collections.unmodifiableMap(mdProvidersInternal);
    } catch (NoSuchAlgorithmException e) {
      // impossible
      throw new IllegalStateException(e);
    }
  }

  @SuppressWarnings("java:S1181") // we really want to catch Throwable here
  private static MessageDigest pickFasterDigest(String algo, Provider sun, MessageDigest md) {
    try {
      MessageDigest sunMd = MessageDigest.getInstance(algo, sun);
      sunMd.digest();
      if (md.getProvider() != sunMd.getProvider()) {
        long timeDef = benchmark(md);
        long timeSun = benchmark(sunMd);
        LOG.debug(
            "event=digest.benchmark.default algo={} provider={} timeNs={}",
            algo,
            md.getProvider(),
            timeDef);
        LOG.debug(
            "event=digest.benchmark.sun algo={} provider={} timeNs={}",
            algo,
            sunMd.getProvider(),
            timeSun);
        if (timeSun < timeDef) {
          return sunMd;
        }
      }
    } catch (GeneralSecurityException e) {
      // ignore
      LOG.warn("event=digest.benchmark.warn algo={} provider={}", algo, sun, e);
    } catch (Throwable e) {
      // ignore
      LOG.error("event=digest.benchmark.error algo={} provider={}", algo, sun, e);
    }
    return md;
  }

  // BigInteger note:
  // - BigInteger.toByteArray() and the BigInteger(byte[]) constructor are compatible.
  // - The unsigned magnitude length equals ceil((bitLength() + 1) / 8).

  /**
   * Writes {@code ints} into {@code bytes} using big-endian order.
   *
   * @param ints source integers
   * @param bytes destination; must have length {@code 4 * ints.length}
   * @throws ArrayIndexOutOfBoundsException if {@code bytes} is too small (no bounds checks are
   *     performed prior to writes)
   */
  public static void fillByteArrayFromInts(int[] ints, byte[] bytes) {
    int ic = 0;
    for (int i : ints) {
      bytes[ic++] = (byte) (i >> 24);
      bytes[ic++] = (byte) (i >> 16);
      bytes[ic++] = (byte) (i >> 8);
      bytes[ic++] = (byte) i;
    }
  }

  /**
   * Writes {@code ints} into {@code bytes} using big-endian order.
   *
   * @param ints source longs
   * @param bytes destination; must have length {@code 8 * ints.length}
   * @throws ArrayIndexOutOfBoundsException if {@code bytes} is too small
   */
  public static void fillByteArrayFromLongs(long[] ints, byte[] bytes) {
    int ic = 0;
    for (long l : ints) {
      bytes[ic++] = (byte) (l >> 56);
      bytes[ic++] = (byte) (l >> 48);
      bytes[ic++] = (byte) (l >> 40);
      bytes[ic++] = (byte) (l >> 32);
      bytes[ic++] = (byte) (l >> 24);
      bytes[ic++] = (byte) (l >> 16);
      bytes[ic++] = (byte) (l >> 8);
      bytes[ic++] = (byte) l;
    }
  }

  /**
   * Encodes a {@link BigInteger} as an MPI (multi-precision integer).
   *
   * <p>Format: two-byte big-endian bit length followed by the big-endian magnitude bytes. The sign
   * is not stored; this method treats the value as non-negative.
   *
   * @param num integer to encode (interpreted as non-negative)
   * @return a new byte array containing the MPI representation
   */
  public static byte[] mpiBytes(BigInteger num) {
    int len = num.bitLength();
    byte[] bytes = new byte[2 + ((len + 8) >> 3)];
    System.arraycopy(num.toByteArray(), 0, bytes, 2, bytes.length - 2);
    bytes[0] = (byte) (len >> 8);
    bytes[1] = (byte) len;
    return bytes;
  }

  /**
   * Writes the MPI encoding of {@code num} to {@code out}.
   *
   * @param num integer to encode (interpreted as non-negative)
   * @param out destination stream
   * @throws IOException if the stream writing fails
   */
  public static void writeMPI(BigInteger num, OutputStream out) throws IOException {
    out.write(mpiBytes(num));
  }

  /**
   * Reads an MPI-encoded integer from {@code in}.
   *
   * <p>Expects a two-byte big-endian bit-length header followed by that many bits of size rounded
   * up to a whole number of bytes. The returned value is constructed with a positive signum.
   *
   * @param in source stream
   * @return decoded non-negative {@link BigInteger}
   * @throws EOFException if the stream ends before the header or body is fully read
   * @throws IOException on I/O errors
   */
  public static BigInteger readMPI(InputStream in) throws IOException {
    int b1 = in.read();
    int b2 = in.read();
    if ((b1 == -1) || (b2 == -1)) throw new EOFException();
    byte[] data = new byte[(((b1 << 8) + b2) + 8) >> 3];
    readFully(in, data, 0, data.length);
    // Construct with signum=1 to force a non-negative result regardless of the leading bit.
    return new BigInteger(1, data);
  }

  /**
   * Computes {@code d(b)} and returns the digest.
   *
   * @param d message-digest instance (not reset by this call other than via {@link
   *     MessageDigest#digest()})
   * @param b input bytes
   * @return digest output of length {@code d.getDigestLength()}
   */
  public static byte[] hashBytes(MessageDigest d, byte[] b) {
    return hashBytes(d, b, 0, b.length);
  }

  /**
   * Computes the digest of a subrange of {@code b}.
   *
   * @param d message-digest instance
   * @param b input buffer
   * @param offset first byte to hash (0-based)
   * @param length number of bytes to hash
   * @return digest output
   * @throws ArrayIndexOutOfBoundsException if the range is invalid
   */
  public static byte[] hashBytes(MessageDigest d, byte[] b, int offset, int length) {
    d.update(b, offset, length);
    return d.digest();
  }

  /**
   * Hashes a string using UTF-8 bytes.
   *
   * @param d message-digest instance
   * @param s string to hash; encoded as UTF-8
   * @return digest output
   */
  public static byte[] hashString(MessageDigest d, String s) {
    byte[] sbytes = s.getBytes(StandardCharsets.UTF_8);
    d.update(sbytes, 0, sbytes.length);
    return d.digest();
  }

  /**
   * Returns a byte-wise XOR of {@code b1} and {@code b2} for the overlapping prefix.
   *
   * <p>The returned array has length {@code max(b1.length, b2.length)}. Bytes beyond {@code
   * min(b1.length, b2.length)} are left as zero in the result.
   *
   * @param b1 first operand
   * @param b2 second operand
   * @return XOR result; unused tail bytes (if any) are {@code 0}
   */
  public static byte[] xor(byte[] b1, byte[] b2) {
    int maxl = Math.max(b1.length, b2.length);
    byte[] rv = new byte[maxl];

    int minl = Math.min(b1.length, b2.length);
    for (int i = 0; i < minl; i++) rv[i] = (byte) (b1[i] ^ b2[i]);
    return rv;
  }

  /**
   * Fills the entire buffer with random bytes using {@link SecureRandom#nextBytes(byte[])}.
   *
   * @param r secure random source
   * @param buf destination buffer
   */
  public static void randomBytes(SecureRandom r, byte[] buf) {
    r.nextBytes(buf);
  }

  /**
   * Fills a subrange of {@code buf} with random bytes from a {@link SecureRandom}.
   *
   * @param r secure random source
   * @param buf destination buffer
   * @param from starting index (inclusive)
   * @param len number of bytes to fill
   * @throws ArrayIndexOutOfBoundsException if the range is invalid
   */
  public static void randomBytes(SecureRandom r, byte[] buf, int from, int len) {
    randomBytesSlowNextInt(r, buf, from, len);
  }

  /** Fill a specified range of byte arrays with random data. */
  private static void randomBytesSlowNextInt(Random r, byte[] buf, int from, int len) {
    if (from == 0 && len == buf.length) {
      r.nextBytes(buf);
      return;
    }
    byte[] tmp = new byte[len];
    r.nextBytes(tmp);
    System.arraycopy(tmp, 0, buf, from, len);
  }

  /**
   * Fills the entire buffer with random data. Equivalent to {@link Random#nextBytes(byte[])}.
   *
   * @param r random source
   * @param buf destination buffer
   */
  public static void randomBytes(Random r, byte[] buf) {
    randomBytes(r, buf, 0, buf.length);
  }

  /**
   * Fills a subrange with random data.
   *
   * <p>Optimized for {@link MersenneTwister} by using {@link Random#nextInt()} to generate four
   * bytes per call. Falls back to a compatible, slower path for other {@link Random}
   * implementations. Behavior matches {@link #randomBytesSlowNextInt(Random, byte[], int, int)};
   * equivalence is required.
   *
   * @param r random source
   * @param buf destination buffer
   * @param from starting index (inclusive)
   * @param len number of bytes to fill
   * @throws ArrayIndexOutOfBoundsException if the range is invalid
   */
  /*
   * Rationale: {@code Random} lacks a range-aware {@code nextBytes(buf, from, len)} method, so we
   * implement a compatible variant here.
   */
  public static void randomBytes(Random r, byte[] buf, int from, int len) {
    if (!(r instanceof MersenneTwister)) {
      /* SecureRandom.nextInt() is slow; use the compatible fallback for non-MersenneTwister. */
      /* More generally, the optimized path is only guaranteed for MersenneTwister. */
      randomBytesSlowNextInt(r, buf, from, len);
      return;
    }
    final int to = from + len;
    while (from + 4 <= to) {
      int rnd = r.nextInt();
      buf[from++] = (byte) rnd;
      rnd >>= 8;
      buf[from++] = (byte) rnd;
      rnd >>= 8;
      buf[from++] = (byte) rnd;
      rnd >>= 8;
      buf[from++] = (byte) rnd;
    }
    if (to > from) {
      for (int rnd = r.nextInt(); from < to; rnd >>= 8) buf[from++] = (byte) rnd;
    }
  }

  /**
   * Compares two byte arrays for equality over a range.
   *
   * <p>Prefer {@link Fields#byteArrayEqual(byte[], byte[], int, int, int)} for new code.
   *
   * @param a first array
   * @param b second array
   * @param offset starting index in both arrays
   * @param length number of bytes to compare
   * @return {@code true} if all compared bytes are equal; {@code false} otherwise
   */
  public static boolean byteArrayEqual(byte[] a, byte[] b, int offset, int length) {
    return Fields.byteArrayEqual(a, b, offset, offset, length);
  }

  // Micro-benchmarks a digest implementation; returns the minimum observed duration.
  private static long benchmark(MessageDigest md) throws GeneralSecurityException {
    long times = Long.MAX_VALUE;
    byte[] input = new byte[1024];
    byte[] output = new byte[md.getDigestLength()];
    // warm-up
    for (int i = 0; i < 32; i++) {
      md.update(input, 0, input.length);
      md.digest(output, 0, output.length);
      System.arraycopy(
          output, 0, input, (i * output.length) % (input.length - output.length), output.length);
    }
    for (int i = 0; i < 128; i++) {
      long startTime = System.nanoTime();
      for (int j = 0; j < 4; j++) {
        for (int k = 0; k < 32; k++) {
          md.update(input, 0, input.length);
        }
        md.digest(output, 0, output.length);
      }
      long endTime = System.nanoTime();
      times = Math.min(endTime - startTime, times);
      System.arraycopy(output, 0, input, 0, output.length);
    }
    return times;
  }

  /**
   * Derives {@code len} bytes of key material from {@code entropy} using iterative SHA-1.
   *
   * <p>The method repeatedly hashes a counter of zero bytes followed by {@code entropy} until the
   * requested number of bytes has been produced. On completion, {@code entropy} is zeroed in place.
   *
   * @param entropy input entropy; cleared to zeros before return
   * @param key destination buffer
   * @param offset starting index into {@code key}
   * @param len number of key bytes to write
   * @throws IllegalStateException if the digest unexpectedly fails
   */
  public static void makeKey(byte[] entropy, byte[] key, int offset, int len) {
    try {
      MessageDigest ctx = HashType.SHA1.get();
      int ctxLength = ctx.getDigestLength();

      int ic = 0;
      while (len > 0) {
        ic++;
        for (int i = 0; i < ic; i++) ctx.update((byte) 0);
        ctx.update(entropy, 0, entropy.length);
        int bc;
        if (len > ctxLength) {
          ctx.digest(key, offset, ctxLength);
          bc = ctxLength;
        } else {
          byte[] hash = ctx.digest();
          bc = Math.min(len, hash.length);
          System.arraycopy(hash, 0, key, offset, bc);
        }
        offset += bc;
        len -= bc;
      }
      Arrays.fill(entropy, (byte) 0);
    } catch (DigestException e) {
      // impossible
      throw new IllegalStateException(e);
    }
  }

  /**
   * Instantiates a {@link BlockCipher} by simple class name.
   *
   * <p>The class is looked up under {@code network.crypta.crypt.ciphers.}{@code name} and must have
   * a no-arg constructor.
   *
   * @param name simple cipher class name (e.g., {@code "AES"})
   * @return a cipher instance, or {@code null} if instantiation fails
   */
  public static BlockCipher getCipherByName(String name) {
    try {
      return (BlockCipher) Loader.getInstance("network.crypta.crypt.ciphers." + name);
    } catch (Exception e) {
      LOG.debug("getCipherByName failed for {}", name, e);
      return null;
    }
  }

  /**
   * Instantiates a {@link BlockCipher} by simple class name with a key-size constructor.
   *
   * <p>The class is looked up under {@code network.crypta.crypt.ciphers.}{@code name} and must
   * declare a constructor taking a single {@link Integer} key-size parameter.
   *
   * @param name simple cipher class name
   * @param keySize key size in bits (constructor argument)
   * @return a cipher instance, or {@code null} if instantiation fails
   */
  public static BlockCipher getCipherByName(String name, int keySize) {
    try {
      return (BlockCipher)
          Loader.getInstance(
              "network.crypta.crypt.ciphers." + name,
              new Class<?>[] {Integer.class},
              new Object[] {keySize});
    } catch (Exception e) {
      LOG.debug("getCipherByName(name,keySize) failed for {}", name, e);
      return null;
    }
  }

  /** Returns ceil(log2(n)) for {@code n >= 1}; returns 0 for {@code n <= 1}. */
  public static int log2(long n) {
    int log2 = 0;
    while ((log2 < 63) && (1L << log2 < n)) ++log2;
    return log2;
  }

  /**
   * Reads exactly {@code b.length} bytes into {@code b}.
   *
   * @param in source stream
   * @param b destination buffer
   * @throws EOFException if the stream ends before filling the buffer
   * @throws IOException on I/O errors
   */
  public static void readFully(InputStream in, byte[] b) throws IOException {
    readFully(in, b, 0, b.length);
  }

  /**
   * Reads exactly {@code length} bytes into {@code b} starting at {@code off}.
   *
   * @param in source stream
   * @param b destination buffer
   * @param off offset into {@code b}
   * @param length number of bytes to read
   * @throws EOFException if the stream ends before the requested bytes are read
   * @throws IOException on I/O errors
   */
  public static void readFully(InputStream in, byte[] b, int off, int length) throws IOException {
    int total = 0;
    while (total < length) {
      int got = in.read(b, off + total, length - total);
      if (got == -1) {
        throw new EOFException();
      }
      total += got;
    }
  }

  /**
   * Interprets the leading eight bytes of a digest as a signed {@code long} and maps it to {@code
   * [0.0, 1.0]}.
   *
   * <p>Uses {@link Math#abs(long)} with a guard for {@link Long#MIN_VALUE}, then divides by {@link
   * Long#MAX_VALUE}.
   *
   * @param digest byte array containing a digest (at least eight bytes)
   * @return normalized double in {@code [0.0, 1.0]}
   */
  public static double keyDigestAsNormalizedDouble(byte[] digest) {
    long asLong = Math.abs(Fields.bytesToLong(digest));
    // Math.abs can actually return negative...
    if (asLong == Long.MIN_VALUE) asLong = Long.MAX_VALUE;
    return ((double) asLong) / ((double) Long.MAX_VALUE);
  }
}
