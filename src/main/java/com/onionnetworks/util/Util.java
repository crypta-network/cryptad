// (c) Copyright 2000 Justin F. Chapweske
// (c) Copyright 2000 Ry4an C. Brase

package com.onionnetworks.util;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.Objects;

/**
 * Utility toolbox for byte/char manipulations, numeric helpers, lightweight reflection, and
 * convenience conversions.
 *
 * <p>The class centralizes a handful of low-level routines that are reused across the legacy
 * OnionNetworks codebase. Typical call sites include encoding and decoding byte buffers, scrubbing
 * sensitive arrays, generating hex dumps for diagnostics, performing deterministic rounding, and
 * discovering public methods in reflection-heavy paths. All methods are static and side effect free
 * except for operations that intentionally mutate caller-supplied arrays.
 *
 * <p>Thread-safety: the class is stateless aside from the shared {@link SecureRandom} instance used
 * by the shuffle helpers. Access to that instance is thread-safe because {@code SecureRandom}
 * itself is synchronized; tests may replace it via the package-scoped setter to achieve repeatable
 * randomness. The zeroing helpers reuse cached zero-filled buffers for efficiency but never expose
 * them to callers.
 *
 * <ul>
 *   <li>Array primitives: conversions between {@code byte[]} and {@code char[]}, equality checks on
 *       sub-ranges, safe zeroing of sensitive data.
 *   <li>Encoding helpers: hexadecimal rendering and parsing plus Unix-style hex dump formatting for
 *       debugging binary payloads.
 *   <li>Reflection aids: tolerant public-method discovery that accepts assignable parameter types.
 * </ul>
 *
 * @see #bytesToHex(byte[])
 * @see #hexToBytes(String)
 * @see #getPublicMethod(Class, String, Class[])
 */
public class Util {

  private static final int MAX_ZERO_COPY = 16384;
  private static byte[] zeroBytes;
  private static char[] zeroChars;
  private static final char[] hexDigit =
      new char[] {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

  // Must be global for shuffle
  private static SecureRandom rand = initSecureRandom();

  private Util() {
    throw new IllegalStateException("Utility class");
  }

  private static SecureRandom initSecureRandom() {
    try {
      return SecureRandom.getInstance("SHA1PRNG");
    } catch (NoSuchAlgorithmException _) {
      return new SecureRandom();
    }
  }

  /**
   * Returns the shared {@link SecureRandom} instance backing the shuffle helpers and any other
   * utilities that need nondeterministic bytes.
   *
   * <p>The generator is lazily initialized using the {@code SHA1PRNG} algorithm when available and
   * falls back to the platform default if that algorithm is missing. Callers receive the live
   * instance; no additional seeding or cloning is performed, so state evolves globally across
   * threads. Tests can swap in a deterministic generator via {@link
   * #setRandForTesting(SecureRandom)} to stabilize outcomes without altering production behavior.
   *
   * @return a process-wide {@code SecureRandom} suitable for general-purpose, blocking-safe use.
   */
  public static SecureRandom getRand() {
    return rand;
  }

  /**
   * Replaces the shared {@link SecureRandom} used by this class.
   *
   * <p>This hook exists exclusively for tests that need reproducible randomness. The provided
   * instance is stored directly and therefore must be thread-safe; {@code SecureRandom} already
   * provides synchronized access. Passing {@code null} is not allowed and will raise a {@link
   * NullPointerException} through {@link Objects#requireNonNull(Object)}.
   *
   * @param secureRandom replacement generator to use for subsequent shuffle operations.
   */
  static void setRandForTesting(SecureRandom secureRandom) {
    rand = Objects.requireNonNull(secureRandom);
  }

  /**
   * Serializes a 32-bit integer into a big-endian four-byte array.
   *
   * <p>The method allocates a fresh array on each call and writes the most significant byte first.
   * The returned buffer is independent of the input value and can be modified by the caller without
   * affecting future invocations. Use this when interoperating with network protocols or file
   * formats that require network byte order but do not expose {@link java.nio.ByteBuffer} APIs.
   *
   * @param i integer value converted into big-endian four bytes.
   * @return four-byte array representing {@code i} in big-endian order.
   */
  @SuppressWarnings("PointlessBitwiseExpression")
  public static byte[] getBytes(int i) {
    byte[] b = new byte[4];
    b[0] = (byte) ((i >>> 24) & 0xFF);
    b[1] = (byte) ((i >>> 16) & 0xFF);
    b[2] = (byte) ((i >>> 8) & 0xFF);
    b[3] = (byte) ((i >>> 0) & 0xFF);
    return b;
  }

  /**
   * Reconstructs a 32-bit integer from a big-endian four-byte array.
   *
   * <p>The input buffer must contain at least four bytes starting at index zero; no bounds checks
   * are performed beyond direct array access. Each byte is treated as unsigned during assembly,
   * producing the same value emitted by {@link #getBytes(int)}. Mutations to the input after the
   * call do not affect the returned primitive.
   *
   * @param b four-byte big-endian buffer containing the encoded integer value.
   * @return integer reconstructed from the first four bytes of {@code b}.
   */
  public static int getInt(byte[] b) {
    return (((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16) | ((b[2] & 0xFF) << 8) | (b[3] & 0xFF));
  }

  /**
   * Fills a segment of a byte array with zeroes without allocating temporary buffers.
   *
   * <p>The method mirrors the classic C {@code bzero} routine: it clears {@code len} bytes starting
   * at {@code off} using a cached zero-filled block to reduce per-call allocations. For large
   * regions it repeatedly doubles the cleared section to keep memory copies local and limit cache
   * thrashing. Callers must ensure the specified range is within the array bounds; this method does
   * not perform explicit range checks beyond the arraycopy operations themselves.
   *
   * @param b target byte array cleared in the specified range.
   * @param off starting index within {@code b} to begin zeroing.
   * @param len number of bytes to clear; zero leaves the array unchanged.
   */
  public static void bzero(byte[] b, int off, int len) {
    if (zeroBytes == null) {
      zeroBytes = new byte[64];
    }
    if (len < zeroBytes.length) {
      System.arraycopy(zeroBytes, 0, b, off, len);
      return;
    } else {
      System.arraycopy(zeroBytes, 0, b, off, zeroBytes.length);
    }

    int zeroLength = zeroBytes.length;
    do {
      int delta = len - zeroLength;
      int copyLength = Math.min(zeroLength, delta);
      if (copyLength > MAX_ZERO_COPY) {
        copyLength = MAX_ZERO_COPY;
      }
      // We copy from close to the current position so we aren't
      // thrashing mem for really large buffers.
      System.arraycopy(b, off + zeroLength - copyLength, b, off + zeroLength, copyLength);
      zeroLength += copyLength;
    } while (zeroLength < len);
  }

  /**
   * Fills a segment of a char array with the {@code '\0'} character using an efficient doubling
   * copy strategy.
   *
   * <p>The approach parallels {@link #bzero(byte[], int, int)} by priming a cached zero-filled
   * buffer and repeatedly expanding it until the requested {@code len} region is cleared. The
   * algorithm minimizes the number of distinct memory regions touched, which reduces cache pressure
   * when wiping large character arrays such as password buffers. The operation mutates the caller's
   * array directly and performs no explicit bounds validation beyond the underlying array copies.
   *
   * @param b target char array cleared for the requested range.
   * @param off starting character index; must remain within array bounds.
   * @param len character count to clear; non-positive values do nothing.
   */
  public static void bzero(char[] b, int off, int len) {
    if (zeroChars == null) {
      zeroChars = new char[64];
    }
    if (len < zeroChars.length) {
      System.arraycopy(zeroChars, 0, b, off, len);
      return;
    } else {
      System.arraycopy(zeroChars, 0, b, off, zeroChars.length);
    }

    int zeroLength = zeroChars.length;
    do {
      int delta = len - zeroLength;
      int copyLength = Math.min(zeroLength, delta);
      if (copyLength > MAX_ZERO_COPY) {
        copyLength = MAX_ZERO_COPY;
      }
      // We copy from close to the current position so we aren't
      // thrashing mem for really large buffers.
      System.arraycopy(b, off + zeroLength - copyLength, b, off + zeroLength, copyLength);
      zeroLength += copyLength;
    } while (zeroLength < len);
  }

  /**
   * Produces a string consisting solely of space characters.
   *
   * <p>The method delegates to {@link String#repeat(int)} while guarding against negative inputs by
   * clamping the requested length to zero. It is typically used to pad diagnostic output or align
   * text when constructing ad-hoc tables without introducing third-party dependencies. Returned
   * strings are intern-free and may be reused or modified by the caller as needed.
   *
   * @param num requested number of space characters; negatives become zero.
   * @return string of {@code num} spaces or empty when clamped.
   */
  public static String getSpaces(int num) {
    return " ".repeat(Math.max(0, num));
  }

  /**
   * Compares two integer arrays for equality over a specified range.
   *
   * <p>The comparison starts at {@code start1} in {@code arr1} and {@code start2} in {@code arr2}
   * and proceeds for {@code len} elements. Iteration walks backward to reduce bounds checks and
   * branch mispredictions. Equality is determined by direct value comparison; no tolerance or
   * overflow handling is applied. Supplying identical arrays with identical offsets short-circuits
   * to {@code true} immediately.
   *
   * @param arr1 first int array supplying the left-hand slice.
   * @param start1 offset in {@code arr1} where comparison begins.
   * @param arr2 second int array supplying the right-hand slice.
   * @param start2 offset in {@code arr2} aligned to {@code start1}.
   * @param len element count to compare; zero short-circuits to true.
   * @return true when every compared element matches; false otherwise.
   */
  public static boolean arraysEqual(int[] arr1, int start1, int[] arr2, int start2, int len) {
    if (arr1 == arr2 && start1 == start2) {
      return true;
    }
    for (int i = len - 1; i >= 0; i--) {
      if (arr1[start1 + i] != arr2[start2 + i]) {
        return false;
      }
    }
    return true;
  }

  /**
   * Compares segments of two {@code long} arrays for strict equality.
   *
   * <p>The method walks from the end of the requested range toward the beginning to avoid repeated
   * offset arithmetic inside the loop. This is a straightforward byte-for-byte comparison with no
   * tolerance for {@code null} arrays or mismatched lengths; callers must validate ranges
   * beforehand to avoid exceptions. Identical array references with matching start indices shortcut
   * to {@code true}.
   *
   * @param arr1 first long array supplying the left-hand slice.
   * @param start1 starting index within {@code arr1}; must be non-negative.
   * @param arr2 second long array providing the comparison slice.
   * @param start2 starting index within {@code arr2} paired with {@code start1}.
   * @param len elements compared in both arrays; zero returns {@code true}.
   * @return true when all compared long values match; false otherwise.
   */
  public static boolean arraysEqual(long[] arr1, int start1, long[] arr2, int start2, int len) {
    if (arr1 == arr2 && start1 == start2) {
      return true;
    }
    for (int i = len - 1; i >= 0; i--) {
      if (arr1[start1 + i] != arr2[start2 + i]) {
        return false;
      }
    }
    return true;
  }

  /**
   * Tests equality across slices of two {@code char} arrays.
   *
   * <p>The comparison is case-sensitive and uses direct character equality; no locale conversions
   * or normalization are performed. The method iterates backward across {@code len} elements to
   * minimize index arithmetic. Passing the same array reference with identical start offsets skips
   * the loop entirely for a fast path.
   *
   * @param arr1 first character array holding the left-hand slice.
   * @param start1 starting index within {@code arr1} used for comparison.
   * @param arr2 second character array providing the right-hand slice.
   * @param start2 starting index within {@code arr2} paired to {@code start1}.
   * @param len number of characters compared; zero marks the arrays equal.
   * @return true if all compared characters match exactly; false otherwise.
   */
  public static boolean arraysEqual(char[] arr1, int start1, char[] arr2, int start2, int len) {
    if (arr1 == arr2 && start1 == start2) {
      return true;
    }
    for (int i = len - 1; i >= 0; i--) {
      if (arr1[start1 + i] != arr2[start2 + i]) {
        return false;
      }
    }
    return true;
  }

  /**
   * Performs range-based equality testing for two {@code byte} arrays.
   *
   * <p>The method compares {@code len} elements starting at {@code start1} and {@code start2}
   * respectively, iterating from the end toward the beginning. This approach keeps the hot indices
   * near each other, which can improve cache behavior on large buffers. Callers are responsible for
   * ensuring the ranges are valid; a malformed range will produce the usual array bounds
   * exceptions.
   *
   * @param arr1 first byte array to check within the given slice.
   * @param start1 starting index in {@code arr1}; must be non-negative.
   * @param arr2 second byte array supplying the comparison slice.
   * @param start2 starting index in {@code arr2} aligned with {@code start1}.
   * @param len number of bytes compared; zero returns {@code true}.
   * @return true when each compared byte matches; false otherwise.
   */
  public static boolean arraysEqual(byte[] arr1, int start1, byte[] arr2, int start2, int len) {
    if (arr1 == arr2 && start1 == start2) {
      return true;
    }
    for (int i = len - 1; i >= 0; i--) {
      if (arr1[start1 + i] != arr2[start2 + i]) {
        return false;
      }
    }
    return true;
  }

  /**
   * Randomly permutes the contents of an integer array in place using the Fisher–Yates algorithm.
   *
   * <p>The implementation walks backward from the end of the array, selecting a random index within
   * the remaining prefix using the shared {@link SecureRandom} instance. Swaps are skipped when the
   * randomly chosen position matches the current index to avoid needless writes. This operation
   * mutates the provided array and is safe for reuse across threads because the randomness source
   * is thread-safe.
   *
   * @param list integer array shuffled in place using unbiased swaps.
   */
  public static void shuffle(int[] list) {
    for (int i = list.length - 1; i >= 0; i--) {
      int j = rand.nextInt(i + 1);
      if (i == j) {
        continue;
      }
      int tmp = list[i];
      list[i] = list[j];
      list[j] = tmp;
    }
  }

  /**
   * Randomly permutes a boolean array in place using Fisher–Yates with a shared {@link
   * SecureRandom} source.
   *
   * <p>Each iteration selects a swap partner from the prefix {@code [0, i]} where {@code i}
   * decreases toward zero. No additional allocations occur, making this suitable for performance
   * sensitive code that needs unbiased shuffling of flags or bitfield-derived values. The provided
   * array is modified directly; callers should copy first if the original ordering must be
   * preserved elsewhere.
   *
   * @param list boolean array shuffled in place; contents are mutated.
   */
  public static void shuffle(boolean[] list) {
    for (int i = list.length - 1; i >= 0; i--) {
      int j = rand.nextInt(i + 1);
      if (i == j) {
        continue;
      }
      boolean tmp = list[i];
      list[i] = list[j];
      list[j] = tmp;
    }
  }

  /**
   * Shuffles the contents of an object array in place using Fisher–Yates and the shared randomness
   * provider.
   *
   * <p>The algorithm swaps elements from the end toward the beginning, yielding an unbiased
   * permutation when {@link SecureRandom#nextInt(int)} produces uniform results. References are
   * swapped directly without cloning or defensive copying, so downstream readers observe the new
   * ordering immediately. Passing {@code null} values in the array is permitted; they are shuffled
   * like any other element.
   *
   * @param list object array permuted in place; {@code null} elements are allowed.
   */
  public static void shuffle(Object[] list) {
    for (int i = list.length - 1; i >= 0; i--) {
      int j = rand.nextInt(i + 1);
      if (i == j) {
        continue;
      }
      Object tmp = list[i];
      list[i] = list[j];
      list[j] = tmp;
    }
  }

  /**
   * Converts a {@code char[]} to a big-endian {@code byte[]} representation.
   *
   * <p>Each character is expanded into two bytes: the high-order byte first, followed by the
   * low-order byte. The returned array length is exactly twice the input length. This helper is
   * primarily intended for legacy protocols that treat Java char values as unsigned 16&nbsp;bit
   * quantities rather than UTF-16 text; no charset encoding is performed.
   *
   * @param chars characters expanded into two big-endian bytes each.
   * @return byte array twice the length containing encoded characters.
   */
  public static byte[] getBytes(char[] chars) {
    byte[] retval = new byte[chars.length * 2];
    arraycopy(chars, 0, retval, 0, retval.length);
    return retval;
  }

  /**
   * Reassembles a {@code char[]} from a big-endian {@code byte[]} stream.
   *
   * <p>The input length must be even because two bytes are required per character; otherwise an
   * {@link IllegalArgumentException} is thrown. Bytes are combined in big-endian order, mirroring
   * {@link #getBytes(char[])}. No character set decoding is attempted; the raw 16-bit values are
   * reconstructed exactly as stored.
   *
   * @param bytes even-length byte array holding paired character bytes.
   * @return char array reconstructed from the provided byte pairs.
   * @throws IllegalArgumentException thrown when the byte length is odd.
   */
  public static char[] getChars(byte[] bytes) {
    int len = bytes.length;
    if (len % 2 != 0) {
      throw new IllegalArgumentException("Input array.length non-even.");
    }
    char[] retval = new char[len / 2];
    arraycopy(bytes, 0, retval, 0, len);
    return retval;
  }

  /**
   * Copies characters into a byte buffer using big-endian ordering.
   *
   * <p>The method writes up to {@code numBytes} bytes starting at {@code charOff} in the source and
   * {@code byteOff} in the destination. Two bytes are emitted for each character until the
   * requested byte count is satisfied; an odd {@code numBytes} results in only the high byte of the
   * trailing character being written. This is a low-level utility and performs only minimal bounds
   * checking via the underlying array operations.
   *
   * @param chars source character array; its contents are not mutated.
   * @param charOff starting character offset within {@code chars}; must be non-negative.
   * @param bytes destination byte array receiving the encoded data.
   * @param byteOff offset within {@code bytes} where writing begins.
   * @param numBytes total number of bytes to transfer; odd values write a partial character.
   */
  public static void arraycopy(char[] chars, int charOff, byte[] bytes, int byteOff, int numBytes) {
    int indexCounter = byteOff;
    int loopMax = numBytes / 2 + charOff;
    for (int i = charOff; i < loopMax; i++) {
      bytes[indexCounter++] = (byte) ((chars[i] & 0xFF00) >> 8);
      bytes[indexCounter++] = (byte) (chars[i] & 0xFF);
    }
    // copy the straggler, if any.
    if (numBytes % 2 != 0) {
      bytes[indexCounter] = (byte) ((chars[loopMax] & 0xFF00) >> 8);
    }
  }

  /**
   * Dumps a byte array to a UNIX style hex dump. This isn't terribly efficient so you should
   * probably try to limit it to debug code.
   *
   * <p>The output mirrors classic {@code hexdump -C} formatting: offsets are displayed in octal
   * with fixed-width padding, bytes are grouped in sixteen-per-line rows, and intra-line spacing
   * separates four-byte blocks. This helper avoids allocations beyond the result {@link String}
   * builder and is intended for diagnostics rather than hot paths.
   *
   * @param b byte array to render; the full array length is processed sequentially.
   * @return formatted hex dump string suitable for logging or test assertions.
   */
  public static String getHexDump(byte[] b) {
    int pos = 0;
    final int INDEX_WIDTH = 7;
    final String ZEROS = "0000000"; // must be at least INDEX_WIDTH length
    StringBuilder sb = new StringBuilder();
    while (pos < b.length) {
      if ((pos % 16) == 0) {
        if (pos > 0) {
          sb.append("\n");
        }
        String index = Integer.toOctalString(pos);
        sb.append(ZEROS, 0, INDEX_WIDTH - index.length());
        sb.append(index).append(" ");
      } else if ((pos % 4) == 0) {
        sb.append(" ");
      }
      String val = Integer.toHexString(b[pos] & 0xFF);
      if (val.length() == 1) {
        sb.append("0");
      }
      sb.append(val);
      pos++;
    }
    return sb.toString();
  }

  /**
   * Copies bytes into a {@code char[]} using big-endian reconstruction.
   *
   * <p>Pairs of bytes are combined into char values until either {@code numBytes} are consumed or
   * the destination range is filled. If {@code numBytes} is odd, the high byte of the final
   * character is written and the low byte is implicitly zero. This routine complements {@link
   * #arraycopy(char[], int, byte[], int, int)} and is useful when handling compact binary encodings
   * of UTF-16 code units.
   *
   * @param bytes source byte array containing big-endian character data.
   * @param byteOff starting byte offset used for decoding characters.
   * @param chars destination char array receiving reconstructed values.
   * @param charOff starting index within destination char array.
   * @param numBytes byte count to process; odd counts leave low byte zero.
   */
  public static void arraycopy(byte[] bytes, int byteOff, char[] chars, int charOff, int numBytes) {
    int indexCounter = byteOff;
    int loopMax = numBytes / 2 + charOff;
    for (int i = charOff; i < loopMax; i++) {
      chars[i] = (char) (((bytes[indexCounter++] & 0xFF) << 8) | (bytes[indexCounter++] & 0xFF));
    }
    // copy the straggler, if any.
    if (numBytes % 2 != 0) {
      chars[loopMax] = (char) ((bytes[indexCounter] & 0xFF) << 8);
    }
  }

  /**
   * Divides two integers and rounds the result up when a remainder exists.
   *
   * <p>The computation uses integer arithmetic: {@code num / denom} plus one when {@code num} is
   * not evenly divisible by {@code denom}. This is a common helper for pagination, buffer sizing,
   * or chunked processing where an extra slot is needed to hold leftover elements. No overflow
   * checks are performed; callers should ensure denominators are non-zero to avoid division errors.
   *
   * @param num dividend being partitioned into equal-sized buckets.
   * @param denom divisor representing bucket size; must be non-zero.
   * @return quotient rounded upward when a remainder is present.
   */
  public static int divideCeil(int num, int denom) {
    return num / denom + ((num % denom == 0) ? 0 : 1);
  }

  /**
   * Divides two {@code long} values and rounds the quotient upward when needed.
   *
   * <p>The method mirrors {@link #divideCeil(int, int)} but operates on wider operands and casts
   * the final result back to {@code int}. Use this when computing counts based on long-running byte
   * totals or timestamps while still needing an integer result for indexing or sizing.
   *
   * @param num long dividend used for large counters or lengths.
   * @param denom long divisor defining chunk size; must be positive.
   * @return rounded-up quotient cast to int; may truncate overflow.
   */
  public static int divideCeil(long num, long denom) {
    return (int) (num / denom + ((num % denom == 0) ? 0 : 1));
  }

  /**
   * Computes the base-2 logarithm of a floating-point value.
   *
   * <p>The calculation delegates to {@link Math#log(double)} and divides by the natural logarithm
   * of two, providing a portable alternative on platforms lacking {@code Math.log2}. Negative or
   * zero inputs will yield {@code NaN} or {@code -Infinity} according to {@link Math#log(double)}
   * semantics; callers should validate domain restrictions before invoking this helper.
   *
   * @param a value whose base-2 logarithm is desired; must be positive for finite results.
   * @return base-2 logarithm of {@code a}, matching double precision semantics of {@link Math#log}.
   */
  public static double log2(double a) {
    return Math.log(a) / Math.log(2);
  }

  /**
   * Renders the contents of a {@link Buffer} as a lowercase hexadecimal string.
   *
   * <p>The method respects the buffer's internal offset and length fields, delegating to {@link
   * #bytesToHex(byte[], int, int)} to perform the conversion. Output uses two characters per byte
   * and contains no separators or prefixes. This is primarily a convenience wrapper when callers
   * already hold a {@code Buffer} structure rather than a raw array slice.
   *
   * @param b buffer exposing {@code b}, {@code off}, and {@code len} fields.
   * @return hexadecimal string for the buffer slice; never {@code null}.
   */
  public static String bytesToHex(Buffer b) {
    return bytesToHex(b.b, b.off, b.len);
  }

  /**
   * Converts an entire byte array to a lowercase hexadecimal string.
   *
   * <p>Each byte becomes two hexadecimal characters using the digits {@code 0-9a-f}. The method
   * processes the full array starting at index zero and does not insert spacing or line breaks.
   * This helper is suitable for logging identifiers or computing textual digests without involving
   * {@link java.util.Formatter}.
   *
   * @param in byte array to encode; may be empty but not {@code null}.
   * @return two-characters-per-byte hexadecimal string covering the full array.
   */
  public static String bytesToHex(byte[] in) {
    return bytesToHex(in, 0, in.length);
  }

  /**
   * Encodes a subsequence of a byte array into lowercase hexadecimal text.
   *
   * <p>The conversion begins at {@code off} and spans {@code len} bytes, emitting two characters
   * per byte. The returned string length is therefore {@code len * 2}. This method performs no
   * validation on the bounds beyond the underlying array accesses and assumes the caller has
   * verified the slice is within the array.
   *
   * @param in source byte array containing the data to encode.
   * @param off starting index within {@code in}; must be non-negative and within bounds.
   * @param len number of bytes to encode; determines half of the resulting string length.
   * @return new string containing the hexadecimal representation of the requested slice.
   */
  public static String bytesToHex(byte[] in, int off, int len) {
    char[] out = new char[in.length * 2];
    for (int i = 0; i < len; i++) {
      out[i * 2] = hexDigit[(0xF0 & in[i + off]) >> 4]; // high nybble
      out[i * 2 + 1] = hexDigit[0xF & in[i + off]]; // low nybble
    }
    return new String(out);
  }

  /**
   * Parses a lowercase or uppercase hexadecimal string into a {@code byte[]} representation.
   *
   * <p>The input length must be even because two characters represent a single byte. Each pair of
   * characters is decoded using {@link Integer#parseInt(String, int)} with radix 16; invalid digits
   * trigger an {@link IllegalArgumentException} wrapping the original {@link
   * NumberFormatException}. No whitespace trimming is performed, so callers should pre-sanitize
   * external inputs.
   *
   * @param in hexadecimal text with an even number of characters; case-insensitive.
   * @return newly allocated byte array containing the decoded values in order.
   * @throws IllegalArgumentException if the length is odd or parsing fails for any pair.
   */
  public static byte[] hexToBytes(String in) {
    int len = in.length();
    if (len % 2 != 0) {
      throw new IllegalArgumentException("Even length string expected.");
    }
    byte[] out = new byte[len / 2];
    try {
      for (int i = 0; i < out.length; i++) {
        out[i] = (byte) Integer.parseInt(in.substring(i * 2, i * 2 + 2), 16);
      }
    } catch (NumberFormatException doh) {
      throw new IllegalArgumentException("ParseError", doh);
    }
    return out;
  }

  /**
   * Check if an IP address is probably inside a NAT. Data culled from RFC 790.
   *
   * <p>The method inspects the four-byte IPv4 address and classifies it as NAT-like when it falls
   * into well-known private ranges: 10/8, 192.168/16, 192.0.0.1/32, or 223.255.255/24. Addresses
   * outside those ranges are treated as publicly routable, though no DNS or routing checks are
   * performed. Input validation ensures the array length is exactly four bytes.
   *
   * @param addr four-byte IPv4 address in network byte order; must not be {@code null}.
   * @return {@code true} when the address matches a recognized private or special-use block.
   * @throws IllegalArgumentException if {@code addr.length} is not equal to four bytes.
   */
  public static boolean isProbablyNat(byte[] addr) {
    if (addr.length != 4) {
      throw new IllegalArgumentException("Address must be 4 bytes long");
    }
    int a = 0xFF & addr[0];
    int b = 0xFF & addr[1];
    int c = 0xFF & addr[2];
    return ((a == 10)
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && c == 1)
        || (a == 223 && b == 255 && c == 255));
  }

  /**
   * Class.getMethod requires exact parameters for the types. This method is more fuzzy and just
   * finds the first one that works. This class will also prefer public classes/methods.
   *
   * <p>The search climbs the class hierarchy, preferring public types and interfaces, and selects
   * the first method whose name matches and whose parameter types are assignable from the provided
   * {@code types} array. Exact length matching is required, but covariant parameter compatibility
   * is allowed. This is particularly useful when reflecting on proxies or subclasses where the
   * runtime signature may be compatible but not identical to the requested types.
   *
   * @param clazz starting class whose hierarchy will be inspected.
   * @param name method name to match exactly, case-sensitive.
   * @param types parameter types that must be assignable from candidates.
   * @return first public compatible method found across the class hierarchy.
   * @throws NoSuchMethodException thrown when no matching public method exists anywhere.
   */
  public static Method getPublicMethod(Class<?> clazz, String name, Class<?>[] types)
      throws NoSuchMethodException {

    Class<?> c = clazz;
    while (c != null) {
      if (Modifier.isPublic(c.getModifiers())) {
        Method m = getMethod(c.getMethods(), name, types);
        if (m != null) {
          return m;
        }
      }

      // check the interfaces.
      Class<?>[] interfs = clazz.getInterfaces();
      for (Class<?> interf : interfs) {
        if (!Modifier.isPublic(interf.getModifiers())) {
          continue;
        }
        Method m = getMethod(interf.getMethods(), name, types);
        if (m != null) {
          return m;
        }
      }
      // climb up the superclass chain.
      c = c.getSuperclass();
    }
    throw new NoSuchMethodException();
  }

  /**
   * Locates a public method in the supplied array that matches the requested signature.
   *
   * <p>The method iterates through {@code methods}, looking for a public entry whose name matches
   * {@code name}, whose parameter count equals {@code types.length}, and whose parameter types are
   * assignable from the supplied {@code types}. It returns the first such match or {@code null}
   * when none qualify. This helper underpins {@link #getPublicMethod(Class, String, Class[])} and
   * centralizes the signature comparison logic.
   *
   * @param methods candidate methods, typically from {@link Class#getMethods()} results.
   * @param name target method name; compared using {@link String#equals(Object)}.
   * @param types parameter types that must be assignable to parameters.
   * @return matching public method or {@code null} when no candidate fits.
   */
  public static Method getMethod(Method[] methods, String name, Class<?>[] types) {

    for (Method method : methods) {
      if (Modifier.isPublic(method.getModifiers())
          && name.equals(method.getName())
          && types.length == method.getParameterTypes().length) {

        if (types.length == 0) {
          return method;
        }

        for (int j = 0; j < types.length; j++) {
          if (!method.getParameterTypes()[j].isAssignableFrom(types[j])) {
            break;
          } else if (j == types.length - 1) {
            return method;
          }
        }
      }
    }
    return null;
  }

  /**
   * Creates an {@link IntIterator} view over a standard {@link Iterator} of {@link Integer}
   * objects.
   *
   * <p>The returned iterator forwards calls directly to the backing {@code Iterator}, unboxing
   * values on demand. Removal operations delegate to the underlying iterator's {@code remove}
   * method, preserving its semantics and error behavior. This adapter is useful when consuming APIs
   * that expect primitive-oriented iteration without rewriting existing collections or stream
   * logic.
   *
   * @param it backing iterator supplying boxed integers to adapt.
   * @return primitive-friendly iterator delegating to the supplied source.
   */
  public static IntIterator createIntIterator(final Iterator<Integer> it) {
    return new IntIterator() {
      @Override
      public boolean hasNextInt() {
        return it.hasNext();
      }

      @Override
      public int nextInt() {
        return it.next();
      }

      @Override
      public void removeInt() {
        it.remove();
      }
    };
  }
}
