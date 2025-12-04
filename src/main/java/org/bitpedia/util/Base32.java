/* (PD) 2006 The Bitzi Corporation
 * Please see http://bitzi.com/publicdomain for more info.
 *
 * $Id: Base32.java,v 1.2 2006/07/14 04:58:39 gojomo Exp $
 */

package org.bitpedia.util;

import java.util.logging.Logger;

/**
 * Base32 encodes and decodes data using the RFC 3548 alphabet without padding.
 *
 * <p>This utility offers a minimal, allocation-conscious implementation that keeps behavior
 * identical to the historical Bitzi version. It targets scenarios where small payloads need a
 * stable textual representation, such as compact tokens, file identifiers, and command-line
 * diagnostics. The class is stateless and thread-safe because all methods are static and operate
 * solely on caller-owned buffers.
 *
 * <p>Notable characteristics:
 *
 * <ul>
 *   <li>Uses the canonical Base32 alphabet ({@code A-Z2-7}) and omits {@code =} padding characters.
 *   <li>Ignores characters outside the alphabet during decoding rather than failing fast.
 *   <li>Optimizes shifts to avoid temporary byte arrays while preserving deterministic output.
 * </ul>
 *
 * <p>Typical flow: supply a byte array to {@link #encode(byte[])} to obtain its textual form, then
 * later feed that string to {@link #decode(String)} to restore the original bytes. Because padding
 * is omitted, consumers must rely on external framing to detect truncation. Input arguments must be
 * non-null; callers retain ownership of provided buffers.
 *
 * @author Robert Kaye
 * @author Gordon Mohr
 */
public class Base32 {
  private static final String BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  private static final int[] BASE32_LOOKUP = {
    0xFF, 0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, // '0', '1', '2', '3', '4', '5', '6', '7'
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // '8', '9', ':', ';', '<', '=', '>', '?'
    0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G'
    0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, // 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O'
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, // 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W'
    0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 'X', 'Y', 'Z', '[', '\', ']', '^', '_'
    0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g'
    0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, // 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o'
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, // 'p', 'q', 'r', 's', 't', 'u', 'v', 'w'
    0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF // 'x', 'y', 'z', '{', '|', '}', '~', 'DEL'
  };

  /**
   * Constructs a new {@code Base32} instance without retaining state.
   *
   * <p>All functionality is exposed via static methods, so instantiation is optional and generally
   * unnecessary. The constructor exists solely for frameworks or tooling that expect a concrete
   * object reference. Creating an instance does not allocate additional resources or change
   * internal caches, and repeated construction is effectively free aside from the object header.
   * Callers should prefer the static utility methods unless dependency injection or reflective
   * creation requires an instance.
   */
  public Base32() {
    // Constructor intentionally empty because the utility holds no instance state or resources.
  }

  /**
   * Encodes a byte array into an unpadded RFC 3548 Base32 string.
   *
   * <p>The method processes the input five bits at a time, mapping each chunk to the canonical
   * {@code A-Z2-7} alphabet. No line breaks or padding characters are emitted. The operation is
   * deterministic and idempotent for identical inputs. Supplying an empty array returns an empty
   * string; passing {@code null} results in a {@link NullPointerException}.
   *
   * <p>Example usage:
   *
   * <pre>{@code
   * byte[] payload = new byte[] {0x01, 0x23, (byte) 0xFF};
   * String encoded = Base32.encode(payload); // yields "AID7"
   * }</pre>
   *
   * @param bytes byte array to encode; must be non-null and remains unmodified by this call
   * @return Base32 representation of {@code bytes} using uppercase alphabet without padding
   */
  public static String encode(final byte[] bytes) {
    if (bytes.length == 0) {
      return "";
    }

    int buffer = bytes[0] & 0xFF;
    int nextIndex = 1;
    int bitsLeft = 8;
    StringBuilder base32 = new StringBuilder((bytes.length + 7) * 8 / 5);

    while (bitsLeft > 0 || nextIndex < bytes.length) {
      if (bitsLeft < 5) {
        if (nextIndex < bytes.length) {
          buffer = buffer << 8 | bytes[nextIndex] & 0xFF;
          bitsLeft += 8;
          nextIndex++;
        } else {
          buffer <<= 5 - bitsLeft;
          bitsLeft = 5;
        }
      }

      int index = buffer >> bitsLeft - 5 & 0x1F;
      bitsLeft -= 5;
      base32.append(BASE32_CHARS.charAt(index));
    }

    return base32.toString();
  }

  /**
   * Decodes an unpadded Base32 string into its original byte sequence.
   *
   * <p>The decoder tolerates and skips characters outside the Base32 alphabet so callers may pass
   * strings containing whitespace or incidental punctuation. Bits are reassembled in order; when
   * the input length is not a multiple of eight characters, the final byte may be partially filled,
   * mirroring the behavior of the original Bitzi implementation. The returned array has a
   * predictable length of {@code (input.length() * 5) / 8}. Passing {@code null} triggers a {@link
   * NullPointerException}.
   *
   * <p>Example usage:
   *
   * <pre>{@code
   * byte[] restored = Base32.decode("AID7");
   * }</pre>
   *
   * @param base32 text to decode; characters outside {@code A-Z2-7} are ignored rather than failing
   *     the operation
   * @return newly allocated byte array containing the decoded data in original order
   */
  public static byte[] decode(final String base32) {
    byte[] bytes = new byte[base32.length() * 5 / 8];
    int index = 0;
    int offset = 0;
    int position = 0;

    while (position < base32.length() && offset < bytes.length) {
      int digit = toBase32Digit(base32.charAt(position));
      position++;
      if (digit < 0) {
        continue;
      }

      if (index <= 3) {
        index = (index + 5) % 8;
        if (index == 0) {
          bytes[offset] = (byte) (bytes[offset] | digit);
          offset++;
        } else {
          bytes[offset] = (byte) (bytes[offset] | digit << 8 - index & 0xFF);
        }
      } else {
        index = (index + 5) % 8;
        bytes[offset] = (byte) (bytes[offset] | digit >>> index & 0xFF);
        offset++;
        if (offset < bytes.length) {
          bytes[offset] = (byte) (bytes[offset] | digit << 8 - index & 0xFF);
        }
      }
    }
    return bytes;
  }

  /**
   * Command-line helper that decodes a Base32 argument, prints hex, and re-encodes it.
   *
   * <p>This method is intended for quick manual verification. It logs the original string, the
   * decoded bytes expressed in lowercase hexadecimal, and the re-encoded Base32 value to
   * demonstrate round-trip fidelity. When no arguments are supplied, it emits usage guidance and
   * exits without performing conversions.
   *
   * @param args command-line arguments where {@code args[0]} should hold a Base32-encoded payload;
   *     additional elements are ignored
   */
  public static void main(String[] args) {
    if (args.length == 0) {
      LOGGER.info("Supply a Base32-encoded argument.");
      return;
    }
    LOGGER.info(() -> " Original: " + args[0]);
    byte[] decoded = Base32.decode(args[0]);
    LOGGER.info(() -> "      Hex: " + toHex(decoded));
    LOGGER.info(() -> "Re-encoded: " + Base32.encode(decoded));
  }

  private static int toBase32Digit(char character) {
    int lookup = character - '0';
    if (lookup < 0 || lookup >= BASE32_LOOKUP.length) {
      return -1;
    }
    int digit = BASE32_LOOKUP[lookup];
    return digit == 0xFF ? -1 : digit;
  }

  private static String toHex(byte[] decoded) {
    StringBuilder hex = new StringBuilder(decoded.length * 2);
    for (byte value : decoded) {
      int unsigned = value & 0xFF;
      hex.append(Integer.toHexString(unsigned + 256).substring(1));
    }
    return hex.toString();
  }

  private static final Logger LOGGER = Logger.getLogger(Base32.class.getName());
}
