package network.crypta.support;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Base64 utilities for encoding bytes/strings and decoding Base64 text.
 *
 * <p>This class supports two alphabets:
 *
 * <ul>
 *   <li>A modified, URL‑friendly alphabet using {@code '~'} and {@code '-'} for indices 62 and 63;
 *       this is <strong>not</strong> RFC&nbsp;4648 nor the common URL‑safe variant.
 *   <li>The standard Base64 alphabet using {@code '+'} and {@code '/'}, compatible with
 *       RFC&nbsp;4648.
 * </ul>
 *
 * <p>Padding: The standard alphabet encoders always pad with {@code '='} to a length that is a
 * multiple of four characters. Modified alphabet encoders allow the caller to request padding; the
 * unpadded form omits trailing {@code '='}. Decoders accept both padded and unpadded input and
 * ignore trailing {@code '='}.
 *
 * <p>All methods are {@code static} and thread‑safe. Passing {@code null} to any method results in
 * a {@link NullPointerException}. Encoding/decoding runs in O(n) time.
 *
 * @author Stephen Blackheath
 */
public class Base64 {
  private Base64() {}

  static final Charset UTF8 = StandardCharsets.UTF_8;

  private static final char[] base64Alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~-".toCharArray();

  private static final char[] base64StandardAlphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

  /** A reverse lookup table to convert Base64 characters back into 6‑bit values. */
  private static final byte[] base64Reverse;

  private static final byte[] base64StandardReverse;

  // Populate reverse lookup tables from both alphabets.
  static {
    base64Reverse = new byte[128];
    base64StandardReverse = new byte[base64Reverse.length];

    // Initialize entries to 0xFF to mark illegal Base64 characters.
    for (int i = 0; i < base64Reverse.length; i++) {
      base64Reverse[i] = (byte) 0xFF;
      base64StandardReverse[i] = (byte) 0xFF;
    }
    for (int i = 0; i < base64Alphabet.length; i++) {
      base64Reverse[base64Alphabet[i]] = (byte) i;
      base64StandardReverse[base64StandardAlphabet[i]] = (byte) i;
    }
  }

  /**
   * Encodes bytes using the modified (non‑standard) Base64 alphabet without padding.
   *
   * @param in source bytes; must not be {@code null}
   * @return Base64 text using the modified alphabet with no trailing {@code '='}
   */
  public static String encode(byte[] in) {
    return encode(in, false);
  }

  /* Overload that allows callers to request '=' padding when using the modified alphabet. */
  /**
   * Encodes bytes using the modified (non‑standard) Base64 alphabet with optional padding.
   *
   * <p>When {@code equalsPad} is {@code true}, the result is padded to a length that is a multiple
   * of four characters. When {@code false}, no padding is added and the length may not be a
   * multiple of four.
   *
   * @param in source bytes; must not be {@code null}
   * @param equalsPad whether to append {@code '='} padding
   * @return Base64 text using the modified alphabet
   */
  public static String encode(byte[] in, boolean equalsPad) {
    return encode(in, equalsPad, base64Alphabet);
  }

  /**
   * Encodes a UTF‑8 {@link String} using the modified alphabet without padding.
   *
   * @param in text to encode; must not be {@code null}
   * @return Base64 text using the modified alphabet with no trailing {@code '='}
   */
  public static String encodeUTF8(String in) {
    return encodeUTF8(in, false);
  }

  /**
   * Encodes a UTF‑8 {@link String} using the modified alphabet with optional padding.
   *
   * @param in text to encode; must not be {@code null}
   * @param equalsPad whether to append {@code '='} padding
   * @return Base64 text using the modified alphabet
   */
  public static String encodeUTF8(String in, boolean equalsPad) {
    return encode(in.getBytes(UTF8), equalsPad, base64Alphabet);
  }

  /**
   * Encodes a UTF‑8 {@link String} using the standard Base64 alphabet with padding.
   *
   * @param in text to encode; must not be {@code null}
   * @return Base64 text using the standard alphabet padded with {@code '='}
   */
  public static String encodeStandardUTF8(String in) {
    return encodeStandard(in.getBytes(UTF8));
  }

  /**
   * Encodes bytes using the standard Base64 alphabet with padding.
   *
   * @param in source bytes; must not be {@code null}
   * @return Base64 text using the standard alphabet padded with {@code '='}
   */
  public static String encodeStandard(byte[] in) {
    return encode(in, true, base64StandardAlphabet);
  }

  /* Core encoder used by both alphabets. {@code equalsPad} toggles '=' padding. */
  private static String encode(byte[] in, boolean equalsPad, char[] alphabet) {
    char[] out = new char[((in.length + 2) / 3) * 4];
    int rem = in.length % 3;
    int o = 0;
    int i = 0;
    while (i < in.length) {
      int val = (in[i++] & 0xFF) << 16;
      if (i < in.length) val |= (in[i++] & 0xFF) << 8;
      if (i < in.length) val |= (in[i++] & 0xFF);
      out[o++] = alphabet[(val >> 18) & 0x3F];
      out[o++] = alphabet[(val >> 12) & 0x3F];
      out[o++] = alphabet[(val >> 6) & 0x3F];
      out[o++] = alphabet[val & 0x3F];
    }
    int outLen =
        switch (rem) {
          case 1 -> out.length - 2;
          case 2 -> out.length - 1;
          default -> out.length;
        };
    // Pad with '=' signs up to a multiple of four if requested.
    if (equalsPad) while (outLen < out.length) out[outLen++] = '=';
    return new String(out, 0, outLen);
  }

  /**
   * Decodes Base64 text using the modified alphabet.
   *
   * <p>Accepts both padded and unpadded input. Trailing {@code '='} is ignored.
   *
   * @param inStr Base64 text using the modified alphabet; must not be {@code null}
   * @return decoded bytes
   * @throws IllegalBase64Exception if the input contains illegal characters or the effective length
   *     (after trimming trailing {@code '='}) is invalid (length mod 4 == 1)
   */
  public static byte[] decode(String inStr) throws IllegalBase64Exception {
    return decode(inStr, base64Reverse);
  }

  /**
   * Decodes Base64 text (modified alphabet) and returns a UTF‑8 {@link String}.
   *
   * @param inStr Base64 text using the modified alphabet; must not be {@code null}
   * @return decoded text as UTF‑8
   * @throws IllegalBase64Exception if the input is not valid Base64 in the modified alphabet
   */
  public static String decodeUTF8(String inStr) throws IllegalBase64Exception {
    return new String(decode(inStr), UTF8);
  }

  /**
   * Decodes Base64 text using the standard alphabet.
   *
   * <p>Accepts both padded and unpadded input. Trailing {@code '='} is ignored.
   *
   * @param inStr Base64 text using the standard alphabet; must not be {@code null}
   * @return decoded bytes
   * @throws IllegalBase64Exception if the input contains illegal characters or the effective length
   *     (after trimming trailing {@code '='}) is invalid (length mod 4 == 1)
   */
  public static byte[] decodeStandard(String inStr) throws IllegalBase64Exception {
    return decode(inStr, base64StandardReverse);
  }

  /*
   * Core decoder shared by both alphabets.
   *
   * Implementation detail: Trims trailing '=' padding, then processes full 4‑character blocks. The
   * remainder determines how many output bytes follow. Any character that does not map to a 6‑bit
   * value in the selected alphabet yields an IllegalBase64Exception. When the (unpadded) length
   * mod 4 == 1, the length is illegal and an exception is thrown.
   */
  private static byte[] decode(String inStr, byte[] reverseAlphabet) throws IllegalBase64Exception {
    try {
      char[] in = inStr.toCharArray();
      int inLength = in.length;

      // Strip trailing '=' padding ignored by the decoder.
      while ((inLength > 0) && (in[inLength - 1] == '=')) inLength--;

      int blocks = inLength / 4;
      int remainder = inLength & 3;
      // wholeInLen/wholeOutLen exclude any partial block at the end.
      int wholeInLen = blocks * 4;
      int wholeOutLen = blocks * 3;
      int outLen =
          switch (remainder) {
            case 1 -> throw new IllegalBase64Exception("illegal Base64 length");
            case 2 -> wholeOutLen + 1;
            case 3 -> wholeOutLen + 2;
            default -> wholeOutLen;
          };
      byte[] out = new byte[outLen];
      int o = 0;
      int i = 0;
      while (i < wholeInLen) {
        int in1 = reverseAlphabet[in[i]];
        int in2 = reverseAlphabet[in[i + 1]];
        int in3 = reverseAlphabet[in[i + 2]];
        int in4 = reverseAlphabet[in[i + 3]];
        int orValue = in1 | in2 | in3 | in4;
        if ((orValue & 0x80) != 0) throw new IllegalBase64Exception("illegal Base64 character");
        int outVal = (in1 << 18) | (in2 << 12) | (in3 << 6) | in4;
        out[o] = (byte) (outVal >> 16);
        out[o + 1] = (byte) (outVal >> 8);
        out[o + 2] = (byte) outVal;
        i += 4;
        o += 3;
      }
      int orValue =
          switch (remainder) {
            case 2 -> {
              int in1 = reverseAlphabet[in[i]];
              int in2 = reverseAlphabet[in[i + 1]];
              int outVal = (in1 << 18) | (in2 << 12);
              out[o] = (byte) (outVal >> 16);
              yield in1 | in2;
            }
            case 3 -> {
              int in1 = reverseAlphabet[in[i]];
              int in2 = reverseAlphabet[in[i + 1]];
              int in3 = reverseAlphabet[in[i + 2]];
              int outVal = (in1 << 18) | (in2 << 12) | (in3 << 6);
              out[o] = (byte) (outVal >> 16);
              out[o + 1] = (byte) (outVal >> 8);
              yield in1 | in2 | in3;
            }
            default -> 0;
          };
      if ((orValue & 0x80) != 0) throw new IllegalBase64Exception("illegal Base64 character");
      return out;
    }
    // Illegal characters can cause an ArrayIndexOutOfBoundsException when
    // looking up reverseAlphabet.
    catch (ArrayIndexOutOfBoundsException _) {
      throw new IllegalBase64Exception("illegal Base64 character");
    }
  }
}
