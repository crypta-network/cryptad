package network.crypta.platform.api;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Supplies canonical SHA-256 handling for baseline definitions and lifecycle records.
 *
 * <p>This package-private helper keeps digest validation and length-delimited canonical encoding
 * identical across definitions, lineage entries, and registries. It accepts only lowercase
 * hexadecimal SHA-256 values and hashes UTF-8 canonical text. Length-prefixing each optional field
 * prevents concatenation ambiguity without exposing a second serialization format. Callers build
 * domain-separated canonical text in a fixed field order, then use this class for validation and
 * hashing. The class is stateless and thread-safe; it does not read files, select release evidence,
 * or authenticate the artifact that supplied a digest.
 */
final class PlatformApiBaselineDigest {
  /** Matches the canonical lowercase hexadecimal representation of one SHA-256 value. */
  private static final Pattern SHA_256 = Pattern.compile("[0-9a-f]{64}");

  /** Prevents construction of this stateless package utility. */
  private PlatformApiBaselineDigest() {}

  /**
   * Validates and returns a canonical SHA-256 value.
   *
   * @param value the lowercase hexadecimal digest to validate
   * @param fieldName the field name used in validation failures
   * @return the supplied digest after successful validation
   * @throws NullPointerException if {@code value} is {@code null}
   * @throws IllegalArgumentException if the value is not a lowercase SHA-256 digest
   */
  static String requireSha256(String value, String fieldName) {
    String digest = Objects.requireNonNull(value, fieldName);
    if (!SHA_256.matcher(digest).matches()) {
      throw new IllegalArgumentException(fieldName + " must be a lowercase SHA-256 digest");
    }
    return digest;
  }

  /**
   * Computes the lowercase SHA-256 digest of canonical UTF-8 text.
   *
   * @param canonicalText the fully assembled canonical representation to hash
   * @return the lowercase hexadecimal digest of the UTF-8 bytes
   * @throws NullPointerException if {@code canonicalText} is {@code null}
   * @throws IllegalStateException if the Java runtime does not provide SHA-256
   */
  static String sha256(String canonicalText) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      return HexFormat.of()
          .formatHex(
              digest.digest(
                  Objects.requireNonNull(canonicalText, "canonicalText")
                      .getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is unavailable", e);
    }
  }

  /**
   * Appends one nullable field using an unambiguous length-delimited representation.
   *
   * @param target the canonical buffer that receives the encoded field
   * @param value the field value, with {@code null} encoded as an empty value
   * @throws NullPointerException if {@code target} is {@code null}
   */
  static void append(StringBuilder target, String value) {
    String text = Objects.requireNonNullElse(value, "");
    target.append(text.length()).append(':').append(text).append(';');
  }
}
