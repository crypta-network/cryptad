package network.crypta.platform.appvault;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.jetbrains.annotations.NotNull;

/**
 * Versioned AES-GCM envelope for app secret values and private identity material.
 *
 * <p>The envelope stores ciphertext plus the metadata required to decrypt it with a local vault
 * key. Additional authenticated data binds each envelope to immutable metadata such as app id,
 * secret name, identity id, kind, and creation timestamp. If metadata is copied under another path
 * or edited after encryption, decryption fails before plaintext is returned.
 *
 * <p>This format provides local at-rest protection with the configured {@link AppVaultKeyProvider}.
 * It is not a hardware-backed keystore, remote sync format, or compliance claim by itself. The
 * caller is responsible for atomic file writes and for keeping the wrapping key protected.
 *
 * @param version envelope format version
 * @param algorithm public algorithm label for the envelope format
 * @param keyId identifier of the wrapping key used to encrypt the plaintext
 * @param nonce AES-GCM nonce bytes generated for this envelope
 * @param aad additional authenticated data bound to the ciphertext
 * @param ciphertext encrypted plaintext and authentication tag
 * @param createdAt envelope creation timestamp
 */
public record AppVaultEnvelope(
    int version,
    String algorithm,
    String keyId,
    byte[] nonce,
    byte[] aad,
    byte[] ciphertext,
    Instant createdAt) {
  /**
   * Current envelope format version.
   *
   * <p>The value is serialized with every envelope so future migrations can reject or migrate older
   * formats explicitly instead of guessing from file shape.
   */
  public static final int FORMAT_VERSION = 1;

  /**
   * Current envelope algorithm label.
   *
   * <p>The implementation uses JDK {@code AES/GCM/NoPadding} with a 256-bit local vault key and a
   * 128-bit authentication tag.
   */
  public static final String FORMAT_ALGORITHM = "AES-GCM-256";

  private static final int GCM_TAG_BITS = 128;
  private static final int GCM_NONCE_BYTES = 12;

  /**
   * Creates a validated envelope.
   *
   * <p>The constructor enforces the supported version, algorithm, nonce length, and required
   * fields. Mutable byte arrays are copied so callers cannot alter envelope contents after
   * construction.
   */
  public AppVaultEnvelope {
    if (version != FORMAT_VERSION) {
      throw new AppVaultException(400, "unsupported_vault_envelope", "Unsupported vault envelope.");
    }
    algorithm = requireText(algorithm, "algorithm");
    if (!FORMAT_ALGORITHM.equals(algorithm)) {
      throw new AppVaultException(400, "unsupported_vault_envelope", "Unsupported vault envelope.");
    }
    keyId = requireText(keyId, "keyId");
    nonce = Objects.requireNonNull(nonce, "nonce").clone();
    if (nonce.length != GCM_NONCE_BYTES) {
      throw new AppVaultException(400, "invalid_vault_envelope", "Invalid vault envelope.");
    }
    aad = Objects.requireNonNull(aad, "aad").clone();
    ciphertext = Objects.requireNonNull(ciphertext, "ciphertext").clone();
    Objects.requireNonNull(createdAt, "createdAt");
  }

  /**
   * Encrypts plaintext with the supplied wrapping key and authenticated metadata.
   *
   * <p>A fresh 96-bit AES-GCM nonce is generated with the provided {@link SecureRandom}. The AAD is
   * not secret and is serialized in the envelope, but it must match the expected metadata exactly
   * at decrypt time.
   *
   * @param plaintext value or private material to encrypt
   * @param aad canonical additional authenticated data for the record
   * @param key active local vault wrapping key
   * @param secureRandom random source used for nonce generation and cipher initialization
   * @return newly encrypted envelope ready for durable storage
   */
  public static AppVaultEnvelope encrypt(
      byte[] plaintext, byte[] aad, AppVaultKeyProvider.VaultKey key, SecureRandom secureRandom) {
    byte[] nonce = new byte[GCM_NONCE_BYTES];
    secureRandom.nextBytes(nonce);
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(
          Cipher.ENCRYPT_MODE,
          new SecretKeySpec(key.keyBytes(), "AES"),
          new GCMParameterSpec(GCM_TAG_BITS, nonce));
      cipher.updateAAD(aad);
      return new AppVaultEnvelope(
          FORMAT_VERSION,
          FORMAT_ALGORITHM,
          key.keyId(),
          nonce,
          aad,
          cipher.doFinal(plaintext),
          Instant.now());
    } catch (GeneralSecurityException exception) {
      throw new AppVaultException(
          500, "vault_encrypt_failed", "Vault encryption failed.", exception);
    }
  }

  /**
   * Decrypts this envelope with the supplied wrapping key and expected AAD.
   *
   * <p>The method checks key id and AAD before invoking the cipher so metadata mismatches produce a
   * stable {@code vault_aad_mismatch} error. Authentication failures from AES-GCM are mapped to a
   * redacted decrypt error and do not return partial plaintext.
   *
   * @param expectedAad canonical AAD computed from the current metadata record
   * @param key active local vault wrapping key
   * @return decrypted plaintext bytes for the caller to handle in memory
   */
  public byte[] decrypt(byte[] expectedAad, AppVaultKeyProvider.VaultKey key) {
    if (!keyId.equals(key.keyId()) || !Arrays.equals(aad, expectedAad)) {
      throw new AppVaultException(403, "vault_aad_mismatch", "Vault envelope metadata mismatch.");
    }
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(
          Cipher.DECRYPT_MODE,
          new SecretKeySpec(key.keyBytes(), "AES"),
          new GCMParameterSpec(GCM_TAG_BITS, nonce));
      cipher.updateAAD(expectedAad);
      return cipher.doFinal(ciphertext);
    } catch (GeneralSecurityException _) {
      throw new AppVaultException(
          403, "vault_decrypt_failed", "Vault material could not be decrypted.");
    }
  }

  /**
   * Returns a defensive copy of the AES-GCM nonce.
   *
   * @return copied nonce bytes serialized with the envelope
   */
  @Override
  public byte[] nonce() {
    return nonce.clone();
  }

  /**
   * Returns a defensive copy of the envelope AAD.
   *
   * @return copied additional authenticated data bytes
   */
  @Override
  @SuppressWarnings("unused")
  public byte[] aad() {
    return aad.clone();
  }

  /**
   * Returns a defensive copy of the ciphertext and authentication tag.
   *
   * @return copied encrypted bytes, including the AES-GCM tag
   */
  @Override
  public byte[] ciphertext() {
    return ciphertext.clone();
  }

  @Override
  public boolean equals(Object object) {
    if (this == object) {
      return true;
    }
    if (!(object instanceof AppVaultEnvelope that)) {
      return false;
    }
    return version == that.version
        && Objects.equals(algorithm, that.algorithm)
        && Objects.equals(keyId, that.keyId)
        && Arrays.equals(nonce, that.nonce)
        && Arrays.equals(aad, that.aad)
        && Arrays.equals(ciphertext, that.ciphertext)
        && Objects.equals(createdAt, that.createdAt);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(version, algorithm, keyId, createdAt);
    result = 31 * result + Arrays.hashCode(nonce);
    result = 31 * result + Arrays.hashCode(aad);
    result = 31 * result + Arrays.hashCode(ciphertext);
    return result;
  }

  /**
   * Serializes the envelope to a deterministic small JSON document.
   *
   * <p>The JSON shape is intentionally flat and controlled by this class. Binary fields are Base64
   * encoded. The resulting text may be stored on disk but should not be treated as a public status
   * document because it contains ciphertext and AAD.
   *
   * @return deterministic JSON representation with a trailing newline
   */
  public String toJson() {
    Base64.Encoder encoder = Base64.getEncoder();
    return "{"
        + "\"version\":"
        + version
        + ",\"algorithm\":\""
        + algorithm
        + "\",\"keyId\":\""
        + keyId
        + "\",\"nonce\":\""
        + encoder.encodeToString(nonce)
        + "\",\"aad\":\""
        + encoder.encodeToString(aad)
        + "\",\"ciphertext\":\""
        + encoder.encodeToString(ciphertext)
        + "\",\"createdAt\":\""
        + createdAt
        + "\"}\n";
  }

  /**
   * Parses an envelope written by {@link #toJson()}.
   *
   * <p>Malformed JSON, missing fields, unsupported versions, unsupported algorithms, invalid
   * Base64, and malformed timestamps all map to a stable {@code invalid_vault_envelope} error.
   *
   * @param json serialized envelope text from the vault store
   * @return parsed and validated envelope
   */
  public static AppVaultEnvelope fromJson(String json) {
    Map<String, String> values = parseFlatJson(json);
    Base64.Decoder decoder = Base64.getDecoder();
    try {
      return new AppVaultEnvelope(
          Integer.parseInt(required(values, "version")),
          required(values, "algorithm"),
          required(values, "keyId"),
          decoder.decode(required(values, "nonce")),
          decoder.decode(required(values, "aad")),
          decoder.decode(required(values, "ciphertext")),
          Instant.parse(required(values, "createdAt")));
    } catch (IllegalArgumentException _) {
      throw new AppVaultException(400, "invalid_vault_envelope", "Invalid vault envelope.");
    }
  }

  @Override
  public @NotNull String toString() {
    return "AppVaultEnvelope[version="
        + version
        + ", algorithm="
        + algorithm
        + ", keyId="
        + keyId
        + ", ciphertext=<redacted>]";
  }

  private static Map<String, String> parseFlatJson(String json) {
    String text = Objects.requireNonNull(json, "json").trim();
    if (!text.startsWith("{") || !text.endsWith("}")) {
      throw new AppVaultException(400, "invalid_vault_envelope", "Invalid vault envelope.");
    }
    LinkedHashMap<String, String> values = LinkedHashMap.newLinkedHashMap(7);
    java.util.regex.Matcher matcher =
        java.util.regex.Pattern.compile("\"([A-Za-z0-9]+)\":(\"([^\"]*)\"|\\d+)").matcher(text);
    while (matcher.find()) {
      String raw = matcher.group(2);
      values.put(matcher.group(1), raw.startsWith("\"") ? matcher.group(3) : raw);
    }
    return values;
  }

  private static String required(Map<String, String> values, String key) {
    String value = values.get(key);
    if (value == null || value.isBlank()) {
      throw new AppVaultException(400, "invalid_vault_envelope", "Invalid vault envelope.");
    }
    return value;
  }

  private static String requireText(String value, String fieldName) {
    String text = Objects.requireNonNull(value, fieldName).trim();
    if (text.isEmpty()) {
      throw new IllegalArgumentException(fieldName + " must not be blank");
    }
    return text;
  }

  static byte[] utf8(String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }
}
