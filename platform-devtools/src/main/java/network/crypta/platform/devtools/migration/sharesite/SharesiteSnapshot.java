package network.crypta.platform.devtools.migration.sharesite;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * Strict independent decoder for the pinned Sharesite map writer.
 *
 * <p>Only explicitly selected regular snapshots are opened, with no-follow semantics. Each
 * operation verifies the complete source again even when semantic decoding fails. Raw bytes may
 * contain legacy private keys; the decoder skips known secret values without creating strings, but
 * does not promise JVM memory erasure. A concurrent writer may prevent a successful operation; this
 * class never repairs a database or invokes legacy code.
 *
 * <p>Call {@link #inspect} with one stopped-writer snapshot and a conversion callback. The decoder
 * bounds framing and allocations, rejects ambiguous recovery sidecars, and retains only private
 * decoded values. It compares the final file identity, metadata, and complete bytes with the
 * initial snapshot before returning. Detection cannot prove that an external writer never changed
 * and restored identical bytes between observations. The helper is stateless; concurrent operations
 * may inspect independent immutable snapshots without sharing decoded state.
 */
public final class SharesiteSnapshot {
  static final int MAX_INPUT_BYTES = 8 * 1024 * 1024;
  static final int MAX_ENTRIES = 4096;
  static final int MAX_VALUE_BYTES = 131072;
  private static final byte[] HEADER = "ShareWiki-db-ver1".getBytes(StandardCharsets.UTF_8);

  private SharesiteSnapshot() {}

  /**
   * Runs an offline operation and checks source preservation before returning its result.
   *
   * <p>The callback receives decoded fields only after strict format checks succeed. A separate
   * check verifies source preservation even when conversion fails; detected drift prevents a
   * successful result. This method opens the file read-only and never repairs sidecars or corrupt
   * input. The caller must keep callback results private and must not use the supplied source path
   * or decoded metadata as output or network authority.
   *
   * @param path explicit regular snapshot created while its legacy writer was stopped
   * @param operation conversion callback using private decoded values and exact local source
   *     identity
   * @param <T> detached private operation result returned after source preservation succeeds
   * @return callback result only after complete source-preservation verification has succeeded
   * @throws IOException with a content-free reason code on unsafe input or source change
   */
  public static <T> T inspect(Path path, Function<Decoded, T> operation) throws IOException {
    Path source = path.toAbsolutePath().normalize();
    try {
      requireSafePath(source);
      requireNoRecovery(source);
      BasicFileAttributes before = attributes(source);
      byte[] original = read(source, MAX_INPUT_BYTES);
      T result = null;
      Exception conversionFailure = null;
      try {
        result = operation.apply(new Decoded(decode(original), sha256(original)));
      } catch (IOException | RuntimeException exception) {
        conversionFailure = exception;
      }
      requireNoRecovery(source);
      BasicFileAttributes after = attributes(source);
      if (!Objects.equals(before.fileKey(), after.fileKey())
          || before.size() != after.size()
          || !before.lastModifiedTime().equals(after.lastModifiedTime())
          || !MessageDigest.isEqual(original, read(source, MAX_INPUT_BYTES))) {
        throw failure("snapshot_changed");
      }
      if (conversionFailure instanceof IOException ioFailure) throw ioFailure;
      if (conversionFailure instanceof RuntimeException runtimeFailure) throw runtimeFailure;
      return result;
    } catch (IOException exception) {
      if (exception.getClass() == IOException.class
          && exception.getMessage() != null
          && exception.getMessage().startsWith("sharesite_")) {
        throw exception;
      }
      throw failure("snapshot_io");
    }
  }

  /**
   * Private decoded fields and local-only source fingerprint; never use this as public evidence.
   *
   * <p>Construction defensively copies the field map. Literal values remain private user data;
   * known secret-field values have already been skipped by the decoder. The fingerprint binds exact
   * local bytes for conversion consent and must not become a public certification identity.
   * Accessors serve the format-specific converter, while {@link #toString()} returns only a fixed
   * privacy label. Instances are immutable and safe to share with read-only conversion code.
   *
   * @param fields decoded private field map copied into an immutable representation
   * @param snapshotSha256 exact local source digest that must remain in private artifacts
   */
  public record Decoded(Map<String, String> fields, String snapshotSha256) {
    /**
     * Copies the private map to prevent changes during conversion.
     *
     * <p>The immutable copy preserves field spellings and literal values without normalization.
     * Secret skipping and digest construction belong to the enclosing decoder; this constructor
     * only detaches the supplied map. Null keys or values are rejected by the immutable-map copy.
     * Callers must never serialize this record into public diagnostic or certification output.
     */
    public Decoded {
      fields = Map.copyOf(fields);
    }

    /**
     * Avoids accidental private field disclosure through ordinary diagnostics.
     *
     * <p>The representation is constant for every snapshot and contains neither fields nor the
     * local source digest. This protects ordinary record logging from accidental disclosure without
     * changing the private accessors used by conversion. It is not a redaction or encryption
     * service for values explicitly retrieved through those accessors.
     *
     * @return fixed privacy label independent of source identity and decoded content
     */
    @Override
    public String toString() {
      return "SharesiteSnapshot[PRIVATE]";
    }
  }

  static Map<String, String> decode(byte[] bytes) throws IOException {
    if (bytes.length > MAX_INPUT_BYTES) throw failure("input_limit");
    ByteBuffer input = ByteBuffer.wrap(bytes);
    if (input.remaining() < HEADER.length
        || !Arrays.equals(readBytes(input, HEADER.length), HEADER)) {
      throw failure("unsupported_header");
    }
    int count = length(input, MAX_ENTRIES);
    Map<String, String> fields = new LinkedHashMap<>();
    long allocation = 0;
    for (int entry = 0; entry < count; entry++) {
      int keySize = length(input, 1024);
      String key = utf8(readBytes(input, keySize));
      int valueSize = length(input, MAX_VALUE_BYTES);
      allocation += 2L * (keySize + valueSize);
      if (allocation > 2L * MAX_INPUT_BYTES) throw failure("allocation_limit");
      if (fields.containsKey(key)) throw failure("duplicate_key");
      if (valueSize > input.remaining()) throw failure("truncated_value");
      if (isSecretField(key)) {
        // Validate encoding without retaining a decoded secret string.
        validateUtf8(input.slice(input.position(), valueSize));
        input.position(input.position() + valueSize);
        fields.put(key, "");
      } else {
        fields.put(key, utf8(readBytes(input, valueSize)));
      }
    }
    if (input.hasRemaining()) throw failure("trailing_bytes");
    return fields;
  }

  static boolean isSecretField(String key) {
    String lower = key.toLowerCase(java.util.Locale.ROOT);
    return lower.contains("insertssk")
        || lower.contains("private")
        || lower.contains("secret")
        || lower.contains("token")
        || lower.contains("password")
        || lower.contains("seed");
  }

  private static void validateUtf8(ByteBuffer bytes) throws IOException {
    try {
      var decoder =
          StandardCharsets.UTF_8
              .newDecoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .onUnmappableCharacter(CodingErrorAction.REPORT);
      var chars = java.nio.CharBuffer.allocate(1024);
      while (true) {
        var result = decoder.decode(bytes, chars, true);
        Arrays.fill(chars.array(), '\0');
        chars.clear();
        if (result.isError()) result.throwException();
        if (result.isUnderflow()) break;
      }
    } catch (CharacterCodingException _) {
      throw failure("invalid_utf8");
    }
  }

  static String utf8(byte[] bytes) throws IOException {
    try {
      return StandardCharsets.UTF_8
          .newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(bytes))
          .toString();
    } catch (CharacterCodingException _) {
      throw failure("invalid_utf8");
    }
  }

  private static int length(ByteBuffer input, int maximum) throws IOException {
    if (input.remaining() < 4) throw failure("truncated_framing");
    int length = input.getInt();
    if (length < 0 || length > maximum) throw failure("length_limit");
    return length;
  }

  private static byte[] readBytes(ByteBuffer input, int length) throws IOException {
    if (length > input.remaining()) throw failure("truncated_value");
    byte[] result = new byte[length];
    input.get(result);
    return result;
  }

  static byte[] read(Path path, int maximum) throws IOException {
    try (FileChannel channel =
        FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
      long size = channel.size();
      if (size < 0 || size > maximum) throw failure("input_limit");
      ByteBuffer bytes = ByteBuffer.allocate((int) size);
      while (bytes.hasRemaining()) if (channel.read(bytes) < 0) throw failure("snapshot_changed");
      if (channel.read(ByteBuffer.allocate(1)) != -1) throw failure("snapshot_changed");
      return bytes.array();
    }
  }

  static void requireSafePath(Path path) throws IOException {
    for (Path part = path.toAbsolutePath().normalize(); part != null; part = part.getParent()) {
      if (Files.isSymbolicLink(part)) throw failure("unsafe_link");
    }
  }

  private static BasicFileAttributes attributes(Path path) throws IOException {
    BasicFileAttributes result =
        Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    if (!result.isRegularFile()) throw failure("not_regular_file");
    return result;
  }

  private static void requireNoRecovery(Path path) throws IOException {
    Path filenamePath = path.getFileName();
    if (filenamePath == null) throw failure("snapshot_not_regular_file");
    String filename = filenamePath.toString();
    if (filename.endsWith(".tmp") || filename.endsWith(".corrupted")) {
      throw failure("recovery_artifact_not_snapshot");
    }
    if (Files.exists(path.resolveSibling(filename + ".tmp"), LinkOption.NOFOLLOW_LINKS)) {
      throw failure("ambiguous_recovery");
    }
  }

  static IOException failure(String code) {
    return new IOException("sharesite_" + code);
  }

  static String sha256(byte[] bytes) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (NoSuchAlgorithmException _) {
      throw new IllegalStateException("sha256_unavailable");
    }
  }
}
