package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Map;
import java.util.Optional;

/**
 * Reads and writes standalone review receipt properties files.
 *
 * <p>The standalone file uses the same unprefixed {@code review.receipt.*} fields that catalogs
 * embed below {@code app.<id>.}. It is suitable for offline signing, verification, and catalog
 * authoring before the receipt is copied into a signed catalog entry.
 *
 * <p>The parser consumes and removes known receipt fields from a caller-supplied property map. That
 * lets {@link AppCatalogParser} reuse the same code for embedded catalog receipts while still
 * rejecting stray keys in standalone files. Serialization always writes fields in canonical order:
 * payload fields first, optional payload fields only when present, then signature fields. This
 * keeps command-line output reproducible and makes reviews auditable in ordinary properties diffs.
 *
 * <p>File writes create missing parent directories and refuse to replace symbolic links or
 * non-regular targets. The methods do not verify reviewer trust. They only parse and preserve the
 * receipt value; callers must use {@link AppReviewReceiptVerifier} for policy and signature
 * decisions.
 */
public final class AppReviewReceiptIO {
  private static final String RECEIPT_STATUS_FIELD = "review.receipt.status";
  private static final String RECEIPT_REVIEWED_AT_FIELD = "review.receipt.reviewed.at";
  private static final String RECEIPT_EXPIRES_AT_FIELD = "review.receipt.expires.at";
  private static final String RECEIPT_DECISION_REASON_SHA256_FIELD =
      "review.receipt.decision.reason.sha256";
  private static final String RECEIPT_EVIDENCE_URI_FIELD = "review.receipt.evidence.uri";

  private AppReviewReceiptIO() {}

  /**
   * Reads a review receipt from disk.
   *
   * <p>The file is bounded by the shared sidecar size limit before UTF-8 parsing. The returned
   * receipt is structurally valid, but no reviewer key lookup or signature verification happens in
   * this method.
   *
   * @param receiptFile properties file to read as a standalone receipt sidecar
   * @return parsed review receipt with canonical payload and detached signature
   * @throws IOException if the configured receipt file cannot be read
   */
  public static AppReviewReceipt read(Path receiptFile) throws IOException {
    byte[] bytes =
        AppCatalogSidecars.readRequiredBytes(
            receiptFile,
            AppCatalogSidecars.MAX_SIGNATURE_BYTES,
            "review receipt",
            AppCatalogSidecars.INVALID_CATALOG_ENTRY);
    return parse(bytes);
  }

  /**
   * Parses a standalone receipt from exact UTF-8 bytes.
   *
   * <p>All properties must be recognized unprefixed {@code review.receipt.*} keys. Embedded catalog
   * prefixes are handled by package-private helpers because standalone receipt files should not
   * carry catalog entry prefixes.
   *
   * @param receiptBytes receipt properties bytes read from disk or supplied by tooling
   * @return parsed receipt with no remaining unsupported properties
   */
  public static AppReviewReceipt parse(byte[] receiptBytes) {
    Map<String, String> properties =
        AppCatalogSidecars.parseKeyValueSidecar(
            AppCatalogSidecars.utf8(receiptBytes), "review receipt");
    AppReviewReceipt receipt = parseProperties(properties, "");
    if (!properties.isEmpty()) {
      throw AppCatalogSidecars.invalidEntry(
          "unsupported review receipt property: " + properties.keySet().iterator().next());
    }
    return receipt;
  }

  /**
   * Serializes a receipt in deterministic properties order.
   *
   * <p>The byte form is UTF-8 and matches {@link #serializeText(AppReviewReceipt)} exactly. Use it
   * when writing test fixtures, command output, or signed catalog inputs that need reproducible
   * hashes.
   *
   * @param receipt receipt to serialize without changing payload or signature fields
   * @return UTF-8 receipt properties bytes in deterministic field order
   */
  public static byte[] serialize(AppReviewReceipt receipt) {
    return serializeText(receipt).getBytes(StandardCharsets.UTF_8);
  }

  /**
   * Serializes a receipt in deterministic properties order.
   *
   * <p>The text form intentionally mirrors the canonical payload order and appends the signature
   * fields at the end. It is safe for display and file output because it contains only public
   * receipt metadata and the signature value, not reviewer private keys or local paths.
   *
   * @param receipt receipt to serialize without performing trust evaluation
   * @return receipt properties text ending with a trailing newline
   */
  public static String serializeText(AppReviewReceipt receipt) {
    StringBuilder builder = new StringBuilder();
    appendReceiptProperties(builder, "", receipt);
    return builder.toString();
  }

  /**
   * Writes a receipt properties file.
   *
   * <p>The destination path is normalized, missing parent directories are created, and existing
   * symlinks or non-regular files are rejected before the writing. Existing regular files are
   * overwritten; CLI callers enforce their own overwrite policy before invoking this method.
   *
   * @param receiptFile destination properties file for the serialized receipt
   * @param receipt receipt to write in deterministic properties order
   * @throws IOException if the destination cannot be created or written
   */
  public static void write(Path receiptFile, AppReviewReceipt receipt) throws IOException {
    Path normalized = receiptFile.toAbsolutePath().normalize();
    Path parent = normalized.getParent();
    if (parent != null) {
      Files.createDirectories(parent);
    }
    if (Files.exists(normalized, LinkOption.NOFOLLOW_LINKS)
        && (!Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS)
            || Files.isSymbolicLink(normalized))) {
      throw AppCatalogSidecars.invalidEntry("review receipt output must be a regular file");
    }
    Files.writeString(
        normalized,
        serializeText(receipt),
        StandardCharsets.UTF_8,
        StandardOpenOption.CREATE,
        StandardOpenOption.TRUNCATE_EXISTING,
        StandardOpenOption.WRITE,
        LinkOption.NOFOLLOW_LINKS);
  }

  static AppReviewReceipt parseProperties(Map<String, String> properties, String prefix) {
    AppReviewReceiptPayload payload =
        new AppReviewReceiptPayload(
            parseVersion(removeRequired(properties, prefix + "review.receipt.version")),
            removeRequired(properties, prefix + "review.receipt.app.id"),
            removeRequired(properties, prefix + "review.receipt.app.version"),
            removeRequired(properties, prefix + "review.receipt.artifact.sha256"),
            parseSize(removeRequired(properties, prefix + "review.receipt.artifact.size")),
            removeOptional(properties, prefix + "review.receipt.bundle.key.id"),
            removeRequired(properties, prefix + "review.receipt.policy.id"),
            removeRequired(properties, prefix + "review.receipt.policy.version"),
            AppReviewReceiptStatus.parse(
                removeRequired(properties, prefix + RECEIPT_STATUS_FIELD),
                prefix + RECEIPT_STATUS_FIELD),
            removeRequired(properties, prefix + "review.receipt.reviewer.key.id"),
            parseInstant(
                removeRequired(properties, prefix + RECEIPT_REVIEWED_AT_FIELD),
                prefix + RECEIPT_REVIEWED_AT_FIELD),
            removeOptional(properties, prefix + RECEIPT_EXPIRES_AT_FIELD)
                .map(value -> parseInstant(value, prefix + RECEIPT_EXPIRES_AT_FIELD)),
            removeOptional(properties, prefix + "review.receipt.evidence.sha256"),
            removeOptional(properties, prefix + RECEIPT_DECISION_REASON_SHA256_FIELD),
            removeOptional(properties, prefix + RECEIPT_EVIDENCE_URI_FIELD)
                .map(value -> parseUri(value, prefix + RECEIPT_EVIDENCE_URI_FIELD)),
            removeOptional(properties, prefix + "review.receipt.note"));
    AppReviewReceiptSignature signature =
        new AppReviewReceiptSignature(
            removeRequired(properties, prefix + "review.receipt.signature.algorithm"),
            removeRequired(properties, prefix + "review.receipt.signature.value.base64"));
    return new AppReviewReceipt(payload, signature);
  }

  static void appendReceiptProperties(
      StringBuilder builder, String prefix, AppReviewReceipt receipt) {
    AppReviewReceiptPayload payload = receipt.payload();
    append(builder, prefix + "review.receipt.version", Integer.toString(payload.version()));
    append(builder, prefix + "review.receipt.app.id", payload.appId());
    append(builder, prefix + "review.receipt.app.version", payload.appVersion());
    append(builder, prefix + "review.receipt.artifact.sha256", payload.artifactSha256());
    append(
        builder,
        prefix + "review.receipt.artifact.size",
        Long.toString(payload.artifactSizeBytes()));
    payload
        .bundleKeyId()
        .ifPresent(value -> append(builder, prefix + "review.receipt.bundle.key.id", value));
    append(builder, prefix + "review.receipt.policy.id", payload.policyId());
    append(builder, prefix + "review.receipt.policy.version", payload.policyVersion());
    append(builder, prefix + RECEIPT_STATUS_FIELD, payload.status().catalogValue());
    append(builder, prefix + "review.receipt.reviewer.key.id", payload.reviewerKeyId());
    append(builder, prefix + RECEIPT_REVIEWED_AT_FIELD, payload.reviewedAt().toString());
    payload
        .expiresAt()
        .ifPresent(value -> append(builder, prefix + RECEIPT_EXPIRES_AT_FIELD, value.toString()));
    payload
        .evidenceSha256()
        .ifPresent(value -> append(builder, prefix + "review.receipt.evidence.sha256", value));
    payload
        .decisionReasonSha256()
        .ifPresent(value -> append(builder, prefix + RECEIPT_DECISION_REASON_SHA256_FIELD, value));
    payload
        .evidenceUri()
        .ifPresent(value -> append(builder, prefix + RECEIPT_EVIDENCE_URI_FIELD, value.toString()));
    payload.note().ifPresent(value -> append(builder, prefix + "review.receipt.note", value));
    append(builder, prefix + "review.receipt.signature.algorithm", receipt.signature().algorithm());
    append(
        builder,
        prefix + "review.receipt.signature.value.base64",
        receipt.signature().valueBase64());
  }

  private static void append(StringBuilder builder, String key, String value) {
    builder.append(key).append('=').append(value).append('\n');
  }

  private static int parseVersion(String value) {
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid review.receipt.version: " + value,
          exception);
    }
  }

  private static long parseSize(String value) {
    try {
      return Long.parseLong(value);
    } catch (NumberFormatException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid review.receipt.artifact.size: " + value,
          exception);
    }
  }

  private static Instant parseInstant(String value, String fieldName) {
    try {
      return Instant.parse(value);
    } catch (DateTimeParseException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid " + fieldName + ": " + value,
          exception);
    }
  }

  private static URI parseUri(String value, String fieldName) {
    String text =
        AppCatalogSidecars.requireNonBlankSingleLine(
            value, fieldName, AppCatalogSidecars.INVALID_CATALOG_ENTRY);
    try {
      return new URI(text);
    } catch (URISyntaxException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY, "invalid " + fieldName, exception);
    }
  }

  private static String removeRequired(Map<String, String> properties, String key) {
    String value = properties.remove(key);
    if (value == null) {
      throw AppCatalogSidecars.invalidEntry("missing " + key);
    }
    return value;
  }

  private static Optional<String> removeOptional(Map<String, String> properties, String key) {
    return Optional.ofNullable(properties.remove(key));
  }
}
