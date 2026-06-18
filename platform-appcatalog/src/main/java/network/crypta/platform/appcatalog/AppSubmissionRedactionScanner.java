package network.crypta.platform.appcatalog;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Conservative redaction scanner for third-party submission package evidence.
 *
 * <p>The scanner never returns raw matched content. Findings include only stable ids and redacted
 * path fingerprints so CLI output, pre-review JSON, release certification evidence, and
 * transparency log warnings cannot expose secrets while reporting why a package failed closed.
 *
 * <p>The scanner is intentionally stricter than a normal text linter. It treats oversized evidence,
 * unsafe ZIP paths, ZIP envelope gaps, AppleDouble entries, local paths, private keys, bearer
 * tokens, browser-session tokens, private insert URIs, and raw content markers as blockers.
 * ZIP-like evidence is inspected recursively with bounded depth, bounded entry count, and
 * canonical-envelope checks so compressed or hidden bytes do not bypass the redaction gate.
 *
 * <p>This class does not decide whether an app is otherwise reviewable. It only answers whether the
 * submitted evidence can be safely summarized and persisted. Package verification and pre-review
 * combine these findings with manifest, API, UI, sandbox, and catalog-readiness checks.
 */
public final class AppSubmissionRedactionScanner {
  private static final int MAX_TEXT_SCAN_BYTES = 2 * 1024 * 1024;
  private static final int MAX_NESTED_ZIP_DEPTH = 4;
  private static final int MAX_NESTED_ZIP_ENTRIES = 1024;
  private static final int END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054B50;
  private static final int CENTRAL_DIRECTORY_HEADER_SIGNATURE = 0x02014B50;
  private static final int LOCAL_FILE_HEADER_SIGNATURE = 0x04034B50;
  private static final int DATA_DESCRIPTOR_SIGNATURE = 0x08074B50;
  private static final int END_OF_CENTRAL_DIRECTORY_MIN_BYTES = 22;
  private static final int ZIP_MAX_COMMENT_BYTES = 65_535;
  private static final int CENTRAL_DIRECTORY_HEADER_BYTES = 46;
  private static final int LOCAL_FILE_HEADER_BYTES = 30;
  private static final int ZIP64_UNSIGNED_SHORT_MARKER = 0xFFFF;
  private static final long ZIP64_UNSIGNED_INT_MARKER = 0xFFFF_FFFFL;
  private static final int GENERAL_PURPOSE_ENCRYPTED_FLAG = 0x0001;
  private static final int GENERAL_PURPOSE_DATA_DESCRIPTOR_FLAG = 0x0008;
  private static final byte[] FIXED_TIMESTAMP_EXTRA = {0x55, 0x54, 0x05, 0x00, 0x01, 0, 0, 0, 0};
  private static final List<String> LOCAL_UNIX_PATH_PREFIXES =
      List.of(
          "/home/",
          "/users/",
          "/work/",
          "/tmp/",
          "/var/",
          "/etc/",
          "/root/",
          "/opt/",
          "/mnt/",
          "/private/var/",
          "/volumes/");
  private static final String LOCALHOST_SEGMENT = "localhost";
  private static final String SESSION_TOKEN_FINDING_ID = "redaction.session-token";
  private static final String LOCAL_PATH_FINDING_ID = "redaction.local-path";
  private static final String PRIVATE_INSERT_URI_FINDING_ID = "redaction.private-insert-uri";

  private static final Pattern PRIVATE_KEY_PATTERN =
      Pattern.compile("-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", Pattern.CASE_INSENSITIVE);
  private static final Pattern AUTHORIZATION_HEADER_PATTERN =
      Pattern.compile("(?im)^\\s*authorization\\s*:");
  private static final Pattern BEARER_TOKEN_PATTERN =
      Pattern.compile("(?i)\\bbearer\\s+[a-z0-9._~+/=-]{12,}");
  private static final Pattern SESSION_TOKEN_HEADER_PATTERN =
      Pattern.compile("(?im)^\\s*x-crypta-app-session\\s*:\\s*\\S{12,}");
  private static final Pattern TOKEN_ASSIGNMENT_PATTERN =
      Pattern.compile(
          "(?i)\\b([a-z][a-z0-9_-]*)[\"']?\\s*[:=]\\s*[\"']?([a-z0-9._~+/=-]{12,})(?![a-z0-9._~+/=-])(?!\\s*\\()");
  private static final Pattern CRYPTA_SIGNED_SUBSPACE_URI_PATTERN =
      Pattern.compile("(?i)\\b(?:crypta:|freenet:)?(?:SSK|USK)@[^\\s'\"<>]+");
  private static final Pattern LOCAL_WINDOWS_PATH_PATTERN =
      Pattern.compile("(?i)(?:^|[\\s='\"])[a-z]:\\\\[^\\s'\"]+");
  private static final Pattern RAW_CONTENT_PATTERN =
      Pattern.compile(
          "(?i)\\b(raw fetched content|raw app data|raw request body|raw feed body)\\b");

  private AppSubmissionRedactionScanner() {}

  /**
   * Scans a package entry name and byte payload.
   *
   * <p>The entry name is scanned before any ZIP display suffix is stripped, so malicious paths that
   * carry secrets or traversal components are reported by digest only. Text entries are scanned up
   * to the configured cap and fail closed when larger. ZIP-shaped entries are validated as ZIP
   * envelopes and then recursed into until the nested-depth cap is reached.
   *
   * @param entryName normalized package-relative path or nested display path
   * @param bytes entry bytes to inspect without exposing in findings
   * @return immutable blocker findings with redacted path details
   */
  public static List<AppSubmissionFinding> scanEntry(String entryName, byte[] bytes) {
    return scanEntry(entryName, bytes, 0);
  }

  /**
   * Validates the metadata envelope of a ZIP evidence file.
   *
   * <p>This check is used before opening submission ZIP snapshots and nested evidence archives. It
   * rejects comments, prepended bytes, trailing bytes, central-directory gaps, encrypted entries,
   * and unsupported data descriptors so that bytes outside member payloads cannot carry unscanned
   * secrets.
   *
   * @param entryName redacted display name for the ZIP evidence
   * @param bytes complete ZIP bytes to validate
   * @return immutable blocker findings with redacted path details
   */
  static List<AppSubmissionFinding> scanZipEnvelope(String entryName, byte[] bytes) {
    List<AppSubmissionFinding> findings = new ArrayList<>();
    addPathFindings(findings, entryName);
    if (!isZipEvidence(entryName, bytes)) {
      findings.add(
          blocker(
              "redaction.zip-envelope",
              entryName,
              "ZIP evidence contains unscanned metadata or bytes"));
      return List.copyOf(findings);
    }
    validateZipEnvelope(entryName, bytes, findings);
    return List.copyOf(findings);
  }

  private static List<AppSubmissionFinding> scanEntry(
      String entryName, byte[] bytes, int zipDepth) {
    List<AppSubmissionFinding> findings = new ArrayList<>();
    addPathFindings(findings, entryName);
    if (isZipEvidence(entryName, bytes)) {
      if (zipDepth >= MAX_NESTED_ZIP_DEPTH) {
        findings.add(
            blocker(
                "redaction.nested-zip-depth",
                entryName,
                "Nested ZIP evidence exceeds the recursion depth cap"));
        return List.copyOf(findings);
      }
      validateZipEnvelope(entryName, bytes, findings);
      findings.addAll(scanNestedZip(entryName, bytes, zipDepth));
      return List.copyOf(findings);
    }
    if (bytes.length <= MAX_TEXT_SCAN_BYTES) {
      scanText(entryName, decodeUtf8(bytes), findings);
    } else {
      scanText(entryName, decodeUtf8(Arrays.copyOf(bytes, MAX_TEXT_SCAN_BYTES)), findings);
      findings.add(
          blocker(
              "redaction.entry-too-large",
              entryName,
              "Submission evidence entry exceeds the text scan size cap"));
    }
    return List.copyOf(findings);
  }

  /**
   * Adds path-only findings for an entry name.
   *
   * <p>The method checks both the full display path and any nested-entry suffix after {@code !}.
   * Findings use path digests rather than raw names because ZIP filenames can themselves contain
   * tokens, private URIs, or local paths.
   *
   * @param findings mutable finding list to append to
   * @param entryName package or nested ZIP entry name to inspect
   */
  static void addPathFindings(List<AppSubmissionFinding> findings, String entryName) {
    addPathFindings(findings, entryName, entryName);
    int nestedSeparator = entryName.lastIndexOf('!');
    if (nestedSeparator >= 0 && nestedSeparator + 1 < entryName.length()) {
      addPathFindings(findings, entryName, entryName.substring(nestedSeparator + 1));
    }
  }

  private static void addPathFindings(
      List<AppSubmissionFinding> findings, String entryName, String path) {
    String lower = path.toLowerCase(Locale.ROOT);
    String baseName = path.substring(path.lastIndexOf('/') + 1);
    if (lower.startsWith("__macosx/")
        || baseName.equals(".DS_Store")
        || baseName.startsWith("._")) {
      findings.add(blocker("redaction.appledouble", entryName, "Forbidden macOS metadata entry"));
    }
    if (isUnsafePath(path)) {
      findings.add(blocker("redaction.unsafe-path", entryName, "Unsafe package path"));
    }
  }

  private static boolean isUnsafePath(String path) {
    return path.startsWith("/")
        || path.contains("\\")
        || hasUnsafePathComponent(path)
        || path.matches("^[A-Za-z]:.*");
  }

  private static boolean hasUnsafePathComponent(String path) {
    for (String component : path.split("/", -1)) {
      if (component.isEmpty() || component.equals(".") || component.equals("..")) {
        return true;
      }
    }
    return false;
  }

  private static List<AppSubmissionFinding> scanNestedZip(
      String entryName, byte[] bytes, int zipDepth) {
    List<AppSubmissionFinding> findings = new ArrayList<>();
    try (ZipInputStream input = new ZipInputStream(new ByteArrayInputStream(bytes))) {
      ZipEntry entry;
      byte[] buffer = new byte[MAX_TEXT_SCAN_BYTES + 1];
      int entryCount = 0;
      while ((entry = input.getNextEntry()) != null) {
        entryCount++;
        if (entryCount > MAX_NESTED_ZIP_ENTRIES) {
          findings.add(
              blocker(
                  "redaction.nested-zip-entry-count",
                  entryName,
                  "Nested ZIP contains too many entries to scan safely"));
          return List.copyOf(findings);
        }
        String nestedName = entryName + "!" + entry.getName();
        scanText(nestedName, entry.getName(), findings);
        int total = 0;
        int read;
        while (total < buffer.length
            && (read = input.read(buffer, total, buffer.length - total)) >= 0) {
          total += read;
          if (read == 0) {
            break;
          }
        }
        if (total <= MAX_TEXT_SCAN_BYTES) {
          findings.addAll(scanEntry(nestedName, Arrays.copyOf(buffer, total), zipDepth + 1));
        } else {
          addPathFindings(findings, nestedName);
          findings.add(
              blocker(
                  "redaction.nested-zip-entry-too-large",
                  nestedName,
                  "Nested ZIP entry exceeds the scan size cap"));
          return List.copyOf(findings);
        }
        input.closeEntry();
      }
    } catch (IOException _) {
      findings.add(
          blocker("redaction.nested-zip-unreadable", entryName, "Nested ZIP is unreadable"));
    }
    return findings;
  }

  private static boolean isZipEvidence(String entryName, byte[] bytes) {
    return entryName.toLowerCase(Locale.ROOT).endsWith(".zip") || hasZipMagic(bytes);
  }

  private static boolean hasZipMagic(byte[] bytes) {
    if (bytes.length < 4 || bytes[0] != 'P' || bytes[1] != 'K') {
      return false;
    }
    int third = Byte.toUnsignedInt(bytes[2]);
    int fourth = Byte.toUnsignedInt(bytes[3]);
    return (third == 0x03 && fourth == 0x04)
        || (third == 0x05 && fourth == 0x06)
        || (third == 0x07 && fourth == 0x08);
  }

  private static void validateZipEnvelope(
      String entryName, byte[] bytes, List<AppSubmissionFinding> findings) {
    try {
      if (!hasZipMagic(bytes)) {
        throw new IllegalArgumentException("ZIP evidence must start with a ZIP header");
      }
      ByteBuffer buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
      int eocdOffset = endOfCentralDirectoryOffset(buffer, bytes.length);
      int commentLength = unsignedShort(buffer, eocdOffset + 20);
      if (commentLength != 0
          || eocdOffset + END_OF_CENTRAL_DIRECTORY_MIN_BYTES + commentLength != bytes.length) {
        throw new IllegalArgumentException("ZIP comments or trailing bytes are unsupported");
      }
      int entryCount = unsignedShort(buffer, eocdOffset + 10);
      long centralDirectorySize = unsignedInt(buffer, eocdOffset + 12);
      long centralDirectoryOffset = unsignedInt(buffer, eocdOffset + 16);
      if (entryCount == ZIP64_UNSIGNED_SHORT_MARKER
          || centralDirectorySize == ZIP64_UNSIGNED_INT_MARKER
          || centralDirectoryOffset == ZIP64_UNSIGNED_INT_MARKER) {
        throw new IllegalArgumentException("ZIP64 evidence metadata is unsupported");
      }
      long centralDirectoryEnd = centralDirectoryOffset + centralDirectorySize;
      if (centralDirectoryOffset > bytes.length
          || centralDirectorySize > bytes.length - centralDirectoryOffset
          || centralDirectoryEnd != eocdOffset) {
        throw new IllegalArgumentException("ZIP central directory has unscanned bytes");
      }
      validateCentralDirectoryEntries(
          buffer, bytes, entryCount, (int) centralDirectoryOffset, eocdOffset);
    } catch (RuntimeException _) {
      findings.add(
          blocker(
              "redaction.zip-envelope",
              entryName,
              "ZIP evidence contains unscanned metadata or bytes"));
    }
  }

  private static int endOfCentralDirectoryOffset(ByteBuffer buffer, int zipLength) {
    if (zipLength < END_OF_CENTRAL_DIRECTORY_MIN_BYTES) {
      throw new IllegalArgumentException("missing end-of-central-directory record");
    }
    int minimumOffset =
        Math.max(0, zipLength - END_OF_CENTRAL_DIRECTORY_MIN_BYTES - ZIP_MAX_COMMENT_BYTES);
    for (int offset = zipLength - END_OF_CENTRAL_DIRECTORY_MIN_BYTES;
        offset >= minimumOffset;
        offset--) {
      if (buffer.getInt(offset) == END_OF_CENTRAL_DIRECTORY_SIGNATURE) {
        int commentLength = unsignedShort(buffer, offset + 20);
        if (offset + END_OF_CENTRAL_DIRECTORY_MIN_BYTES + commentLength == zipLength) {
          return offset;
        }
      }
    }
    throw new IllegalArgumentException("missing end-of-central-directory record");
  }

  private static void validateCentralDirectoryEntries(
      ByteBuffer buffer, byte[] bytes, int entryCount, int offset, int expectedEnd) {
    List<LocalFileRange> localRanges = new ArrayList<>();
    int cursor = offset;
    for (int index = 0; index < entryCount; index++) {
      CentralDirectoryEntry entry = readCentralDirectoryEntry(buffer, bytes, cursor);
      localRanges.add(validateLocalFileHeader(buffer, bytes, entry.metadata()));
      cursor = entry.nextOffset();
    }
    if (cursor != expectedEnd) {
      throw new IllegalArgumentException("central directory contains trailing bytes");
    }
    validateLocalFileCoverage(localRanges, offset);
  }

  private static CentralDirectoryEntry readCentralDirectoryEntry(
      ByteBuffer buffer, byte[] bytes, int cursor) {
    validateCentralDirectoryHeader(buffer, cursor);
    int flags = unsignedShort(buffer, cursor + 8);
    int method = unsignedShort(buffer, cursor + 10);
    long crc = unsignedInt(buffer, cursor + 16);
    long compressedSize = unsignedInt(buffer, cursor + 20);
    long uncompressedSize = unsignedInt(buffer, cursor + 24);
    int nameLength = unsignedShort(buffer, cursor + 28);
    int extraLength = unsignedShort(buffer, cursor + 30);
    int commentLength = unsignedShort(buffer, cursor + 32);
    long localHeaderOffset = unsignedInt(buffer, cursor + 42);
    validateCentralDirectoryMetadata(
        buffer, flags, compressedSize, uncompressedSize, commentLength, localHeaderOffset);
    int nameOffset = cursor + CENTRAL_DIRECTORY_HEADER_BYTES;
    int extraOffset = nameOffset + nameLength;
    int nextOffset = centralDirectoryNextOffset(buffer, nameOffset, nameLength, extraLength);
    String rawName = new String(bytes, nameOffset, nameLength, StandardCharsets.UTF_8);
    if (isUnsafePath(rawName)) {
      throw new IllegalArgumentException("unsafe central directory path");
    }
    byte[] centralExtra = Arrays.copyOfRange(bytes, extraOffset, extraOffset + extraLength);
    if (hasUnsupportedZipExtra(centralExtra)) {
      throw new IllegalArgumentException("central directory extra fields are unsupported");
    }
    return new CentralDirectoryEntry(
        new ZipEntryMetadata(
            rawName,
            flags,
            method,
            crc,
            compressedSize,
            uncompressedSize,
            Math.toIntExact(localHeaderOffset)),
        nextOffset);
  }

  private static void validateCentralDirectoryHeader(ByteBuffer buffer, int cursor) {
    if (cursor + CENTRAL_DIRECTORY_HEADER_BYTES > buffer.capacity()
        || buffer.getInt(cursor) != CENTRAL_DIRECTORY_HEADER_SIGNATURE) {
      throw new IllegalArgumentException("malformed central directory entry");
    }
  }

  private static void validateCentralDirectoryMetadata(
      ByteBuffer buffer,
      int flags,
      long compressedSize,
      long uncompressedSize,
      int commentLength,
      long localHeaderOffset) {
    if ((flags & GENERAL_PURPOSE_ENCRYPTED_FLAG) != 0) {
      throw new IllegalArgumentException("encrypted ZIP evidence is unsupported");
    }
    if (compressedSize == ZIP64_UNSIGNED_INT_MARKER
        || uncompressedSize == ZIP64_UNSIGNED_INT_MARKER) {
      throw new IllegalArgumentException("ZIP64 entry sizes are unsupported");
    }
    if (commentLength != 0) {
      throw new IllegalArgumentException("central directory comments are unsupported");
    }
    if (localHeaderOffset == ZIP64_UNSIGNED_INT_MARKER || localHeaderOffset > buffer.capacity()) {
      throw new IllegalArgumentException("ZIP64 local header offsets are unsupported");
    }
  }

  private static int centralDirectoryNextOffset(
      ByteBuffer buffer, int nameOffset, int nameLength, int extraLength) {
    long nextOffset = (long) nameOffset + nameLength + extraLength;
    if (nextOffset > buffer.capacity()) {
      throw new IllegalArgumentException("central directory entry escapes ZIP");
    }
    return Math.toIntExact(nextOffset);
  }

  private static LocalFileRange validateLocalFileHeader(
      ByteBuffer buffer, byte[] bytes, ZipEntryMetadata metadata) {
    int offset = metadata.localHeaderOffset();
    if ((long) offset + LOCAL_FILE_HEADER_BYTES > buffer.capacity()
        || buffer.getInt(offset) != LOCAL_FILE_HEADER_SIGNATURE) {
      throw new IllegalArgumentException("malformed local file header");
    }
    int flags = unsignedShort(buffer, offset + 6);
    int method = unsignedShort(buffer, offset + 8);
    long crc = unsignedInt(buffer, offset + 14);
    long compressedSize = unsignedInt(buffer, offset + 18);
    long uncompressedSize = unsignedInt(buffer, offset + 22);
    int nameLength = unsignedShort(buffer, offset + 26);
    int extraLength = unsignedShort(buffer, offset + 28);
    int nameOffset = offset + LOCAL_FILE_HEADER_BYTES;
    int extraOffset = nameOffset + nameLength;
    long nextOffset = (long) extraOffset + extraLength;
    if (nextOffset > buffer.capacity()) {
      throw new IllegalArgumentException("local file header escapes ZIP");
    }
    String localName = new String(bytes, nameOffset, nameLength, StandardCharsets.UTF_8);
    if (!metadata.name().equals(localName)) {
      throw new IllegalArgumentException("local file header name mismatch");
    }
    if (flags != metadata.flags() || method != metadata.method()) {
      throw new IllegalArgumentException("local file header metadata mismatch");
    }
    byte[] localExtra = Arrays.copyOfRange(bytes, extraOffset, extraOffset + extraLength);
    if (hasUnsupportedZipExtra(localExtra)) {
      throw new IllegalArgumentException("local file header extra fields are unsupported");
    }
    long payloadEnd = nextOffset + metadata.compressedSize();
    if (payloadEnd > buffer.capacity()) {
      throw new IllegalArgumentException("local file payload escapes ZIP");
    }
    long entryEnd;
    if ((metadata.flags() & GENERAL_PURPOSE_DATA_DESCRIPTOR_FLAG) == 0) {
      if (crc != metadata.crc()
          || compressedSize != metadata.compressedSize()
          || uncompressedSize != metadata.uncompressedSize()) {
        throw new IllegalArgumentException("local file header sizes mismatch");
      }
      entryEnd = payloadEnd;
    } else {
      entryEnd = validateDataDescriptor(buffer, payloadEnd, metadata);
    }
    if (entryEnd > buffer.capacity()) {
      throw new IllegalArgumentException("local file entry escapes ZIP");
    }
    return new LocalFileRange(offset, Math.toIntExact(entryEnd));
  }

  private static boolean hasUnsupportedZipExtra(byte[] extra) {
    return extra.length != 0 && !Arrays.equals(FIXED_TIMESTAMP_EXTRA, extra);
  }

  private static long validateDataDescriptor(
      ByteBuffer buffer, long payloadEnd, ZipEntryMetadata metadata) {
    if (payloadEnd + 12 > buffer.capacity()) {
      throw new IllegalArgumentException("missing ZIP data descriptor");
    }
    int descriptorOffset = Math.toIntExact(payloadEnd);
    int valueOffset = descriptorOffset;
    long descriptorEnd = payloadEnd + 12;
    if (payloadEnd + 16 <= buffer.capacity()
        && buffer.getInt(descriptorOffset) == DATA_DESCRIPTOR_SIGNATURE) {
      valueOffset += 4;
      descriptorEnd += 4;
    }
    long crc = unsignedInt(buffer, valueOffset);
    long compressedSize = unsignedInt(buffer, valueOffset + 4);
    long uncompressedSize = unsignedInt(buffer, valueOffset + 8);
    if (crc != metadata.crc()
        || compressedSize != metadata.compressedSize()
        || uncompressedSize != metadata.uncompressedSize()) {
      throw new IllegalArgumentException("ZIP data descriptor metadata mismatch");
    }
    return descriptorEnd;
  }

  private static void validateLocalFileCoverage(
      List<LocalFileRange> localRanges, int centralDirectoryOffset) {
    localRanges.sort(Comparator.comparingInt(LocalFileRange::start));
    int expectedOffset = 0;
    for (LocalFileRange range : localRanges) {
      if (range.start() != expectedOffset) {
        throw new IllegalArgumentException("ZIP local file region contains a gap or overlap");
      }
      expectedOffset = range.end();
    }
    if (expectedOffset != centralDirectoryOffset) {
      throw new IllegalArgumentException("ZIP local file region does not reach central directory");
    }
  }

  private record ZipEntryMetadata(
      String name,
      int flags,
      int method,
      long crc,
      long compressedSize,
      long uncompressedSize,
      int localHeaderOffset) {}

  private record CentralDirectoryEntry(ZipEntryMetadata metadata, int nextOffset) {}

  private record LocalFileRange(int start, int end) {}

  private static int unsignedShort(ByteBuffer buffer, int offset) {
    return Short.toUnsignedInt(buffer.getShort(offset));
  }

  private static long unsignedInt(ByteBuffer buffer, int offset) {
    return Integer.toUnsignedLong(buffer.getInt(offset));
  }

  private static void scanText(String entryName, String text, List<AppSubmissionFinding> findings) {
    addIfMatches(
        findings,
        PRIVATE_KEY_PATTERN,
        text,
        "redaction.private-key",
        entryName,
        "Private key material is forbidden");
    addIfMatches(
        findings,
        AUTHORIZATION_HEADER_PATTERN,
        text,
        "redaction.authorization-header",
        entryName,
        "Authorization headers are forbidden");
    addIfMatches(
        findings,
        BEARER_TOKEN_PATTERN,
        text,
        "redaction.bearer-token",
        entryName,
        "Bearer tokens are forbidden");
    addIfContainsSessionToken(findings, text, entryName);
    addIfContainsLabeledPrivateInsertUri(findings, text, entryName);
    addIfContainsPrivateInsertUriMaterial(findings, text, entryName);
    addIfContainsLocalUnixPath(findings, text, entryName);
    addIfMatches(
        findings,
        LOCAL_WINDOWS_PATH_PATTERN,
        text,
        LOCAL_PATH_FINDING_ID,
        entryName,
        "Local absolute paths are forbidden");
    addIfMatches(
        findings,
        RAW_CONTENT_PATTERN,
        text,
        "redaction.raw-content",
        entryName,
        "Raw fetched content or app data is forbidden");
  }

  private static void addIfMatches(
      List<AppSubmissionFinding> findings,
      Pattern pattern,
      String text,
      String id,
      String entryName,
      String summary) {
    if (pattern.matcher(text).find()) {
      findings.add(blocker(id, entryName, summary));
    }
  }

  private static void addIfContainsSessionToken(
      List<AppSubmissionFinding> findings, String text, String entryName) {
    if (containsSessionToken(text)) {
      findings.add(
          blocker(
              SESSION_TOKEN_FINDING_ID, entryName, "Browser or app session tokens are forbidden"));
    }
  }

  private static boolean containsSessionToken(String text) {
    return SESSION_TOKEN_HEADER_PATTERN.matcher(text).find()
        || containsSessionTokenAssignment(text);
  }

  private static boolean containsSessionTokenAssignment(String text) {
    var matcher = TOKEN_ASSIGNMENT_PATTERN.matcher(text);
    while (matcher.find()) {
      if (isSessionTokenKey(matcher.group(1))) {
        return true;
      }
    }
    return false;
  }

  private static boolean isSessionTokenKey(String key) {
    String normalized = normalizeIdentifier(key);
    return normalized.equals("browsersessiontoken")
        || normalized.equals("sessiontoken")
        || normalized.equals("cryptadapptoken");
  }

  private static void addIfContainsLabeledPrivateInsertUri(
      List<AppSubmissionFinding> findings, String text, String entryName) {
    if (containsLabeledPrivateInsertUri(text)) {
      findings.add(
          blocker(PRIVATE_INSERT_URI_FINDING_ID, entryName, "Private insert URIs are forbidden"));
    }
  }

  private static boolean containsLabeledPrivateInsertUri(String text) {
    var matcher = CRYPTA_SIGNED_SUBSPACE_URI_PATTERN.matcher(text);
    while (matcher.find()) {
      if (hasPrivateInsertLabelBefore(text, matcher.start())) {
        return true;
      }
    }
    return false;
  }

  private static boolean hasPrivateInsertLabelBefore(String text, int uriStart) {
    int lineStart =
        Math.max(text.lastIndexOf('\n', uriStart - 1), text.lastIndexOf('\r', uriStart - 1)) + 1;
    String prefix = text.substring(lineStart, uriStart);
    int separator = Math.max(prefix.lastIndexOf('='), prefix.lastIndexOf(':'));
    return separator >= 0 && isPrivateInsertAssignmentKey(prefix.substring(0, separator));
  }

  private static boolean isPrivateInsertAssignmentKey(String key) {
    String normalized = normalizeIdentifier(key);
    return normalized.equals("privateinserturi")
        || normalized.equals("privateinsertkey")
        || normalized.equals("privateusk")
        || normalized.equals("privatessk")
        || normalized.equals("inserturi")
        || normalized.equals("insertkey");
  }

  private static void addIfContainsPrivateInsertUriMaterial(
      List<AppSubmissionFinding> findings, String text, String entryName) {
    if (containsPrivateInsertUriMaterial(text)
        && findings.stream()
            .noneMatch(finding -> finding.id().equals(PRIVATE_INSERT_URI_FINDING_ID))) {
      findings.add(
          blocker(PRIVATE_INSERT_URI_FINDING_ID, entryName, "Private insert URIs are forbidden"));
    }
  }

  private static void addIfContainsLocalUnixPath(
      List<AppSubmissionFinding> findings, String text, String entryName) {
    if (containsLocalUnixPath(text)) {
      findings.add(blocker(LOCAL_PATH_FINDING_ID, entryName, "Local absolute paths are forbidden"));
    }
  }

  private static boolean containsLocalUnixPath(String text) {
    String lower = text.toLowerCase(Locale.ROOT);
    for (String prefix : LOCAL_UNIX_PATH_PREFIXES) {
      if (containsLocalUnixPathPrefix(lower, prefix)) {
        return true;
      }
    }
    return false;
  }

  private static boolean containsLocalUnixPathPrefix(String lower, String prefix) {
    int index = lower.indexOf(prefix);
    while (index >= 0) {
      if (isLocalUnixPathStart(lower, index)) {
        return true;
      }
      index = lower.indexOf(prefix, index + 1);
    }
    return false;
  }

  private static boolean isLocalUnixPathStart(String lower, int index) {
    return hasAbsolutePathDelimiter(lower, index)
        || hasUriSchemeBeforeSlashRun(lower, index)
        || hasLocalhostUriPrefix(lower, index);
  }

  private static boolean hasAbsolutePathDelimiter(String lower, int index) {
    if (index == 0) {
      return true;
    }
    char previous = lower.charAt(index - 1);
    return Character.isWhitespace(previous)
        || previous == '='
        || previous == '\''
        || previous == '"';
  }

  private static boolean hasUriSchemeBeforeSlashRun(String lower, int index) {
    return hasSchemeBeforeSlashRun(lower, slashRunStart(lower, index));
  }

  private static boolean hasLocalhostUriPrefix(String lower, int index) {
    int hostStart = index - LOCALHOST_SEGMENT.length();
    if (hostStart <= 0
        || !lower.regionMatches(hostStart, LOCALHOST_SEGMENT, 0, LOCALHOST_SEGMENT.length())) {
      return false;
    }
    return lower.charAt(hostStart - 1) == '/'
        && hasSchemeBeforeSlashRun(lower, slashRunStart(lower, hostStart - 1));
  }

  private static int slashRunStart(String value, int index) {
    int start = index;
    while (start > 0 && value.charAt(start - 1) == '/') {
      start--;
    }
    return start;
  }

  private static boolean hasSchemeBeforeSlashRun(String lower, int slashStart) {
    if (slashStart == 0 || lower.charAt(slashStart - 1) != ':') {
      return false;
    }
    int schemeEnd = slashStart - 1;
    int schemeStart = schemeEnd - 1;
    while (schemeStart >= 0 && isUriSchemeCharacter(lower.charAt(schemeStart))) {
      schemeStart--;
    }
    schemeStart++;
    return schemeStart < schemeEnd
        && Character.isLetter(lower.charAt(schemeStart))
        && hasSchemeDelimiter(lower, schemeStart);
  }

  private static boolean isUriSchemeCharacter(char character) {
    return Character.isLetterOrDigit(character)
        || character == '+'
        || character == '.'
        || character == '-';
  }

  private static boolean hasSchemeDelimiter(String lower, int schemeStart) {
    if (schemeStart == 0) {
      return true;
    }
    char previous = lower.charAt(schemeStart - 1);
    return Character.isWhitespace(previous)
        || previous == '='
        || previous == '\''
        || previous == '"';
  }

  private static String normalizeIdentifier(String value) {
    StringBuilder normalized = new StringBuilder(value.length());
    for (int index = 0; index < value.length(); index++) {
      char character = value.charAt(index);
      if (Character.isLetterOrDigit(character)) {
        normalized.append(Character.toLowerCase(character));
      }
    }
    return normalized.toString();
  }

  /**
   * Detects private insert-key material inside free text.
   *
   * <p>Public fetch references such as public USK or SSK keys are allowed. Insert material is
   * identified from explicit private/insert wording or the generated insert-key extra component
   * used by Crypta/Freenet SSK and USK keys.
   *
   * @param text text to scan for signed-subspace insert material
   * @return {@code true} when the text contains private insert-key material
   */
  static boolean containsPrivateInsertUriMaterial(String text) {
    var matcher = CRYPTA_SIGNED_SUBSPACE_URI_PATTERN.matcher(text);
    while (matcher.find()) {
      if (looksLikePrivateInsertUri(matcher.group())) {
        return true;
      }
    }
    return false;
  }

  private static boolean looksLikePrivateInsertUri(String token) {
    String lower = token.toLowerCase(Locale.ROOT);
    int keyPrefixOffset = signedSubspacePrefixOffset(lower);
    if (!lower.startsWith("usk@", keyPrefixOffset) && !lower.startsWith("ssk@", keyPrefixOffset)) {
      return false;
    }
    int keyMaterialStart = lower.indexOf('@', keyPrefixOffset) + 1;
    String keyMaterial = lower.substring(keyMaterialStart, keyMaterialEnd(lower, keyMaterialStart));
    return keyMaterial.contains("private")
        || keyMaterial.contains("insert")
        || hasPrivateInsertKeyExtra(keyMaterial);
  }

  private static int signedSubspacePrefixOffset(String lower) {
    if (lower.startsWith("crypta:")) {
      return "crypta:".length();
    }
    if (lower.startsWith("freenet:")) {
      return "freenet:".length();
    }
    return 0;
  }

  private static boolean hasPrivateInsertKeyExtra(String keyMaterial) {
    String[] components = keyMaterial.split(",", -1);
    if (components.length < 3) {
      return false;
    }
    for (int index = 2; index < components.length; index++) {
      if (components[index].startsWith("aqe")) {
        return true;
      }
    }
    return false;
  }

  private static int keyMaterialEnd(String value, int start) {
    int end = value.length();
    int slash = value.indexOf('/', start);
    if (slash >= 0) {
      end = Math.min(end, slash);
    }
    int query = value.indexOf('?', start);
    if (query >= 0) {
      end = Math.min(end, query);
    }
    int fragment = value.indexOf('#', start);
    if (fragment >= 0) {
      end = Math.min(end, fragment);
    }
    return end;
  }

  private static String decodeUtf8(byte[] bytes) {
    return new String(bytes, StandardCharsets.UTF_8);
  }

  private static AppSubmissionFinding blocker(String id, String entryName, String summary) {
    return new AppSubmissionFinding(
        id, AppSubmissionFindingSeverity.BLOCKER, summary, redactedPathDetails(entryName));
  }

  /**
   * Builds redacted path details for a finding.
   *
   * <p>The raw path is never returned. Callers receive a short label plus the full SHA-256 digest
   * so separate reports can correlate the same unsafe entry without exposing attacker-controlled
   * names.
   *
   * @param entryName original package or nested entry name, possibly attacker-controlled
   * @return deterministic detail map safe for JSON evidence
   */
  static Map<String, Object> redactedPathDetails(String entryName) {
    String value = entryName == null ? "" : entryName;
    String digest =
        AppCatalogSidecars.lowercaseHex(
            AppCatalogSidecars.newArtifactSha256Digest()
                .digest(value.getBytes(StandardCharsets.UTF_8)));
    Map<String, Object> details = new LinkedHashMap<>();
    details.put("path", redactedPathLabel(value, digest));
    details.put("pathDigestSha256", digest);
    return details;
  }

  private static String redactedPathLabel(String entryName, String digest) {
    String kind = "entry";
    if (entryName.contains("!")) {
      kind = "nested-entry";
    } else if (entryName.startsWith("zip-entry-name/")) {
      kind = "entry-name";
    }
    return kind + ":" + digest.substring(0, 16);
  }
}
