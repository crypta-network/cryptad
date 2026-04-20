package network.crypta.platform.appdist;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses and verifies {@code cryptad-app.digests} sidecars against bundle contents.
 *
 * <p>The verifier is intentionally stricter than a generic properties' reader. It accepts only the
 * v1 digest keys, requires contiguous {@code file.N.*} indexes, rejects unsupported per-file
 * metadata, and delegates every path to the shared bundle-relative path validator. That makes
 * malformed sidecars fail before any signature check can treat them as trusted input.
 *
 * <p>{@link #verify(Path)} compares the sidecar with a newly generated digest of the current bundle
 * tree. This catches modified files, changed manifest contents, changed POSIX executable-bit state
 * when that state is authenticated, missing payload files, and extra payload files that were added
 * after signing. The method reads from the supplied local directory only; it does not fetch remote
 * catalogs or artifacts.
 */
public final class AppBundleDigestVerifier {
  private static final Pattern FILE_PROPERTY_PATTERN =
      Pattern.compile("file\\.(\\d+)\\.(path|sha256|executable)");

  private AppBundleDigestVerifier() {}

  /**
   * Reads and validates a digest sidecar.
   *
   * <p>This method validates the textual sidecar format but does not compare it with a bundle
   * directory. It is useful when callers need the declared digest inventory, for example before
   * checking the Ed25519 signature over the exact digest sidecar bytes.
   *
   * @param digestFile path to {@code cryptad-app.digests}, resolved by the caller
   * @return parsed digest snapshot with normalized paths and validated metadata
   * @throws IOException if the sidecar is missing, malformed, unsupported, or unsafe
   */
  public static AppBundleDigest read(Path digestFile) throws IOException {
    return read(AppDistributionSidecars.readRequiredBytes(digestFile, "digest sidecar"));
  }

  /**
   * Parses and validates already-read digest sidecar bytes.
   *
   * <p>This overload is used by signed-bundle verification after the signature has been checked
   * over the exact byte array read from {@code cryptad-app.digests}. Parsing those same bytes
   * avoids a second filesystem read that could otherwise observe a different digest sidecar.
   *
   * @param digestBytes exact UTF-8 bytes read from {@code cryptad-app.digests}
   * @return parsed digest snapshot with normalized paths and validated metadata
   * @throws AppDistributionException if the sidecar bytes are malformed or unsupported
   */
  public static AppBundleDigest read(byte[] digestBytes) throws AppDistributionException {
    String content =
        new String(Objects.requireNonNull(digestBytes, "digestBytes"), StandardCharsets.UTF_8);
    Map<String, String> properties =
        AppDistributionSidecars.parseKeyValueSidecar(content, "digest sidecar");
    DigestHeader header = readDigestHeader(properties);
    Map<Integer, DigestEntryBuilder> builders = readDigestEntries(properties);
    List<AppBundleDigestEntry> entries = buildDigestEntries(builders);

    return createDigest(header, entries);
  }

  private static DigestHeader readDigestHeader(Map<String, String> properties)
      throws AppDistributionException {
    String versionText = properties.remove("digest.version");
    String algorithm = properties.remove("digest.algorithm");
    if (versionText == null) {
      throw new AppDistributionException("missing digest.version");
    }
    if (algorithm == null) {
      throw new AppDistributionException("missing digest.algorithm");
    }
    return new DigestHeader(versionText, algorithm);
  }

  private static Map<Integer, DigestEntryBuilder> readDigestEntries(Map<String, String> properties)
      throws AppDistributionException {
    Map<Integer, DigestEntryBuilder> builders = new TreeMap<>();
    for (Map.Entry<String, String> property : properties.entrySet()) {
      DigestProperty digestProperty = parseDigestProperty(property.getKey());
      DigestEntryBuilder builder =
          builders.computeIfAbsent(digestProperty.index(), ignored -> new DigestEntryBuilder());
      setDigestEntryField(builder, digestProperty.field(), property.getValue(), property.getKey());
    }
    if (builders.isEmpty()) {
      throw new AppDistributionException("digest sidecar must contain at least one file entry");
    }
    return builders;
  }

  private static DigestProperty parseDigestProperty(String propertyName)
      throws AppDistributionException {
    Matcher matcher = FILE_PROPERTY_PATTERN.matcher(propertyName);
    if (!matcher.matches()) {
      throw new AppDistributionException("unsupported digest property: " + propertyName);
    }
    return new DigestProperty(parseIndex(matcher.group(1), propertyName), matcher.group(2));
  }

  private static void setDigestEntryField(
      DigestEntryBuilder builder, String field, String value, String propertyName)
      throws AppDistributionException {
    switch (field) {
      case "path" -> builder.path = value;
      case "executable" -> builder.executable = parseExecutable(value, propertyName);
      default -> builder.sha256 = value;
    }
  }

  private static List<AppBundleDigestEntry> buildDigestEntries(
      Map<Integer, DigestEntryBuilder> builders) throws AppDistributionException {
    List<AppBundleDigestEntry> entries = new ArrayList<>(builders.size());
    for (int expectedIndex = 0; expectedIndex < builders.size(); expectedIndex++) {
      DigestEntryBuilder builder = requireDigestEntryBuilder(builders, expectedIndex);
      entries.add(buildDigestEntry(builder, expectedIndex));
    }
    return entries;
  }

  private static DigestEntryBuilder requireDigestEntryBuilder(
      Map<Integer, DigestEntryBuilder> builders, int expectedIndex)
      throws AppDistributionException {
    DigestEntryBuilder builder = builders.get(expectedIndex);
    if (builder == null) {
      throw new AppDistributionException("digest entries must use contiguous indexes");
    }
    return builder;
  }

  private static AppBundleDigestEntry buildDigestEntry(
      DigestEntryBuilder builder, int expectedIndex) throws AppDistributionException {
    if (builder.path == null || builder.sha256 == null) {
      throw new AppDistributionException("digest entry " + expectedIndex + " is incomplete");
    }
    try {
      return new AppBundleDigestEntry(builder.path, builder.sha256, builder.executable);
    } catch (IllegalArgumentException exception) {
      throw new AppDistributionException("invalid digest entry " + expectedIndex, exception);
    }
  }

  private static AppBundleDigest createDigest(
      DigestHeader header, List<AppBundleDigestEntry> entries) throws AppDistributionException {
    try {
      return new AppBundleDigest(
          Integer.parseInt(header.versionText()), header.algorithm(), entries);
    } catch (NumberFormatException exception) {
      throw new AppDistributionException(
          "invalid digest.version: " + header.versionText(), exception);
    } catch (IllegalArgumentException exception) {
      throw new AppDistributionException(exception.getMessage(), exception);
    }
  }

  /**
   * Verifies that the digest sidecar matches the current bundle contents.
   *
   * <p>The bundle root must be a real local directory. Verification regenerates the digest from the
   * current tree using {@link AppBundleDigestWriter#create(Path)} and then performs an exact value
   * comparison with the parsed sidecar. A mismatch is reported generically so API callers do not
   * receive unnecessary filesystem detail.
   *
   * @param bundleRoot staged app bundle root directory to compare with the digest sidecar
   * @return parsed digest snapshot when verification succeeds
   * @throws IOException if the sidecar is missing, malformed, unsafe, or does not match the bundle
   */
  public static AppBundleDigest verify(Path bundleRoot) throws IOException {
    Path normalizedBundleRoot = AppDistributionSidecars.requireBundleRoot(bundleRoot);
    AppBundleDigest expected = read(normalizedBundleRoot.resolve(AppBundleDigest.DIGEST_FILE_NAME));
    return verifyNormalizedBundleRoot(normalizedBundleRoot, expected);
  }

  /**
   * Verifies the current bundle contents against a caller-supplied digest snapshot.
   *
   * <p>Unlike {@link #verify(Path)}, this method does not read {@code cryptad-app.digests} from the
   * bundle root. Signed-bundle callers should pass the digest parsed from the same bytes whose
   * signature was just verified, so a concurrent rewrite of the sidecar cannot substitute a
   * different digest inventory between signature validation and payload validation.
   *
   * @param bundleRoot staged app bundle root directory to compare with the supplied digest
   * @param expected digest snapshot that was already parsed by the caller
   * @return the supplied digest snapshot when verification succeeds
   * @throws IOException if the bundle is unsafe, unreadable, or does not match the supplied digest
   */
  public static AppBundleDigest verify(Path bundleRoot, AppBundleDigest expected)
      throws IOException {
    Path normalizedBundleRoot = AppDistributionSidecars.requireBundleRoot(bundleRoot);
    return verifyNormalizedBundleRoot(normalizedBundleRoot, expected);
  }

  private static AppBundleDigest verifyNormalizedBundleRoot(
      Path normalizedBundleRoot, AppBundleDigest expected) throws IOException {
    AppBundleDigest checkedExpected = Objects.requireNonNull(expected, "expected");
    AppBundleDigest actual = AppBundleDigestWriter.create(normalizedBundleRoot);
    if (!checkedExpected.equals(actual)) {
      throw new AppDistributionException("digest sidecar does not match bundle contents");
    }
    return checkedExpected;
  }

  private static int parseIndex(String rawIndex, String propertyName)
      throws AppDistributionException {
    try {
      return Integer.parseInt(rawIndex);
    } catch (NumberFormatException exception) {
      throw new AppDistributionException(
          "invalid digest entry index in " + propertyName, exception);
    }
  }

  private static Boolean parseExecutable(String rawValue, String propertyName)
      throws AppDistributionException {
    return switch (rawValue) {
      case "true" -> Boolean.TRUE;
      case "false" -> Boolean.FALSE;
      default -> throw new AppDistributionException("invalid executable flag in " + propertyName);
    };
  }

  private record DigestHeader(String versionText, String algorithm) {}

  private record DigestProperty(int index, String field) {}

  private static final class DigestEntryBuilder {
    private String path;
    private String sha256;
    private Boolean executable;
  }
}
