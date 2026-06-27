package network.crypta.platform.appcatalog;

import java.security.MessageDigest;
import java.util.Locale;

final class AppCatalogRevisions {
  private static final String DIGEST_PREFIX = "sha256:";
  private static final int SHA256_HEX_LENGTH = 64;

  private AppCatalogRevisions() {}

  static String catalogDigest(FetchedCatalog fetchedCatalog) {
    MessageDigest digest = AppCatalogSidecars.newArtifactSha256Digest();
    updateLengthPrefixed(digest, fetchedCatalog.catalogBytes());
    updateLengthPrefixed(digest, fetchedCatalog.signatureBytes());
    return DIGEST_PREFIX + AppCatalogSidecars.lowercaseHex(digest.digest());
  }

  static String signatureDigest(FetchedCatalog fetchedCatalog) {
    MessageDigest digest = AppCatalogSidecars.newArtifactSha256Digest();
    return DIGEST_PREFIX
        + AppCatalogSidecars.lowercaseHex(digest.digest(fetchedCatalog.signatureBytes()));
  }

  static String digestDirectoryName(String digest) {
    String normalized =
        AppCatalogSidecars.requireNonBlankSingleLine(
            digest, "revisionDigest", AppCatalogSidecars.INVALID_CATALOG_SOURCE);
    if (!normalized.startsWith(DIGEST_PREFIX)) {
      throw invalidRevisionDigest();
    }
    String hex = normalized.substring(DIGEST_PREFIX.length()).toLowerCase(Locale.ROOT);
    if (hex.length() != SHA256_HEX_LENGTH || !hex.chars().allMatch(AppCatalogRevisions::isHex)) {
      throw invalidRevisionDigest();
    }
    return hex;
  }

  private static void updateLengthPrefixed(MessageDigest digest, byte[] bytes) {
    digest.update((byte) (bytes.length >>> 24));
    digest.update((byte) (bytes.length >>> 16));
    digest.update((byte) (bytes.length >>> 8));
    digest.update((byte) bytes.length);
    digest.update(bytes);
  }

  private static boolean isHex(int character) {
    return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f');
  }

  private static AppCatalogException invalidRevisionDigest() {
    return new AppCatalogException(
        AppCatalogSidecars.INVALID_CATALOG_SOURCE, "revisionDigest must be a sha256 digest");
  }
}
