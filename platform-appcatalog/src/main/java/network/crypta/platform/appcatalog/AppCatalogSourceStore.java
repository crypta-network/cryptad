package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.net.URI;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * File-backed store for configured app catalog sources and their verified sidecars.
 *
 * <p>The store keeps each catalog under a path-safe catalog id directory below a host-owned root.
 * It persists the source URI and refresh timestamps in a strict key/value sidecar, while catalog
 * properties and signature bytes are stored verbatim so later refreshes and reads can re-run
 * signature verification against the same trusted-key policy.
 *
 * <p>The store is deliberately small and synchronous. It does not cache parsed catalogs, perform
 * trust decisions, or manage installed apps. The manager owns synchronization around calls to this
 * class. Scratch files for downloads and extraction live under {@code .staging}, a hidden name that
 * is outside the catalog-id namespace and skipped by listing.
 */
@SuppressWarnings({"ClassCanBeRecord", "java:S6206"})
public final class AppCatalogSourceStore {
  private static final String SOURCE_FILE_NAME = "catalog-source.properties";
  private static final String SOURCE_VERSION_KEY = "catalog.source.version";
  private static final String CATALOG_ID_KEY = "catalog.id";
  private static final String SOURCE_URI_KEY = "source.uri";
  private static final String ADDED_AT_KEY = "source.addedAt";
  private static final String REFRESHED_AT_KEY = "source.refreshedAt";

  private final Path rootDirectory;
  private final SourceMetadataWriter sourceMetadataWriter;

  /**
   * Creates a source store rooted at a host-owned directory.
   *
   * <p>The root path is converted to an absolute normalized path immediately. Directories are
   * created lazily when a source is first written or when staging is needed for an
   * installation/update operation.
   *
   * @param rootDirectory directory where source records and catalog sidecars are stored
   */
  public AppCatalogSourceStore(Path rootDirectory) {
    this(rootDirectory, AppCatalogSourceStore::writeSourceMetadata);
  }

  AppCatalogSourceStore(Path rootDirectory, SourceMetadataWriter sourceMetadataWriter) {
    this.rootDirectory =
        Objects.requireNonNull(rootDirectory, "rootDirectory").toAbsolutePath().normalize();
    this.sourceMetadataWriter =
        Objects.requireNonNull(sourceMetadataWriter, "sourceMetadataWriter");
  }

  /**
   * Returns the root directory used for persistent catalog state.
   *
   * <p>Each configured catalog is stored below this directory using its normalized catalog id as
   * the child directory name. Callers should treat the returned path as host-private operational
   * state.
   *
   * @return absolute normalized store directory
   */
  @SuppressWarnings("unused")
  public Path rootDirectory() {
    return rootDirectory;
  }

  /**
   * Returns the scratch root used for downloads and extraction.
   *
   * <p>The scratch root is named {@code .staging} so valid catalog ids cannot collide with
   * temporary artifact state. The method returns the path only; callers create it when needed.
   *
   * @return scratch directory below the store root
   */
  public Path stagingDirectory() {
    return rootDirectory.resolve(".staging");
  }

  /**
   * Returns whether a catalog id is already stored.
   *
   * <p>The check looks for the source metadata sidecar rather than only the directory. This avoids
   * treating incomplete or scratch directories as configured catalogs.
   *
   * @param catalogId catalog id to test
   * @return {@code true} when source metadata exists for the id
   */
  public boolean exists(String catalogId) {
    return Files.isRegularFile(sourceFile(catalogId), LinkOption.NOFOLLOW_LINKS);
  }

  /**
   * Lists all stored catalog sources.
   *
   * <p>Only child directories containing valid source metadata are returned. The hidden staging
   * directory is skipped even if it contains files from a failed or in-progress catalog operation.
   * Records are sorted by directory name so API output is deterministic.
   *
   * @return stored source records sorted by catalog id
   * @throws IOException if source metadata or sidecars cannot be read safely
   */
  List<StoredCatalogSource> list() throws IOException {
    if (!Files.isDirectory(rootDirectory, LinkOption.NOFOLLOW_LINKS)) {
      return List.of();
    }
    List<StoredCatalogSource> sources = new ArrayList<>();
    try (var children = Files.list(rootDirectory)) {
      for (Path child :
          children.sorted(Comparator.comparing(path -> path.getFileName().toString())).toList()) {
        if (!Files.isDirectory(child, LinkOption.NOFOLLOW_LINKS)
            || child.equals(stagingDirectory())
            || !Files.isRegularFile(child.resolve(SOURCE_FILE_NAME), LinkOption.NOFOLLOW_LINKS)) {
          continue;
        }
        sources.add(readByDirectory(child));
      }
    }
    return List.copyOf(sources);
  }

  /**
   * Reads one stored catalog source.
   *
   * <p>The metadata sidecar is parsed strictly and its catalog id must match the directory name.
   * The catalog properties and signature sidecars are returned as exact bytes for later
   * verification.
   *
   * @param catalogId catalog id to read
   * @return stored source record and catalog sidecar bytes
   * @throws IOException if the id is missing or its files cannot be read safely
   */
  StoredCatalogSource read(String catalogId) throws IOException {
    Path sourceDirectory = catalogDirectory(catalogId);
    if (!Files.isDirectory(sourceDirectory, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppCatalogException(
          AppCatalogSidecars.CATALOG_NOT_FOUND, "Catalog not found: " + catalogId);
    }
    return readByDirectory(sourceDirectory);
  }

  /**
   * Writes or replaces one stored source and its latest fetched sidecars.
   *
   * <p>The method writes catalog bytes and signature bytes before the source metadata marker. The
   * metadata file is the store's commit marker, so a failed add that writes only fetched sidecars
   * is skipped by {@link #list()} and does not block retry as a configured catalog. It stores the
   * raw fetched sidecars rather than serializing {@code catalog}, preserving the exact bytes that
   * passed signature verification.
   *
   * @param catalog catalog content verified from {@code fetchedCatalog}
   * @param source source descriptor used to fetch the catalog
   * @param fetchedCatalog exact catalog and signature bytes to persist
   * @param addedAt original local source creation timestamp
   * @param refreshedAt latest successful refresh timestamp
   * @throws IOException if the store files cannot be written safely
   */
  public void write(
      AppCatalog catalog,
      AppCatalogSource source,
      FetchedCatalog fetchedCatalog,
      Instant addedAt,
      Instant refreshedAt)
      throws IOException {
    Files.createDirectories(rootDirectory);
    Path directory = catalogDirectory(catalog.catalogId());
    Path sourceFile = directory.resolve(SOURCE_FILE_NAME);
    FetchedCatalog previousFetchedCatalog =
        Files.isRegularFile(sourceFile, LinkOption.NOFOLLOW_LINKS)
            ? readFetchedCatalog(directory)
            : null;
    Files.createDirectories(directory);
    try {
      Files.write(
          directory.resolve(AppCatalogSignature.CATALOG_FILE_NAME), fetchedCatalog.catalogBytes());
      Files.write(
          directory.resolve(AppCatalogSignature.SIGNATURE_FILE_NAME),
          fetchedCatalog.signatureBytes());
      sourceMetadataWriter.write(
          directory,
          sourceFile,
          serializeSource(catalog.catalogId(), source, addedAt, refreshedAt));
    } catch (IOException exception) {
      if (previousFetchedCatalog == null) {
        cleanupIncompleteAdd(directory, exception);
      } else {
        restoreFetchedCatalog(directory, previousFetchedCatalog, exception);
      }
      throw exception;
    }
  }

  /**
   * Removes a stored catalog source and its cached sidecars.
   *
   * <p>Removal deletes only the catalog directory named by the normalized id. The shared staging
   * directory and any installed apps are outside that directory and are not removed by this method.
   *
   * @param catalogId catalog id to remove
   * @throws IOException if deletion fails
   */
  public void remove(String catalogId) throws IOException {
    Path directory = catalogDirectory(catalogId);
    if (!Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppCatalogException(
          AppCatalogSidecars.CATALOG_NOT_FOUND, "Catalog not found: " + catalogId);
    }
    AppCatalogBundleExtractor.deleteRecursively(directory);
  }

  private StoredCatalogSource readByDirectory(Path directory) throws IOException {
    Map<String, String> properties = readSourceMetadata(directory);
    validateSourceVersion(properties.remove(SOURCE_VERSION_KEY));
    String catalogId = removeRequired(properties, CATALOG_ID_KEY);
    AppCatalog.normalizeCatalogId(catalogId);
    if (!directory.getFileName().toString().equals(catalogId)) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE,
          "catalog source metadata id does not match directory");
    }
    AppCatalogSource source = parseStoredSource(removeRequired(properties, SOURCE_URI_KEY));
    Instant addedAt = parseInstant(removeRequired(properties, ADDED_AT_KEY), ADDED_AT_KEY);
    Instant refreshedAt =
        parseInstant(removeRequired(properties, REFRESHED_AT_KEY), REFRESHED_AT_KEY);
    if (!properties.isEmpty()) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE,
          "unsupported catalog source property: " + properties.keySet().iterator().next());
    }
    return new StoredCatalogSource(source, addedAt, refreshedAt, readFetchedCatalog(directory));
  }

  private FetchedCatalog readFetchedCatalog(Path directory) throws IOException {
    return new FetchedCatalog(
        AppCatalogSidecars.readRequiredBytes(
            directory.resolve(AppCatalogSignature.CATALOG_FILE_NAME),
            AppCatalogSidecars.MAX_CATALOG_BYTES,
            "catalog properties",
            AppCatalogSidecars.INVALID_CATALOG_SOURCE),
        AppCatalogSidecars.readRequiredBytes(
            directory.resolve(AppCatalogSignature.SIGNATURE_FILE_NAME),
            AppCatalogSidecars.MAX_SIGNATURE_BYTES,
            "catalog signature",
            AppCatalogSidecars.INVALID_CATALOG_SOURCE));
  }

  private static AppCatalogSource parseStoredSource(String rawUri) {
    try {
      return new AppCatalogSource(URI.create(rawUri));
    } catch (IllegalArgumentException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE,
          "invalid stored catalog source URI",
          exception);
    }
  }

  private Path catalogDirectory(String catalogId) {
    return rootDirectory.resolve(AppCatalog.normalizeCatalogId(catalogId));
  }

  private Path sourceFile(String catalogId) {
    return catalogDirectory(catalogId).resolve(SOURCE_FILE_NAME);
  }

  private static Map<String, String> readSourceMetadata(Path directory) throws IOException {
    try {
      return AppCatalogSidecars.parseKeyValueSidecar(
          AppCatalogSidecars.utf8(
              AppCatalogSidecars.readRequiredBytes(
                  directory.resolve(SOURCE_FILE_NAME),
                  AppCatalogSidecars.MAX_SIGNATURE_BYTES,
                  "catalog source metadata",
                  AppCatalogSidecars.INVALID_CATALOG_SOURCE)),
          "catalog source metadata");
    } catch (AppCatalogException exception) {
      if (AppCatalogSidecars.INVALID_CATALOG_ENTRY.equals(exception.errorCode())) {
        throw new AppCatalogException(
            AppCatalogSidecars.INVALID_CATALOG_SOURCE, exception.getMessage(), exception);
      }
      throw exception;
    }
  }

  private static void writeSourceMetadata(Path directory, Path sourceFile, String content)
      throws IOException {
    Path tempFile = Files.createTempFile(directory, ".catalog-source-", ".tmp");
    boolean moved = false;
    try {
      Files.writeString(tempFile, content);
      moveReplacing(tempFile, sourceFile);
      moved = true;
    } finally {
      if (!moved) {
        Files.deleteIfExists(tempFile);
      }
    }
  }

  private static void moveReplacing(Path source, Path target) throws IOException {
    try {
      Files.move(
          source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } catch (AtomicMoveNotSupportedException _) {
      Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
    }
  }

  private static void cleanupIncompleteAdd(Path directory, IOException originalException) {
    try {
      AppCatalogBundleExtractor.deleteRecursively(directory);
    } catch (IOException cleanupException) {
      originalException.addSuppressed(cleanupException);
    }
  }

  private static void restoreFetchedCatalog(
      Path directory, FetchedCatalog fetchedCatalog, IOException originalException) {
    try {
      Files.write(
          directory.resolve(AppCatalogSignature.CATALOG_FILE_NAME), fetchedCatalog.catalogBytes());
      Files.write(
          directory.resolve(AppCatalogSignature.SIGNATURE_FILE_NAME),
          fetchedCatalog.signatureBytes());
    } catch (IOException restoreException) {
      originalException.addSuppressed(restoreException);
    }
  }

  @FunctionalInterface
  interface SourceMetadataWriter {
    void write(Path directory, Path sourceFile, String content) throws IOException;
  }

  private static void validateSourceVersion(String versionText) {
    if (!"1".equals(versionText)) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE,
          versionText == null
              ? "missing catalog.source.version"
              : "unsupported catalog.source.version: " + versionText);
    }
  }

  private static Instant parseInstant(String value, String key) {
    try {
      return Instant.parse(value);
    } catch (DateTimeParseException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE, "invalid " + key + ": " + value, exception);
    }
  }

  private static String removeRequired(Map<String, String> properties, String key) {
    String value = properties.remove(key);
    if (value == null) {
      throw new AppCatalogException(AppCatalogSidecars.INVALID_CATALOG_SOURCE, "missing " + key);
    }
    return value;
  }

  private static String serializeSource(
      String catalogId, AppCatalogSource source, Instant addedAt, Instant refreshedAt) {
    return SOURCE_VERSION_KEY
        + "=1\n"
        + CATALOG_ID_KEY
        + "="
        + catalogId
        + "\n"
        + SOURCE_URI_KEY
        + "="
        + source.displayUri()
        + "\n"
        + ADDED_AT_KEY
        + "="
        + addedAt
        + "\n"
        + REFRESHED_AT_KEY
        + "="
        + refreshedAt
        + "\n";
  }
}
