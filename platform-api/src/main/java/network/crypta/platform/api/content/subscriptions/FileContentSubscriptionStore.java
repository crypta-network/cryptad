package network.crypta.platform.api.content.subscriptions;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.stream.Stream;
import network.crypta.platform.apphost.manifest.AppManifest;

/**
 * File-backed subscription metadata store rooted below the AppHost data tree.
 *
 * <p>The directory layout is {@code <root>/<appId>/<subscriptionId>.properties}. App ids and
 * subscription ids are normalized path-safe labels; source URIs are never used as file names.
 * Stored properties contain only the safe metadata from {@link ContentSubscription}, and no public
 * method returns the backing root path. The store writes through a temporary file and then replaces
 * the target record, preferring an atomic move when the filesystem supports it.
 *
 * <p>Read paths are intentionally forgiving. A missing directory returns an empty list, and a
 * corrupt, unknown-version, mismatched, or unsafe record is skipped instead of leaking path details
 * or blocking unrelated subscriptions. Real directory and write failures still surface as {@link
 * IOException} so API routes can report a stable store-unavailable error.
 */
public final class FileContentSubscriptionStore implements ContentSubscriptionStore {
  private static final String FILE_SUFFIX = ".properties";
  private static final String KEY_VERSION = "version";
  private static final String KEY_SUBSCRIPTION_ID = "subscriptionId";
  private static final String KEY_APP_ID = "appId";
  private static final String KEY_LABEL = "label";
  private static final String KEY_SOURCE_URI = "sourceUri";
  private static final String KEY_ENABLED = "enabled";
  private static final String KEY_STATUS = "status";
  private static final String KEY_POLL_INTERVAL_SECONDS = "pollIntervalSeconds";
  private static final String KEY_MAX_BYTES = "maxBytes";
  private static final String KEY_TIMEOUT_MILLIS = "timeoutMillis";
  private static final String KEY_CREATED_AT = "createdAt";
  private static final String KEY_UPDATED_AT = "updatedAt";
  private static final String KEY_LAST_CHECK_AT = "lastCheckAt";
  private static final String KEY_NEXT_CHECK_AT = "nextCheckAt";
  private static final String KEY_LAST_SUCCESS_AT = "lastSuccessAt";
  private static final String KEY_LAST_FAILURE_AT = "lastFailureAt";
  private static final String KEY_FAILURE_COUNT = "failureCount";
  private static final String KEY_LAST_ERROR_CODE = "lastErrorCode";
  private static final String KEY_LAST_SEEN_RESOLVED_URI = "lastSeenResolvedUri";
  private static final String KEY_LAST_SEEN_EDITION = "lastSeenEdition";
  private static final String KEY_CONTENT_SHA_256 = "contentSha256";
  private static final String KEY_BYTES_LENGTH = "bytesLength";
  private static final String KEY_UPDATE_COUNT = "updateCount";
  private static final String KEY_MESSAGE = "message";
  private static final long MIN_RESTORED_POLICY_VALUE = 1L;

  private final Path rootDirectory;

  /**
   * Creates a file-backed store rooted at the supplied directory.
   *
   * <p>The root path is converted to an absolute normalized path for internal use. It is never
   * returned through subscription summaries or release evidence. Callers are expected to place this
   * root under the AppHost data tree, for example {@code apps/content-subscriptions}.
   *
   * @param rootDirectory directory for subscription metadata partitions
   * @throws NullPointerException if the root directory is {@code null}
   */
  public FileContentSubscriptionStore(Path rootDirectory) {
    this.rootDirectory =
        java.util.Objects.requireNonNull(rootDirectory, "rootDirectory")
            .toAbsolutePath()
            .normalize();
  }

  @Override
  public synchronized List<ContentSubscription> listForApp(String appId) throws IOException {
    String normalizedAppId = AppManifest.normalizeAppId(appId);
    Path appDirectory = appDirectory(normalizedAppId);
    if (!Files.isDirectory(appDirectory)) {
      return List.of();
    }
    try (Stream<Path> stream = Files.list(appDirectory)) {
      return stream
          .filter(Files::isRegularFile)
          .filter(path -> path.getFileName().toString().endsWith(FILE_SUFFIX))
          .sorted(Comparator.comparing(Path::toString))
          .map(path -> readState(path, normalizedAppId, null))
          .flatMap(Optional::stream)
          .toList();
    }
  }

  @Override
  public synchronized List<ContentSubscription> listAll() throws IOException {
    if (!Files.isDirectory(rootDirectory)) {
      return List.of();
    }
    try (Stream<Path> stream = Files.list(rootDirectory)) {
      return stream
          .filter(Files::isDirectory)
          .sorted(Comparator.comparing(Path::toString))
          .flatMap(this::listAppDirectorySafely)
          .sorted(
              Comparator.comparing(ContentSubscription::appId)
                  .thenComparing(ContentSubscription::subscriptionId))
          .toList();
    }
  }

  @Override
  public synchronized Optional<ContentSubscription> read(String appId, String subscriptionId)
      throws IOException {
    String normalizedAppId = AppManifest.normalizeAppId(appId);
    String normalizedSubscriptionId = ContentSubscription.requireSubscriptionId(subscriptionId);
    return readState(
        subscriptionFile(normalizedAppId, normalizedSubscriptionId),
        normalizedAppId,
        normalizedSubscriptionId);
  }

  @Override
  public synchronized void write(ContentSubscription subscription) throws IOException {
    Path file = subscriptionFile(subscription.appId(), subscription.subscriptionId());
    Path parentDirectory = file.getParent();
    Files.createDirectories(parentDirectory);
    Properties properties = new Properties();
    properties.setProperty(KEY_VERSION, "1");
    properties.setProperty(KEY_SUBSCRIPTION_ID, subscription.subscriptionId());
    properties.setProperty(KEY_APP_ID, subscription.appId());
    properties.setProperty(KEY_LABEL, subscription.label());
    properties.setProperty(KEY_SOURCE_URI, subscription.sourceUri());
    properties.setProperty(KEY_ENABLED, Boolean.toString(subscription.enabled()));
    properties.setProperty(KEY_STATUS, subscription.status().jsonValue());
    properties.setProperty(
        KEY_POLL_INTERVAL_SECONDS, Long.toString(subscription.policy().pollIntervalSeconds()));
    properties.setProperty(KEY_MAX_BYTES, Long.toString(subscription.policy().maxBytes()));
    properties.setProperty(
        KEY_TIMEOUT_MILLIS, Long.toString(subscription.policy().timeoutMillis()));
    setInstant(properties, KEY_CREATED_AT, subscription.createdAt());
    setInstant(properties, KEY_UPDATED_AT, subscription.updatedAt());
    setInstant(properties, KEY_LAST_CHECK_AT, subscription.lastCheckAt());
    setInstant(properties, KEY_NEXT_CHECK_AT, subscription.nextCheckAt());
    setInstant(properties, KEY_LAST_SUCCESS_AT, subscription.lastSuccessAt());
    setInstant(properties, KEY_LAST_FAILURE_AT, subscription.lastFailureAt());
    properties.setProperty(KEY_FAILURE_COUNT, Integer.toString(subscription.failureCount()));
    setOptional(properties, KEY_LAST_ERROR_CODE, subscription.lastErrorCode());
    setOptional(properties, KEY_LAST_SEEN_RESOLVED_URI, subscription.lastSeenResolvedUri());
    setLong(properties, KEY_LAST_SEEN_EDITION, subscription.lastSeenEdition());
    setOptional(properties, KEY_CONTENT_SHA_256, subscription.contentSha256());
    setLong(properties, KEY_BYTES_LENGTH, subscription.bytesLength());
    properties.setProperty(KEY_UPDATE_COUNT, Integer.toString(subscription.updateCount()));
    setOptional(properties, KEY_MESSAGE, subscription.message());
    Path tempFile = Files.createTempFile(parentDirectory, ".content-subscription-", ".tmp");
    boolean moved = false;
    try {
      try (Writer writer = Files.newBufferedWriter(tempFile, StandardCharsets.UTF_8)) {
        properties.store(writer, "Cryptad content subscription metadata");
      }
      moveReplacing(tempFile, file);
      moved = true;
    } finally {
      if (!moved) {
        Files.deleteIfExists(tempFile);
      }
    }
  }

  @Override
  public synchronized boolean delete(String appId, String subscriptionId) throws IOException {
    String normalizedAppId = AppManifest.normalizeAppId(appId);
    String normalizedSubscriptionId = ContentSubscription.requireSubscriptionId(subscriptionId);
    return Files.deleteIfExists(subscriptionFile(normalizedAppId, normalizedSubscriptionId));
  }

  @Override
  public synchronized void deleteAllForApp(String appId) throws IOException {
    String normalizedAppId = AppManifest.normalizeAppId(appId);
    Path appDirectory = appDirectory(normalizedAppId);
    if (!Files.exists(appDirectory, LinkOption.NOFOLLOW_LINKS)) {
      return;
    }
    if (!Files.isDirectory(appDirectory, LinkOption.NOFOLLOW_LINKS)) {
      Files.deleteIfExists(appDirectory);
      return;
    }
    List<Path> paths;
    try (Stream<Path> stream = Files.walk(appDirectory)) {
      paths = stream.sorted(Comparator.reverseOrder()).toList();
    }
    for (Path path : paths) {
      Files.deleteIfExists(path);
    }
  }

  private Stream<ContentSubscription> listAppDirectorySafely(Path appDirectory) {
    String appId = appDirectory.getFileName().toString();
    try {
      AppManifest.normalizeAppId(appId);
    } catch (RuntimeException _) {
      return Stream.empty();
    }
    try {
      return listForApp(appId).stream();
    } catch (IOException _) {
      return Stream.empty();
    }
  }

  private Optional<ContentSubscription> readState(
      Path file, String expectedAppId, String expectedSubscriptionId) {
    if (!Files.isRegularFile(file)) {
      return Optional.empty();
    }
    Properties properties = new Properties();
    try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
      properties.load(reader);
      if (!"1".equals(properties.getProperty(KEY_VERSION))) {
        return Optional.empty();
      }
      ContentSubscription subscription =
          new ContentSubscription(
              properties.getProperty(KEY_SUBSCRIPTION_ID),
              properties.getProperty(KEY_APP_ID),
              properties.getProperty(KEY_LABEL),
              properties.getProperty(KEY_SOURCE_URI),
              ContentSubscription.SOURCE_KIND_USK,
              properties.getProperty(KEY_SOURCE_URI),
              Boolean.parseBoolean(properties.getProperty(KEY_ENABLED, "true")),
              ContentSubscriptionStatus.fromJsonValue(properties.getProperty(KEY_STATUS)),
              new ContentSubscriptionPolicy(
                  Duration.ofSeconds(
                      positiveLongOrOne(properties.getProperty(KEY_POLL_INTERVAL_SECONDS))),
                  positiveLongOrOne(properties.getProperty(KEY_MAX_BYTES)),
                  Duration.ofMillis(positiveLongOrOne(properties.getProperty(KEY_TIMEOUT_MILLIS)))),
              instant(properties.getProperty(KEY_CREATED_AT)),
              instant(properties.getProperty(KEY_UPDATED_AT)),
              instant(properties.getProperty(KEY_LAST_CHECK_AT)),
              instant(properties.getProperty(KEY_NEXT_CHECK_AT)),
              instant(properties.getProperty(KEY_LAST_SUCCESS_AT)),
              instant(properties.getProperty(KEY_LAST_FAILURE_AT)),
              integer(properties.getProperty(KEY_FAILURE_COUNT)),
              properties.getProperty(KEY_LAST_ERROR_CODE),
              properties.getProperty(KEY_LAST_SEEN_RESOLVED_URI),
              nullableLong(properties.getProperty(KEY_LAST_SEEN_EDITION)),
              properties.getProperty(KEY_CONTENT_SHA_256),
              nullableLong(properties.getProperty(KEY_BYTES_LENGTH)),
              integer(properties.getProperty(KEY_UPDATE_COUNT)),
              properties.getProperty(KEY_MESSAGE));
      if (!expectedAppId.equals(subscription.appId())) {
        return Optional.empty();
      }
      if (expectedSubscriptionId != null
          && !expectedSubscriptionId.equals(subscription.subscriptionId())) {
        return Optional.empty();
      }
      return Optional.of(subscription);
    } catch (RuntimeException | IOException _) {
      return Optional.empty();
    }
  }

  private Path appDirectory(String appId) {
    return rootDirectory.resolve(AppManifest.normalizeAppId(appId));
  }

  private Path subscriptionFile(String appId, String subscriptionId) {
    String normalizedAppId = AppManifest.normalizeAppId(appId);
    String normalizedSubscriptionId = ContentSubscription.requireSubscriptionId(subscriptionId);
    return appDirectory(normalizedAppId).resolve(normalizedSubscriptionId + FILE_SUFFIX);
  }

  private static void moveReplacing(Path source, Path target) throws IOException {
    try {
      Files.move(
          source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } catch (AtomicMoveNotSupportedException _) {
      Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
    }
  }

  private static Instant instant(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    try {
      return Instant.parse(value.trim());
    } catch (RuntimeException _) {
      return null;
    }
  }

  private static int integer(String value) {
    if (value == null || value.isBlank()) {
      return 0;
    }
    try {
      return Math.max(0, Integer.parseInt(value.trim()));
    } catch (NumberFormatException _) {
      return 0;
    }
  }

  private static long positiveLongOrOne(String value) {
    Long parsed = nullableLong(value);
    return parsed == null || parsed <= 0L ? MIN_RESTORED_POLICY_VALUE : parsed;
  }

  private static Long nullableLong(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    try {
      return Long.parseLong(value.trim());
    } catch (NumberFormatException _) {
      return null;
    }
  }

  private static void setInstant(Properties properties, String key, Instant value) {
    if (value != null) {
      properties.setProperty(key, value.toString());
    }
  }

  private static void setLong(Properties properties, String key, Long value) {
    if (value != null) {
      properties.setProperty(key, Long.toString(value));
    }
  }

  private static void setOptional(Properties properties, String key, String value) {
    if (value != null) {
      properties.setProperty(key, value);
    }
  }
}
