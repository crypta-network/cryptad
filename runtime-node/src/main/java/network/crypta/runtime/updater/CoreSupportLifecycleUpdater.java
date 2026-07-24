package network.crypta.runtime.updater;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.time.Duration;
import network.crypta.client.FetchResult;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Trusted update-key subscriber for the mutable Stable 1.0 support-lifecycle descriptor.
 *
 * <p>The updater follows the dedicated {@code support-lifecycle} USK docname under the configured
 * public core update key. Each fetched edition is validated by {@link CoreSupportLifecycleState}
 * against the exact key identity digest, opaque public scope, docname, semantic predecessor chain,
 * release inventory, and running build identity before replacing persisted last-known-good state.
 *
 * <p>Fetch or validation failures retain the prior descriptor and expose only bounded failure
 * codes. The implementation never logs raw descriptor bodies or URIs, and a build whose lifecycle
 * status is {@code revoked} does not call update-key revocation or blow code.
 */
final class CoreSupportLifecycleUpdater extends NodeUpdater {
  /** Logger for bounded acceptance and persistence outcomes; descriptor bodies are never logged. */
  private static final Logger LOG = LoggerFactory.getLogger(CoreSupportLifecycleUpdater.class);

  /** Validator and last-known-good owner for descriptors fetched by this subscriber. */
  private final CoreSupportLifecycleState lifecycleState;

  /** Initial delay for retrying a descriptor whose validated bytes could not be persisted. */
  private static final long INITIAL_PERSISTENCE_RETRY_DELAY_MILLIS =
      Duration.ofMinutes(1).toMillis();

  /** Maximum delay between repeated lifecycle persistence attempts. */
  private static final long MAX_PERSISTENCE_RETRY_DELAY_MILLIS = Duration.ofHours(1).toMillis();

  /** Edition associated with the current persistence-failure backoff sequence. */
  private int persistenceFailureEdition = -1;

  /** Saturating exponent used to back off persistence retries for one edition. */
  private int persistenceFailureExponent;

  /**
   * Creates a lifecycle subscriber over the same public key as the package updater.
   *
   * @param params updater subscription parameters using the dedicated lifecycle docname
   * @param lifecycleState validator and persisted last-known-good state owner
   */
  CoreSupportLifecycleUpdater(NodeUpdaterParams params, CoreSupportLifecycleState lifecycleState) {
    super(params);
    this.lifecycleState = lifecycleState;
    this.fetchedVersion = lifecycleState.acceptedEditionSeed();
  }

  @Override
  public String artifactName() {
    return "support-lifecycle descriptor";
  }

  @Override
  protected void onStartFetching() {
    // Lifecycle visibility is derived from the last-known-good state, not in-flight bytes.
  }

  @Override
  protected boolean isFetchingEnabled() {
    return true;
  }

  @Override
  protected boolean isFetchingBlockedByManagerState() {
    return manager.isUpdateKeyCompromised();
  }

  @Override
  protected void maybeParseManifest(FetchResult result, int build) {
    // Exact descriptor validation and persistence run after NodeUpdater releases its monitor.
  }

  @Override
  protected boolean processSuccess(int fetched, FetchResult result, File blobFile) {
    try {
      byte[] descriptorBytes = readBounded(result);
      lifecycleState.accept(descriptorBytes, fetched);
      clearPersistenceFailureBackoff();
      LOG.info("Accepted Stable 1.0 support-lifecycle descriptor edition {}", fetched);
      return true;
    } catch (IllegalArgumentException _) {
      clearPersistenceFailureBackoff();
      lifecycleState.recordFailure("lifecycle_validation_failed");
      LOG.warn("Rejected Stable 1.0 support-lifecycle descriptor edition {}", fetched);
      return false;
    } catch (IOException _) {
      recordPersistenceFailure(fetched);
      lifecycleState.recordFailure("lifecycle_persistence_failed");
      LOG.warn("Could not persist Stable 1.0 support-lifecycle descriptor edition {}", fetched);
      return false;
    } finally {
      deleteFetchedBlob(blobFile);
    }
  }

  @Override
  protected synchronized long rejectedFetchRetryDelayMillis() {
    if (persistenceFailureEdition < 0) {
      return -1;
    }
    long delay = INITIAL_PERSISTENCE_RETRY_DELAY_MILLIS << persistenceFailureExponent;
    return Math.min(delay, MAX_PERSISTENCE_RETRY_DELAY_MILLIS);
  }

  @Override
  protected int selectDiscoveredEdition(int discoveredEdition) {
    return Math.min(discoveredEdition, lifecycleState.acceptedEditionSeed() + 1);
  }

  @Override
  protected boolean fetchIntermediateEditionsSequentially() {
    return true;
  }

  @Override
  protected void recordSuccessfulFetch(FreenetURI fetchedUri, int fetchedEdition) {
    // Lifecycle editions are persisted with exact descriptor bytes in their own LKG store.
  }

  /** Starts or advances the saturating persistence retry backoff for one descriptor edition. */
  private synchronized void recordPersistenceFailure(int fetchedEdition) {
    if (persistenceFailureEdition != fetchedEdition) {
      persistenceFailureEdition = fetchedEdition;
      persistenceFailureExponent = 0;
      return;
    }
    if ((INITIAL_PERSISTENCE_RETRY_DELAY_MILLIS << persistenceFailureExponent)
        < MAX_PERSISTENCE_RETRY_DELAY_MILLIS) {
      persistenceFailureExponent++;
    }
  }

  /** Clears persistence retry state after an accepted descriptor or permanent validation error. */
  private synchronized void clearPersistenceFailureBackoff() {
    persistenceFailureEdition = -1;
    persistenceFailureExponent = 0;
  }

  /**
   * Reads one fetched descriptor without allowing an oversized payload into memory.
   *
   * <p>The declared fetch size and the actual bytes read must both fit the parser's fixed public
   * descriptor limit. The returned byte array is the exact input subsequently checked and stored by
   * the lifecycle state; this method performs no character decoding or logging.
   *
   * @param result completed fetch result containing the candidate descriptor body
   * @return exact bounded descriptor bytes ready for strict parsing
   * @throws IOException if the fetched bucket cannot be opened or read completely
   * @throws IllegalArgumentException if the declared or actual payload size is invalid
   */
  private static byte[] readBounded(FetchResult result) throws IOException {
    if (result == null
        || result.size() <= 0
        || result.size() > CoreSupportLifecycleParser.MAX_DESCRIPTOR_BYTES) {
      throw new IllegalArgumentException("lifecycle descriptor is outside runtime size bounds");
    }
    try (Bucket bucket = result.asBucket();
        InputStream input = bucket.getInputStream()) {
      byte[] bytes = input.readNBytes(CoreSupportLifecycleParser.MAX_DESCRIPTOR_BYTES + 1);
      if (bytes.length == 0 || bytes.length > CoreSupportLifecycleParser.MAX_DESCRIPTOR_BYTES) {
        throw new IllegalArgumentException("lifecycle descriptor is outside runtime size bounds");
      }
      return bytes;
    }
  }

  /**
   * Removes the temporary finalized fetch blob after validation has consumed its bytes.
   *
   * <p>Cleanup is the best effort because acceptance is determined by the exact descriptor stored
   * by {@link CoreSupportLifecycleState}, not by retaining the transport blob. Failures are
   * reported without including the local path.
   *
   * @param blobFile temporary fetched blob, or {@code null} when no file was finalized
   */
  private static void deleteFetchedBlob(File blobFile) {
    if (blobFile == null) {
      return;
    }
    try {
      Files.deleteIfExists(blobFile.toPath());
    } catch (IOException _) {
      LOG.warn("Could not remove a processed lifecycle fetch blob");
    }
  }
}
