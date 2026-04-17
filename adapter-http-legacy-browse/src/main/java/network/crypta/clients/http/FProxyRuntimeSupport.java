package network.crypta.clients.http;

import java.io.File;
import java.io.IOException;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.async.CacheFetchResult;
import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.config.SubConfig;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.node.RequestClient;
import network.crypta.support.api.Bucket;

/**
 * Supplies the runtime-facing services that {@link FProxyToadlet} needs from the live daemon.
 *
 * <p>This interface is public only so runtime-owned HTTP bootstrap adapters can implement it from
 * outside {@code network.crypta.clients.http}. It is not a new platform API. The seam keeps the
 * HTTP-side FProxy code coupled to a narrow contract instead of the full node core. The surface is
 * intentionally small: it exposes only the fetch/cache helpers, threat-level state, download-policy
 * checks, background execution, and the FProxy sub-configuration needed to preserve current
 * behavior. Code in {@code clients/http} can depend on this seam without pulling in broader node
 * assembly concerns.
 *
 * <p>Implementations typically wrap a long-lived daemon object and delegate directly. Callers are
 * expected to get one instance during HTTP bootstrap and reuse it for the lifetime of the toadlet
 * registration.
 */
public interface FProxyRuntimeSupport {

  /**
   * Starts a legacy FProxy fetch against the runtime fetch engine.
   *
   * @param uri target content URI
   * @param fetchContext mutable fetch context describing the request
   * @param priorityClass scheduling priority for the runtime fetch
   * @param requestClient request identity used for scheduling and accounting
   * @param callback callback that observes terminal fetch outcomes
   * @return handle that can cancel the in-flight fetch
   * @throws FetchException if the fetch cannot be started
   */
  FetchHandle startFetch(
      FreenetURI uri,
      FetchContext fetchContext,
      short priorityClass,
      RequestClient requestClient,
      FetchCallback callback)
      throws FetchException;

  /**
   * Looks up an existing cached fetch result for the given URI.
   *
   * @param uri target content URI
   * @param allowUnfilteredReuse whether an unfiltered cache hit may be reused directly
   * @return cached fetch result or {@code null} if none is available
   */
  CacheFetchResult lookupCachedResult(FreenetURI uri, boolean allowUnfilteredReuse);

  /**
   * Creates a temporary bucket for intermediate filtering work.
   *
   * @param maxSize requested maximum bucket size, or {@code -1} for implementation default
   * @return fresh temporary bucket
   * @throws IOException if the runtime cannot allocate the temporary bucket
   */
  Bucket createTempBucket(long maxSize) throws IOException;

  /**
   * Exposes the runtime link-filter exception provider used by HTML filtering.
   *
   * @return current link-filter exception provider
   */
  LinkFilterExceptionProvider linkFilterExceptionProvider();

  /**
   * Returns the latest known-good edition for the given USK.
   *
   * @param usk key to query
   * @return latest known-good edition, or {@code -1} when unknown
   */
  long lookupKnownGoodEdition(USK usk);

  /**
   * Queues a timed job on the runtime ticker.
   *
   * @param task job to schedule
   * @param delayMillis delay before execution, in milliseconds
   */
  void queueTimedJob(Runnable task, long delayMillis);

  /**
   * Returns a pseudo-random identifier from the runtime fast weak random source.
   *
   * @return best-effort process-local random integer
   */
  int nextWeakRandomInt();

  /**
   * Returns the current physical-threat policy that should govern local download behavior.
   *
   * <p>FProxy uses this value to decide whether disk-download controls should be shown or
   * suppressed for the current node security posture. The enum is a local to the HTTP package, so
   * callers do not need to import node-level security types.
   *
   * @return the physical-threat level currently enforced for the node.
   */
  PhysicalThreatLevel physicalThreatLevel();

  /**
   * Returns the current network-threat policy that should govern local download behavior.
   *
   * <p>Combined with {@link #physicalThreatLevel()}, this value determines which download actions
   * remain available from the browser UI. The local enum preserves the existing decision points
   * while avoiding a direct dependency on the node security API from {@link FProxyToadlet}.
   *
   * @return the network-threat level currently enforced for the node.
   */
  NetworkThreatLevel networkThreatLevel();

  /**
   * Reports whether downloads to local storage are globally disabled.
   *
   * <p>This check represents a hard gate. When it returns {@code true}, FProxy should avoid
   * presenting or executing disk-download flows even if the request path would otherwise be valid.
   *
   * @return {@code true} when local downloads are disabled for this node instance.
   */
  boolean isDownloadDisabled();

  /**
   * Returns the default download directory configured for the local node.
   *
   * <p>FProxy uses this path as the primary destination suggestion when it offers download-to-disk
   * actions. The path may still be subject to additional allowlist checks via {@link
   * #allowDownloadTo(File)} and {@link #allowedDownloadDirs()}.
   *
   * @return the configured default directory for downloads.
   */
  File downloadsDir();

  /**
   * Checks whether a specific destination path is allowed for download-to-disk operations.
   *
   * <p>The check is used to preserve the node's existing download sandbox rules. Callers should
   * treat a {@code false} result as authoritative and avoid presenting the corresponding location
   * as a selectable writing target.
   *
   * @param file destination file or directory candidate to validate against node policy.
   * @return {@code true} when the supplied path is allowed for downloads.
   */
  boolean allowDownloadTo(File file);

  /**
   * Returns the configured allowlist roots for download-to-disk operations.
   *
   * <p>FProxy uses these directories when it needs to explain or evaluate where files may be saved.
   * The returned array is owned by the implementation; callers should treat it as read-only
   * configuration data.
   *
   * @return the allowed download directory roots currently configured for the node.
   */
  File[] allowedDownloadDirs();

  /**
   * Schedules background work needed for asynchronous HTTP-side follow-up tasks.
   *
   * <p>The supplied task runs on the node-managed executor associated with FProxy support work.
   * Callers use this hook for fire-and-forget tasks such as prefetch follow-up, not for request
   * threads that must complete inline with the current HTTP response.
   *
   * @param task runnable unit of background work to execute.
   */
  void executeBackground(Runnable task);

  /**
   * Returns the live {@code fproxy} sub-configuration.
   *
   * <p>This remains part of the local seam because FProxy still reads a few settings directly from
   * the HTTP layer. The method intentionally exposes {@link SubConfig} instead of introducing a
   * wider shared SPI before the rest of the HTTP refactor is ready.
   *
   * @return the sub-configuration containing FProxy-specific settings.
   */
  SubConfig fproxyConfig();

  /**
   * Describes the local machine-threat posture used when deciding whether disk actions are safe.
   */
  enum PhysicalThreatLevel {
    /** Local physical access is treated as low risk. */
    LOW,
    /** Local physical access is treated as requiring the default safeguards. */
    NORMAL,
    /** Local physical access is treated as high risk, and disk actions become more restricted. */
    HIGH,
    /** Local physical access is treated as maximally hostile and disk actions are suppressed. */
    MAXIMUM
  }

  /** Describes the network-threat posture used when deciding whether disk actions are safe. */
  enum NetworkThreatLevel {
    /** Remote network observation or interference is treated as low risk. */
    LOW,
    /** Remote network observation or interference is treated as requiring default safeguards. */
    NORMAL,
    /** Remote network observation or interference is treated as high risk. */
    HIGH,
    /** Remote network observation or interference is treated as maximally hostile. */
    MAXIMUM
  }

  /** Terminal callback for runtime-backed FProxy fetches. */
  interface FetchCallback {
    /**
     * Called when the fetch completes successfully.
     *
     * @param result completed fetch result
     */
    void onSuccess(FetchResult result);

    /**
     * Called when the fetch fails.
     *
     * @param failure terminal fetch failure
     */
    void onFailure(FetchException failure);
  }

  /** Handle for a runtime-backed in-flight FProxy fetch. */
  interface FetchHandle {
    /** Cancels the associated in-flight fetch. */
    void cancel();
  }
}
