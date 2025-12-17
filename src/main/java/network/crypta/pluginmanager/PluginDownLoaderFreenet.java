package network.crypta.pluginmanager;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchResult;
import network.crypta.client.FetchWaiter;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.ReadBucketAndFreeInputStream;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.pluginmanager.PluginManager.PluginProgress;
import network.crypta.support.api.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Downloads a plugin archive from Crypta (Freenet) given a {@link FreenetURI} source key.
 *
 * <p>This downloader is used by {@link PluginManager} when a plugin is configured to be fetched
 * from the network rather than from a local file or an external URL. Callers typically create an
 * instance via the plugin manager's download flow, validate the source with {@link
 * #checkSource(String)}, and then request the plugin contents through the parent {@link
 * PluginDownLoader} contract.
 *
 * <p>Notable behaviors include redirect handling (permanent redirects and path-component rewrites),
 * download progress reporting via {@link SplitfileProgressEvent}, and careful resource ownership:
 * the returned {@link InputStream} releases the underlying {@link Bucket} when closed.
 *
 * <p>This type is stateful and not thread-safe. A single instance is intended for one in-flight
 * download attempt; it tracks the active {@link ClientGetter} for cancellation and records whether
 * the last failure was fatal via {@link #fatalFailure()}.
 *
 * <ul>
 *   <li><b>Progress reporting:</b> Updates {@link PluginProgress} when total splitfile size is
 *       known.
 *   <li><b>Retry policy:</b> In "desperate" mode, disables the standard retry limits.
 *   <li><b>Cancellation:</b> Attempts to cancel the current getter via {@link #tryCancel()}.
 * </ul>
 */
public class PluginDownLoaderFreenet extends PluginDownLoader<FreenetURI> {
  private static final Logger LOG = LoggerFactory.getLogger(PluginDownLoaderFreenet.class);

  final HighLevelSimpleClient hlsc;
  final boolean desperate;
  final Node node;
  private boolean fatalFailure;
  private ClientGetter get;

  PluginDownLoaderFreenet(HighLevelSimpleClient hlsc, Node node, boolean desperate) {
    this.hlsc = hlsc.copy();
    this.node = node;
    this.desperate = desperate;
  }

  /**
   * Parses and validates a plugin source string as a {@link FreenetURI}.
   *
   * <p>This method converts the user- or configuration-provided source into the strongly typed URI
   * representation used by the downloader. The returned {@link FreenetURI} is suitable for passing
   * to the internal fetch pipeline. If the input is not a syntactically valid Freenet key, the
   * failure is surfaced as a {@link PluginNotFoundException} so callers can treat it like any other
   * lookup error.
   *
   * <p>This method performs only parsing/validation; it does not contact the network and does not
   * verify that the key actually exists.
   *
   * @param source Freenet URI string identifying plugin content; parsed as-is.
   * @return A parsed {@link FreenetURI} representing the same source key.
   * @throws PluginNotFoundException If {@code source} is not a valid Freenet key string.
   */
  @Override
  public FreenetURI checkSource(String source) throws PluginNotFoundException {
    try {
      return new FreenetURI(source);
    } catch (MalformedURLException e) {
      throw new PluginNotFoundException("not a valid freenet key: " + source, e);
    }
  }

  @Override
  InputStream getInputStream(final PluginProgress progress)
      throws IOException, PluginNotFoundException {
    FreenetURI uri = getSource();
    LOG.info("Downloading plugin from Crypta: {}", uri);
    while (true) {
      try {
        progress.setDownloading();
        hlsc.addEventHook(
            (ce, context) -> {
              if (ce instanceof SplitfileProgressEvent split && split.finalizedTotal) {
                progress.setDownloadProgress(
                    split.getMinSuccessfulBlocks(),
                    split.succeedBlocks,
                    split.totalBlocks,
                    split.failedBlocks,
                    split.fatallyFailedBlocks,
                    true);
              }
            });
        FetchResult res = fetchPlugin(uri);
        return openAndReleaseOnClose(res);
      } catch (FetchException e) {
        if (isRedirect(e)) {
          uri = e.newURI;
          continue;
        }
        throw asPluginNotFoundException(e);
      }
    }
  }

  private static InputStream openAndReleaseOnClose(FetchResult res) throws IOException {
    Bucket bucket = res.asBucket();
    try {
      return ReadBucketAndFreeInputStream.create(bucket);
    } catch (IOException | RuntimeException e) {
      bucket.free();
      throw e;
    }
  }

  private FetchResult fetchPlugin(FreenetURI uri) throws FetchException {
    FetchContext context = hlsc.getFetchContext();
    if (desperate) {
      context.setMaxNonSplitfileRetries(-1);
      context.setMaxSplitfileBlockRetries(-1);
    }
    FetchWaiter fw = new FetchWaiter(node.getNonPersistentClientBulk());
    get = new ClientGetter(fw, uri, context, PluginManager.PRIO, null, null, null);
    startGetter(get);
    return fw.waitForCompletion();
  }

  private void startGetter(ClientGetter getter) throws FetchException {
    try {
      node.getClientCore().getClientContext().start(getter);
    } catch (PersistenceDisabledException e) {
      throw new IllegalStateException("Plugin download unexpectedly requires persistence", e);
    }
  }

  private static boolean isRedirect(FetchException e) {
    FetchExceptionMode mode = e.getMode();
    return mode == FetchExceptionMode.PERMANENT_REDIRECT
        || mode == FetchExceptionMode.TOO_MANY_PATH_COMPONENTS;
  }

  private PluginNotFoundException asPluginNotFoundException(FetchException e) {
    if (e.isFatal()) {
      fatalFailure = true;
    }
    return new PluginNotFoundException(
        "error while fetching plugin: " + e.getMessage() + " for key " + getSource(), e);
  }

  @Override
  String getPluginName(String source) throws PluginNotFoundException {
    return source.substring(source.lastIndexOf('/') + 1);
  }

  @Override
  String getSHA1sum() {
    return null;
  }

  /**
   * Indicates whether the most recent download failure was considered fatal by the fetch layer.
   *
   * <p>This flag is set when {@link FetchException#isFatal()} is observed during the download
   * attempt. It is intended to help higher-level control flow decide whether retrying is likely to
   * succeed (for example, after a definitive "not found" style failure). The value is sticky for
   * the lifetime of this downloader instance and reflects only failures encountered by this
   * instance.
   *
   * <p>This method does not perform any I/O and is safe to call at any time, including after
   * cancellation.
   *
   * @return {@code true} if a fatal fetch failure occurred during this instance's work.
   */
  public boolean fatalFailure() {
    return fatalFailure;
  }

  @Override
  void tryCancel() {
    if (get != null) get.cancel(node.getClientCore().getClientContext());
  }

  /**
   * Reports whether this downloader loads plugin content from the Crypta network.
   *
   * <p>This value is used as a simple capability indicator by higher-level logic (for example, to
   * select user-facing wording, or to decide whether "network retry" affordances are applicable).
   * For this implementation the answer is always {@code true}, as all downloads are performed via
   * {@link HighLevelSimpleClient} and {@link FreenetURI} keys.
   *
   * <p>This method is pure: it does not consult runtime state and does not initiate any I/O.
   *
   * @return {@code true} to indicate a Crypta/Freenet-backed download source.
   */
  @Override
  public boolean isLoadingFromFreenet() {
    return true;
  }

  /**
   * Creates a retry-oriented downloader instance for the same source type.
   *
   * <p>The returned downloader is configured in "desperate" mode, which relaxes retry limits in the
   * underlying {@link FetchContext}. This can be useful after a transient failure where aggressive
   * retrying is preferred over quickly surfacing an error to the user.
   *
   * <p>The new instance copies the provided {@link HighLevelSimpleClient} configuration (via {@link
   * HighLevelSimpleClient#copy()}) and does not share cancellation state with this instance.
   *
   * @return A new {@link PluginDownLoaderFreenet} suitable for retrying the download.
   */
  @Override
  public PluginDownLoader<FreenetURI> getRetryDownloader() {
    return new PluginDownLoaderFreenet(hlsc, node, true);
  }
}
