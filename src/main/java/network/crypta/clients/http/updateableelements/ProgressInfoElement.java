package network.crypta.clients.http.updateableelements;

import network.crypta.client.FetchContext;
import network.crypta.clients.http.FProxyFetchInProgress;
import network.crypta.clients.http.FProxyFetchResult;
import network.crypta.clients.http.FProxyFetchTracker;
import network.crypta.clients.http.FProxyFetchWaiter;
import network.crypta.clients.http.FProxyToadlet;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.complexhtmlnodes.SecondCounterNode;
import network.crypta.keys.FreenetURI;
import network.crypta.support.Base64;
import network.crypta.support.HTMLNode;
import network.crypta.support.SizeUtil;

/**
 * Renders the progress information box for an in-progress fetch on the FProxy progress page.
 *
 * <p>This element is used by the HTTP UI's "updateable elements" system to present status for a
 * single {@link FreenetURI} being fetched. It periodically rebuilds its child HTML tree from the
 * latest {@link FProxyFetchResult} produced by a {@link FProxyFetchTracker}. The output includes
 * basic metadata (filename, MIME type, size) and live timing information (elapsed time and an ETA
 * counter when available). When constructed in "advanced mode", it also renders block-level detail
 * suitable for debugging or power users.
 *
 * <p>Instances are mutable and rebuild their internal children list on each update. The
 * implementation performs no synchronization; callers should treat instances as confined to the
 * request/UI lifecycle that owns the element tree.
 *
 * <ul>
 *   <li><b>Primary responsibility:</b> Convert fetch progress into human-readable HTML.
 *   <li><b>Optional push integration:</b> When {@code pushed} is true, registers a listener so the
 *       UI can be refreshed promptly on progress events.
 * </ul>
 *
 * @see BaseUpdatableElement
 * @see FProxyToadlet
 */
public class ProgressInfoElement extends BaseUpdatableElement {

  private final FProxyFetchTracker tracker;
  private final FreenetURI key;
  private final FetchContext fctx;
  private final long maxSize;
  private NotifierFetchListener fetchListener;

  /** Whether to render advanced-mode details (e.g., per-block counters). */
  private final boolean isAdvancedMode;

  /**
   * Creates a progress info element for a single in-progress fetch.
   *
   * <p>The element is bound to the supplied {@code tracker}, {@code key}, {@code fctx}, and {@code
   * maxSize}; those values are used on each update to look up the current {@link FProxyFetchResult}
   * and to release any temporary objects acquired from the tracker. If {@code pushed} is true, the
   * element also registers a {@link NotifierFetchListener} with the server's push manager so that
   * UI updates can be triggered promptly when progress changes.
   *
   * <p>This constructor does not perform validation of the provided arguments. In particular, the
   * {@code key} is expected to be non-null and stable for the lifetime of the element.
   *
   * @param tracker fetch tracker used to locate and close progress/result objects.
   * @param key the {@link FreenetURI} being fetched and displayed in this element.
   * @param fctx fetch context forwarded to tracker lookups for this request.
   * @param maxSize maximum size hint forwarded to tracker lookups for this request.
   * @param isAdvancedMode whether to include advanced block counters in the rendered output.
   * @param ctx request context providing the server container and feature flags.
   * @param pushed whether to register for push-driven refresh notifications immediately.
   */
  public ProgressInfoElement(
      FProxyFetchTracker tracker,
      FreenetURI key,
      FetchContext fctx,
      long maxSize,
      boolean isAdvancedMode,
      ToadletContext ctx,
      boolean pushed) {
    super("span", ctx);
    this.tracker = tracker;
    this.key = key;
    this.fctx = fctx;
    this.maxSize = maxSize;
    this.isAdvancedMode = isAdvancedMode;
    init(pushed);
    if (!pushed) return;
    fetchListener =
        new NotifierFetchListener(
            ((SimpleToadletServer) ctx.getContainer()).getPushDataManager(), this);
    tracker.getFetchInProgress(key, maxSize, fctx).addListener(fetchListener);
  }

  /**
   * Rebuilds this element's children to reflect the latest fetch progress.
   *
   * <p>This method queries the {@link FProxyFetchTracker} for the current progress and then
   * replaces the element's HTML children with a freshly rendered view. If no fetch result can be
   * obtained, a short "No fetcher found" message is rendered instead. When progress data is
   * present, the output includes basic file metadata and a time elapsed counter, and may include an
   * ETA counter as well as advanced block-level detail.
   *
   * <p>The {@code initial} flag is currently ignored by this implementation; it is accepted for
   * compatibility with the updatable element interface.
   *
   * @param initial whether this update is the initial render; currently ignored.
   */
  @Override
  public void updateState(boolean initial) {
    children.clear();

    FProxyFetchWaiter waiter = tracker.makeWaiterForFetchInProgress(key, maxSize, fctx);
    FProxyFetchResult fr = waiter == null ? null : waiter.getResult();
    if (fr == null) {
      addChild("div", "No fetcher found");
      return;
    }

    addChild("#", FProxyToadlet.l10n("filenameLabel") + " ");
    addChild("a", "href", "/" + key.toString(false, false), key.getPreferredFilename());
    if (fr.mimeType != null)
      addChild("br", FProxyToadlet.l10n("contentTypeLabel") + " " + fr.mimeType);
    if (fr.size > 0) addChild("br", "Size: " + SizeUtil.formatSize(fr.size));
    if (isAdvancedMode) {
      addChild(
          "br",
          FProxyToadlet.l10n(
              "blocksDetail",
              new String[] {"fetched", "required", "total", "failed", "fatallyfailed"},
              new String[] {
                Integer.toString(fr.fetchedBlocks),
                Integer.toString(fr.requiredBlocks),
                Integer.toString(fr.totalBlocks),
                Integer.toString(fr.failedBlocks),
                Integer.toString(fr.fatallyFailedBlocks)
              }));
    }
    long elapsed = System.currentTimeMillis() - fr.timeStarted;
    addChild("br");
    addChild(new SecondCounterNode(elapsed, true, FProxyToadlet.l10n("timeElapsedLabel") + " "));
    long eta = fr.eta - elapsed;
    if (eta > 0) {
      addChild("br");
      addChild(new SecondCounterNode(eta, false, "ETA: "));
    }
    if (ctx.getContainer().isFProxyJavascriptEnabled()) {
      HTMLNode lastRefreshNode = new HTMLNode("span", "class", "jsonly");
      lastRefreshNode.addChild("br");
      lastRefreshNode.addChild(new SecondCounterNode(0, true, FProxyToadlet.l10n("lastRefresh")));
      addChild(lastRefreshNode);
    }
    if (fr.goneToNetwork) addChild("p", FProxyToadlet.l10n("progressDownloading"));
    else addChild("p", FProxyToadlet.l10n("progressCheckingStore"));
    if (!fr.finalizedBlocks) addChild("p", FProxyToadlet.l10n("progressNotFinalized"));

    tracker.getFetchInProgress(key, maxSize, fctx).close(waiter);
    tracker.getFetchInProgress(key, maxSize, fctx).close(fr);
  }

  /**
   * Returns the stable updater identifier for this element.
   *
   * <p>The returned value is derived solely from the element's {@link FreenetURI} and is therefore
   * stable across updates for the same URI. The {@code requestId} parameter is accepted for
   * signature compatibility and is not used by this implementation.
   *
   * @param requestId request identifier from the surrounding UI; ignored by this implementation.
   * @return a stable updater id suitable for client-side element replacement.
   */
  @Override
  public String getUpdaterId(String requestId) {
    return getId(key);
  }

  /**
   * Computes the updater id string used to identify a progress info element for a URI.
   *
   * <p>The id is a Base64-encoded UTF-8 string that incorporates the URI's string form. The exact
   * encoding is an implementation detail, but the output is intended to be stable for a given
   * {@code uri} and safe for use as an HTML element identifier in the updateable elements system.
   *
   * @param uri the {@link FreenetURI} to derive an updater id from; must be non-null.
   * @return a deterministic Base64-encoded updater id derived from the supplied URI.
   * @throws NullPointerException if {@code uri} is null.
   */
  public static String getId(FreenetURI uri) {
    return Base64.encodeStandardUTF8(("progressinfo[URI:" + uri.toString() + "]"));
  }

  /**
   * Releases any resources held by this element.
   *
   * <p>If the element was created in {@code pushed} mode, it attempts to unregister the internal
   * {@link NotifierFetchListener} from the corresponding {@link FProxyFetchInProgress}. This
   * prevents the push system from retaining references after the element is no longer in use.
   *
   * <p>This method is idempotent with respect to a missing progress object; if no in-progress fetch
   * exists, no action is taken.
   */
  @Override
  public void dispose() {
    FProxyFetchInProgress progress = tracker.getFetchInProgress(key, maxSize, fctx);
    if (progress != null) {
      progress.removeListener(fetchListener);
    }
  }

  /**
   * Returns the updater type constant for this element.
   *
   * <p>This element uses the "replacer" updater model, meaning updates replace the entire element
   * subtree rather than applying incremental patches.
   *
   * @return the updater type string for a replacer-style updatable element.
   */
  @Override
  public String getUpdaterType() {
    return UpdaterConstants.REPLACER_UPDATER;
  }

  /**
   * Returns a debugging representation including the key and computed updater id.
   *
   * <p>The returned string is intended for logs and diagnostics. It includes the associated {@link
   * FreenetURI}, the configured {@code maxSize}, and the current updater id.
   *
   * @return a human-readable representation of this element for debugging.
   */
  @Override
  public String toString() {
    return "ProgressInfoElement[key:"
        + key
        + ",maxSize:"
        + maxSize
        + ",updaterId:"
        + getUpdaterId(null)
        + "]";
  }
}
