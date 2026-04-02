package network.crypta.clients.http.updateableelements;

import java.text.NumberFormat;
import network.crypta.client.FetchContext;
import network.crypta.clients.http.FProxyFetchCriteria;
import network.crypta.clients.http.FProxyFetchInProgress;
import network.crypta.clients.http.FProxyFetchResult;
import network.crypta.clients.http.FProxyFetchTracker;
import network.crypta.clients.http.FProxyFetchWaiter;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.ToadletContext;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.Base64;
import network.crypta.support.HTMLNode;

/**
 * Renders an auto-updating progress bar for an in-progress fetch in the FProxy UI.
 *
 * <p>This {@link BaseUpdatableElement} represents a pushed {@code <div>} whose content is refreshed
 * by the update mechanism while a page is loading. It observes a {@link FProxyFetchTracker} for a
 * specific {@link FreenetURI} (and the associated {@link FetchContext} and {@code maxSize}) and
 * translates the current {@link FProxyFetchResult} into a simple HTML progress bar: completed
 * blocks, transient failures, and fatal failures.
 *
 * <p>Lifecycle: when constructed with {@code pushed=true}, the instance registers a listener so UI
 * push can be triggered as new progress arrives, and {@link #updateState(boolean)} renders the
 * latest state. Once the fetch completes (finished, data available, or failed), the element
 * switches its content to {@link UpdaterConstants#FINISHED} so the surrounding UI can reload the
 * page. Call {@link #dispose()} to deregister the listener when the element is no longer needed.
 *
 * <ul>
 *   <li><b>Thread-safety:</b> not thread-safe; intended to be driven by the HTTP/UI update thread.
 *   <li><b>Scope:</b> generates HTML only; it does not initiate or control the underlying fetch.
 * </ul>
 */
public class ProgressBarElement extends BaseUpdatableElement {

  private static final String ATTR_CLASS = "class";
  private static final String ATTR_STYLE = "style";
  private static final String STYLE_WIDTH_PREFIX = "width: ";

  /** Tracker used to locate the in-progress fetch that provides progress information. */
  private final FProxyFetchTracker tracker;

  /** URI identifying the fetch whose progress is displayed by this element. */
  private final FreenetURI key;

  /**
   * Maximum expected size hint (bytes) used when selecting the corresponding in-progress fetch
   * instance.
   */
  private final long maxSize;

  /**
   * Listener registered when {@code pushed=true}, used to trigger update pushes as download
   * progress changes.
   */
  private final NotifierFetchListener fetchListener;

  private final FetchContext fctx;

  /**
   * Creates a progress bar element bound to an existing tracked fetch.
   *
   * <p>The element is rendered as a {@code <div class="progressbar">}. When {@code pushed} is
   * {@code true}, this constructor registers an internal listener with {@code tracker} so that UI
   * push updates can be triggered as the fetch advances. When {@code pushed} is {@code false}, the
   * element still renders on demand but no listener is registered and {@link #dispose()} becomes a
   * no-op.
   *
   * <p>The {@code key}, {@code maxSize}, and {@code fctx} arguments are forwarded via {@link
   * FProxyFetchCriteria} to {@link FProxyFetchTracker#getFetchInProgress(FProxyFetchCriteria)} to
   * select the correct in-progress fetch instance.
   *
   * @param tracker tracker used to locate and observe the fetch progress for the given URI.
   * @param key URI identifying the fetch whose progress is displayed by this element.
   * @param fctx fetch context used to resolve the tracked fetch; should match the initiating
   *     request.
   * @param maxSize maximum expected size hint in bytes used to select the tracked fetch instance.
   * @param ctx toadlet context providing container access and (when pushed) a push data manager.
   * @param pushed whether to register a push listener; {@code true} enables live updates, {@code
   *     false} disables.
   */
  public ProgressBarElement(
      FProxyFetchTracker tracker,
      FreenetURI key,
      FetchContext fctx,
      long maxSize,
      ToadletContext ctx,
      boolean pushed) {
    // This is a <div>
    super("div", ATTR_CLASS, "progressbar", ctx);
    this.tracker = tracker;
    this.key = key;
    this.fctx = fctx;
    this.maxSize = maxSize;
    init(pushed);
    if (!pushed) {
      fetchListener = null;
      return;
    }
    // Creates and registers the FetchListener
    fetchListener =
        new NotifierFetchListener(
            ((SimpleToadletServer) ctx.getContainer()).getPushDataManager(), this);
    tracker
        .getFetchInProgress(new FProxyFetchCriteria(key, maxSize, fctx))
        .addListener(fetchListener);
  }

  /**
   * Updates this element's rendered state to reflect the latest fetch progress.
   *
   * <p>This method clears any previously-rendered children and queries the {@link
   * FProxyFetchTracker} for the current {@link FProxyFetchResult}. If the fetch cannot be located,
   * a minimal fallback message is rendered. If the fetch is considered finished (success, available
   * data, or failure), the element emits {@link UpdaterConstants#FINISHED} so the surrounding UI
   * can trigger a page reload. Otherwise, a segmented progress bar is rendered based on fetched and
   * failed block counts, along with localized accuracy hints.
   *
   * <p>Resource handling: any obtained waiter/result objects are closed in a {@code finally} block
   * to avoid leaking fetch-related resources across update cycles.
   *
   * @param initial whether this update is the first update for the element; currently not used by
   *     this implementation.
   */
  @Override
  public void updateState(boolean initial) {
    children.clear();

    FProxyFetchInProgress progress =
        tracker.getFetchInProgress(new FProxyFetchCriteria(key, maxSize, fctx));
    FProxyFetchWaiter waiter = progress == null ? null : progress.getWaiter();
    FProxyFetchResult fr = waiter == null ? null : waiter.getResult();
    try {
      if (fr == null) {
        addChild("div", "No fetcher found");
        return;
      }
      if (isFetchFinished(fr)) {
        // If finished then we just send a FINISHED text. It will reload the page
        setContent(UpdaterConstants.FINISHED);
        return;
      }
      renderProgressBar(fr);
    } finally {
      if (waiter != null) {
        progress.close(waiter);
      }
      if (fr != null) {
        progress.close(fr);
      }
    }
  }

  private static boolean isFetchFinished(FProxyFetchResult fr) {
    return fr.isFinished() || fr.hasData() || fr.failed != null;
  }

  private void renderProgressBar(FProxyFetchResult fr) {
    int total = fr.requiredBlocks;
    int fetchedPercent = percent(fr.fetchedBlocks, total);
    int failedPercent = percent(fr.failedBlocks, total);
    int fatallyFailedPercent = percent(fr.fatallyFailedBlocks, total);

    HTMLNode progressBar = addChild("div", ATTR_CLASS, "progressbar");
    addProgressBarSegment(progressBar, "progressbar-done", fetchedPercent);

    if (fr.failedBlocks > 0) {
      addProgressBarSegment(progressBar, "progressbar-failed", failedPercent);
    }
    if (fr.fatallyFailedBlocks > 0) {
      addProgressBarSegment(progressBar, "progressbar-failed2", fatallyFailedPercent);
    }

    renderProgressText(progressBar, fr, total);
  }

  private static int percent(int blocks, int total) {
    return (int) (blocks / (double) total * 100);
  }

  private static void addProgressBarSegment(HTMLNode progressBar, String cssClass, int percent) {
    progressBar.addChild(
        "div", new String[] {ATTR_CLASS, ATTR_STYLE}, new String[] {cssClass, widthStyle(percent)});
  }

  private static String widthStyle(int percent) {
    return STYLE_WIDTH_PREFIX + percent + "%;";
  }

  private void renderProgressText(HTMLNode progressBar, FProxyFetchResult fr, int total) {
    NumberFormat nf = NumberFormat.getInstance();
    nf.setMaximumFractionDigits(1);
    String prefix = '(' + Integer.toString(fr.fetchedBlocks) + "/ " + total + "): ";

    String percentText = nf.format((int) ((fr.fetchedBlocks / (double) total) * 1000) / 10.0) + '%';
    if (fr.finalizedBlocks) {
      progressBar.addChild(
          "div",
          new String[] {ATTR_CLASS, "title"},
          new String[] {
            "progress_fraction_finalized",
            prefix + NodeL10n.getBase().getString("QueueToadlet.progressbarAccurate")
          },
          percentText);
      return;
    }

    String text = fr.fetchedBlocks + " (" + percentText + "??)";
    progressBar.addChild(
        "div",
        new String[] {ATTR_CLASS, "title"},
        new String[] {
          "progress_fraction_not_finalized",
          prefix + NodeL10n.getBase().getString("QueueToadlet.progressbarNotAccurate")
        },
        text);
  }

  /**
   * Returns the updater id for this progress bar.
   *
   * <p>The updater id is stable for a given {@link FreenetURI} and is used by the update framework
   * to identify the element to refresh. The {@code requestId} parameter is accepted for API
   * compatibility but is not used when deriving the id; callers should not rely on it affecting the
   * result.
   *
   * @param requestId request-scoped identifier provided by the update framework; ignored by this
   *     implementation.
   * @return a stable, Base64-encoded updater id derived from the current fetch URI.
   */
  @Override
  public String getUpdaterId(String requestId) {
    return getId(key);
  }

  /**
   * Computes a stable updater id for the given URI.
   *
   * <p>The returned value is a Base64-encoded, UTF-8 string that embeds the URI in a fixed prefix.
   * It is used as a DOM/update key rather than as a security boundary, and it is intended to remain
   * stable for the same URI across refresh cycles.
   *
   * @param uri URI to include in the updater id; must be non-null and should identify a single
   *     fetch.
   * @return a Base64-encoded id string suitable for identifying a progress bar element in the
   *     update system.
   */
  public static String getId(FreenetURI uri) {
    return Base64.encodeStandardUTF8(("progressbar[URI:" + uri.toString() + "]"));
  }

  /**
   * Deregisters any push listener previously registered by this element.
   *
   * <p>When constructed with {@code pushed=true}, this element registers a listener with the
   * underlying {@link FProxyFetchInProgress} instance. This method removes that listener if the
   * fetch is still available. It is safe to call when {@code pushed=false}; in that case the
   * listener is {@code null} and no work is performed.
   */
  @Override
  public void dispose() {
    // Deregisters the FetchListener
    FProxyFetchInProgress progress =
        tracker.getFetchInProgress(new FProxyFetchCriteria(key, maxSize, fctx));
    if (progress != null) {
      progress.removeListener(fetchListener);
    }
  }

  /**
   * Returns the updater type string used by the update framework.
   *
   * <p>The type identifies the kind of updater this element participates in and is used for routing
   * update requests on the client side. The value is a constant defined in {@link
   * UpdaterConstants}.
   *
   * @return the updater type identifier for progress bar elements.
   */
  @Override
  public String getUpdaterType() {
    return UpdaterConstants.PROGRESSBAR_UPDATER;
  }

  /**
   * Returns a concise, diagnostic string representation of this element.
   *
   * <p>The returned value includes the fetch URI, {@code maxSize}, and the derived updater id. It
   * is intended for debugging and logs and is not a stable, parseable serialization format.
   *
   * @return a human-readable summary of this element's key configuration values.
   */
  @Override
  public String toString() {
    return "ProgressBarElement[key:"
        + key
        + ",maxSize:"
        + maxSize
        + ",updaterId:"
        + getUpdaterId(null)
        + "]";
  }
}
