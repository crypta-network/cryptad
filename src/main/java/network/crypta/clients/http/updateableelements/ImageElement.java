package network.crypta.clients.http.updateableelements;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import network.crypta.client.FetchException;
import network.crypta.client.filter.HTMLFilter.ParsedTag;
import network.crypta.clients.http.FProxyFetchCriteria;
import network.crypta.clients.http.FProxyFetchInProgress;
import network.crypta.clients.http.FProxyFetchInProgress.REFILTER_POLICY;
import network.crypta.clients.http.FProxyFetchResult;
import network.crypta.clients.http.FProxyFetchTracker;
import network.crypta.clients.http.FProxyFetchWaiter;
import network.crypta.clients.http.FProxyToadlet;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.ToadletContext;
import network.crypta.keys.FreenetURI;
import network.crypta.support.Base64;
import network.crypta.support.HTMLNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An updatable {@code <img>} element that can render fetch progress.
 *
 * <p>This element is used by the HTTP UI update system to represent an image whose bytes may still
 * be arriving. When JavaScript is enabled, it renders a placeholder {@code <img>} whose {@code src}
 * points at the internal {@code /imagecreator/} endpoint, which generates a progress image (either
 * an “initializing” banner or a percentage indicator). When JavaScript is disabled, it renders the
 * original image tag inside a {@code <noscript>} block.
 *
 * <p>When created in “pushed” mode, the instance registers a {@link NotifierFetchListener} with the
 * {@link FProxyFetchInProgress} for the requested URI and schedules an immediate job on the server
 * ticker to start/attach to the fetch. This means that the element can be updated asynchronously as
 * the fetch progresses, and it can react to {@link FetchException} redirects by switching to {@link
 * FetchException#newURI} when available.
 *
 * <p><b>Notable behaviors</b>
 *
 * <ul>
 *   <li>Shows the original {@code <img>} once the fetch completes successfully and data is present.
 *   <li>Falls back to the original {@code <img>} on failure (no “broken” placeholder is emitted).
 *   <li>Includes hidden inputs ({@code fetchedBlocks} / {@code requiredBlocks}) to allow clients to
 *       read progress values without parsing images.
 * </ul>
 *
 * <p><b>Thread-safety</b>: Instances are mutable and are not designed for concurrent access. They
 * are expected to be driven by the update/render lifecycle and the associated fetch notification
 * callbacks.
 */
public class ImageElement extends BaseUpdatableElement {
  private static final Logger LOG = LoggerFactory.getLogger(ImageElement.class);

  private static final String ATTR_WIDTH = "width";
  private static final String ATTR_HEIGHT = "height";
  private static final String TAG_INPUT = "input";
  private static final String ATTR_VALUE = "value";
  private static final String VALUE_HIDDEN = "hidden";

  /** Tracker from which fetch progress objects and results are obtained. */
  private final FProxyFetchTracker tracker;

  /**
   * The original (requested) URI for this image element.
   *
   * <p>This value is set at construction time and never changes. It is used as the stable identity
   * for the updater id (see {@link #getUpdaterId(String)}), even if the underlying fetch is later
   * redirected and the effective key (see {@link #getKey()}) changes to a different URI.
   */
  public final FreenetURI origKey;

  /** The URI of the download this progress bar shows */
  private FreenetURI key;

  /** The maxSize */
  private final long maxSize;

  /** The FetchListener that gets notified when the download progresses */
  private NotifierFetchListener fetchListener;

  private final ParsedTag originalImg;

  private final int randomNumber;

  private boolean wasError = false;

  /**
   * Creates a new {@link ImageElement} with no explicit width/height or accessible name.
   *
   * <p>This is a convenience overload that delegates to the full factory and uses {@code -1} for
   * width/height (meaning “unspecified”) and {@code null} for the name. The returned element
   * renders the original {@code <img>} when complete, and renders progress via {@code
   * /imagecreator/} while the fetch is still running (when JavaScript is enabled).
   *
   * @param tracker the fetch tracker used to start and observe the underlying fetch; must not be
   *     {@code null}.
   * @param key the image URI to fetch and to expose as the logical identity for updates; must not
   *     be {@code null}.
   * @param maxSize the maximum number of bytes allowed for the fetch; values {@code <= 0} rely on
   *     upstream validation and may fail fetch initialization.
   * @param ctx the toadlet context providing server/container access for push updates; must not be
   *     {@code null}.
   * @param pushed {@code true} to attach a push listener and schedule immediate fetch observation;
   *     {@code false} to render passively without registering listeners.
   * @return a new image element configured for the given URI and update mode.
   */
  public static ImageElement createImageElement(
      FProxyFetchTracker tracker,
      FreenetURI key,
      long maxSize,
      ToadletContext ctx,
      boolean pushed) {
    return createImageElement(
        tracker, key, maxSize, ctx, ImageElementAttributes.unspecified(), pushed);
  }

  /**
   * Creates a new {@link ImageElement} with optional size attributes and an optional accessible
   * name.
   *
   * <p>The factory constructs an {@code <img>} {@link ParsedTag} with {@code src} set to the given
   * URI string and, when provided, {@code width}/{@code height} attributes. If {@code name} is
   * non-{@code null}, it is used for both {@code alt} and {@code title} to improve accessibility
   * and discoverability.
   *
   * <p>While a fetch is in progress (and when JavaScript is enabled), the element swaps the {@code
   * src} to {@code /imagecreator/} so the browser displays a server-generated progress image. The
   * original tag is preserved and will be re-rendered once the fetch is finished.
   *
   * @param tracker the fetch tracker used to start and observe the underlying fetch; must not be
   *     {@code null}.
   * @param key the image URI to fetch and to expose as the logical identity for updates; must not
   *     be {@code null}.
   * @param maxSize the maximum number of bytes allowed for the fetch; values {@code <= 0} rely on
   *     upstream validation and may fail fetch initialization.
   * @param ctx the toadlet context providing server/container access for push updates; must not be
   *     {@code null}.
   * @param attributes optional size and accessible-name attributes; when {@code null}, the default
   *     of no size and no name is applied.
   * @param pushed {@code true} to attach a push listener and schedule immediate fetch observation;
   *     {@code false} to render passively without registering listeners.
   * @return a new image element configured with the requested attributes and update mode.
   */
  public static ImageElement createImageElement(
      FProxyFetchTracker tracker,
      FreenetURI key,
      long maxSize,
      ToadletContext ctx,
      ImageElementAttributes attributes,
      boolean pushed) {
    ImageElementAttributes resolvedAttributes =
        attributes != null ? attributes : ImageElementAttributes.unspecified();
    Map<String, String> attributesMap = new HashMap<>();
    attributesMap.put("src", key.toString());
    if (resolvedAttributes.width() != -1) {
      attributesMap.put(ATTR_WIDTH, String.valueOf(resolvedAttributes.width()));
    }
    if (resolvedAttributes.height() != -1) {
      attributesMap.put(ATTR_HEIGHT, String.valueOf(resolvedAttributes.height()));
    }
    if (resolvedAttributes.name() != null) {
      attributesMap.put("alt", resolvedAttributes.name());
      attributesMap.put("title", resolvedAttributes.name());
    }
    return new ImageElement(
        tracker, key, maxSize, ctx, new ParsedTag("img", attributesMap), pushed);
  }

  /**
   * Creates a new image element from an already-parsed {@code <img>} tag.
   *
   * <p>The element stores both the original URI ({@link #origKey}) and a mutable effective key used
   * to resolve and track the fetch. In pushed mode, it registers a {@link NotifierFetchListener}
   * and schedules an immediate ticker job to attach to the {@link FProxyFetchInProgress}. If a
   * {@link FetchException} indicates a redirect via {@link FetchException#newURI}, the effective
   * key is updated and the listener is re-attached to the new fetch.
   *
   * <p>This constructor does not perform any network I/O directly; it wires up the element and, in
   * pushed mode, arranges for fetch observation to begin asynchronously.
   *
   * @param tracker the fetch tracker used to start and observe the underlying fetch; must not be
   *     {@code null}.
   * @param key the initial URI to fetch; this also seeds {@link #origKey}; must not be {@code
   *     null}.
   * @param maxSize the maximum number of bytes allowed for the fetch; values {@code <= 0} rely on
   *     upstream validation and may fail fetch initialization.
   * @param ctx the toadlet context providing server/container access for push updates; must not be
   *     {@code null}.
   * @param originalImg parsed representation of the original {@code <img>} tag to re-render when
   *     complete or on error; must not be {@code null}.
   * @param pushed {@code true} to register for push updates; {@code false} to avoid listener
   *     registration and cancellation on disposal.
   */
  public ImageElement(
      FProxyFetchTracker tracker,
      FreenetURI key,
      long maxSize,
      ToadletContext ctx,
      ParsedTag originalImg,
      boolean pushed) {
    super("span", ctx);
    randomNumber = tracker.makeRandomElementID();
    long now = System.currentTimeMillis();
    if (LOG.isDebugEnabled()) {
      LOG.debug("ImageElement creating for uri:{}", key);
    }
    this.originalImg = originalImg;
    this.tracker = tracker;
    this.key = this.origKey = key;
    this.maxSize = maxSize;
    init(pushed);
    if (!pushed) return;
    // Creates and registers the FetchListener
    fetchListener =
        new NotifierFetchListener(
            ((SimpleToadletServer) ctx.getContainer()).getPushDataManager(), this);
    ((SimpleToadletServer) ctx.getContainer())
        .getTicker()
        .queueTimedJob(
            () -> {
              try {
                FProxyFetchWaiter waiter =
                    ImageElement.this.tracker.makeFetcher(
                        new FProxyFetchCriteria(
                            ImageElement.this.key, ImageElement.this.maxSize, null),
                        REFILTER_POLICY.RE_FILTER);
                ImageElement.this
                    .tracker
                    .getFetchInProgress(
                        new FProxyFetchCriteria(
                            ImageElement.this.key, ImageElement.this.maxSize, null))
                    .addListener(fetchListener);
                ImageElement.this
                    .tracker
                    .getFetchInProgress(
                        new FProxyFetchCriteria(
                            ImageElement.this.key, ImageElement.this.maxSize, null))
                    .close(waiter);
              } catch (FetchException fe) {
                if (fe.newURI != null) {
                  try {
                    ImageElement.this.key = fe.newURI;
                    FProxyFetchWaiter waiter =
                        ImageElement.this.tracker.makeFetcher(
                            new FProxyFetchCriteria(
                                ImageElement.this.key, ImageElement.this.maxSize, null),
                            REFILTER_POLICY.RE_FILTER);
                    ImageElement.this
                        .tracker
                        .getFetchInProgress(
                            new FProxyFetchCriteria(
                                ImageElement.this.key, ImageElement.this.maxSize, null))
                        .addListener(fetchListener);
                    ImageElement.this
                        .tracker
                        .getFetchInProgress(
                            new FProxyFetchCriteria(
                                ImageElement.this.key, ImageElement.this.maxSize, null))
                        .close(waiter);
                  } catch (FetchException _) {
                    wasError = true;
                  }
                }
              }
              fetchListener.onEvent();
            },
            0);

    if (LOG.isDebugEnabled()) {
      LOG.debug("ImageElement creating finished in:{} ms", System.currentTimeMillis() - now);
    }
  }

  /**
   * Releases resources associated with this element and requests cancellation of any in-progress
   * fetch.
   *
   * <p>If the element was created in pushed mode, it may have registered a {@link
   * NotifierFetchListener} with an {@link FProxyFetchInProgress}. This method removes that listener
   * (when present) and then requests an immediate cancel of the fetch. If the progress object
   * reports that it can be canceled, the tracker is kicked to ensure cancellation work is processed
   * promptly.
   *
   * <p>This method is intended to be called by the UI/update lifecycle when the element is no
   * longer needed. It is safe to call even when no fetch is in progress; in that case it is
   * effectively a no-op beyond debug logging.
   */
  @Override
  public void dispose() {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Disposing ImageElement");
    }
    FProxyFetchInProgress progress =
        tracker.getFetchInProgress(new FProxyFetchCriteria(key, maxSize, null));
    if (progress != null) {
      progress.removeListener(fetchListener);
      if (LOG.isDebugEnabled()) {
        LOG.debug("canCancel():{}", progress.canCancel());
      }
      progress.requestImmediateCancel();
      if (progress.canCancel()) {
        tracker.run();
      }
    }
  }

  /**
   * Returns the update system identifier for this element instance.
   *
   * <p>The identifier is derived from the original URI and a per-instance random number so that
   * multiple image elements can coexist even when they reference the same URI. The {@code
   * requestId} argument is accepted to satisfy the updater interface but is not used by this
   * implementation.
   *
   * @param requestId an optional request identifier provided by the update framework; ignored by
   *     this implementation and may be {@code null}.
   * @return an updater id string suitable for use in HTML/JS update payloads.
   */
  @Override
  public String getUpdaterId(String requestId) {
    return getId(origKey, randomNumber);
  }

  /**
   * Builds a stable update identifier for an image element instance.
   *
   * <p>The returned identifier is derived from the provided URI and a caller-supplied random
   * number. The random component allows multiple elements that refer to the same URI to coexist
   * without collisions in the update system. The final identifier is Base64-encoded, so it is safe
   * to embed into HTML attributes or JavaScript payloads.
   *
   * @param uri the logical image URI used as part of the identifier; must not be {@code null}.
   * @param randomNumber per-element random value used to avoid collisions; any {@code int} value is
   *     accepted.
   * @return a Base64-encoded string suitable for use as an updater element id.
   */
  public static String getId(FreenetURI uri, int randomNumber) {
    return Base64.encodeStandardUTF8(
        ("image[URI:" + uri.toString() + ",random:" + randomNumber + "]"));
  }

  @Override
  public String getUpdaterType() {
    return UpdaterConstants.IMAGE_ELEMENT_UPDATER;
  }

  /**
   * Renders the current state of this element into its child node list.
   *
   * <p>The render output always includes both a JavaScript-enabled span (used by the live updater)
   * and a {@code <noscript>} fallback that contains the original image tag. When {@code initial} is
   * {@code true}, the JS-enabled branch points to {@code /imagecreator/} with an “initializing”
   * message and a minimal progress payload ({@code fetchedBlocks=0}, {@code requiredBlocks=1}).
   *
   * <p>For non-initial updates, this method attempts to obtain a fast fetch result. If the fetch
   * has completed successfully, it re-renders the original image. If the fetch is still running, it
   * renders a progress image that encodes the percentage complete and emits hidden progress inputs.
   * Failures fall back to the original image tag.
   *
   * @param initial {@code true} when the element is first rendered and should show an initializing
   *     placeholder; {@code false} when rendering an incremental update.
   */
  @Override
  public void updateState(boolean initial) {
    logUpdateState();
    children.clear();
    HTMLNode whenJsEnabled = new HTMLNode("span", "class", "jsonly ImageElement");
    addChild(whenJsEnabled);
    // When js disabled
    addChild("noscript").addChild(makeHtmlNodeForParsedTag(originalImg));
    if (initial) {
      renderInitialState(whenJsEnabled);
      return;
    }
    renderUpdatedState(whenJsEnabled);
  }

  /**
   * Returns the {@link FProxyFetchTracker} used by this element.
   *
   * <p>Callers can use the tracker to inspect or interact with the underlying fetch progress
   * objects that back this element. The tracker reference is fixed for the lifetime of the element.
   *
   * @return the tracker used for fetch observation and result retrieval.
   */
  public FProxyFetchTracker getTracker() {
    return tracker;
  }

  /**
   * Returns the current effective URI used for fetch tracking.
   *
   * <p>This may differ from {@link #origKey} if the fetch was redirected and a {@link
   * FetchException} provided a {@link FetchException#newURI}. The value is mutable and reflects the
   * most recent key that the element is observing.
   *
   * @return the current effective URI for this element; never {@code null} after construction.
   */
  public FreenetURI getKey() {
    return key;
  }

  /**
   * Sets the effective URI used for fetch tracking.
   *
   * <p>This is primarily used to switch to a redirected URI when the fetch layer indicates a new
   * location. Changing the key affects subsequent fetch observation and update identifiers derived
   * from {@link #origKey} remain unchanged.
   *
   * @param key the new effective URI to observe; must not be {@code null}.
   */
  public void setKey(FreenetURI key) {
    this.key = key;
  }

  /**
   * Returns the maximum allowed size for the underlying fetch.
   *
   * <p>This value is forwarded to {@link FProxyFetchTracker} when creating or looking up fetch
   * state and can influence whether a fetch is started, reused, or rejected. The unit is bytes.
   *
   * @return the maximum fetch size in bytes, as configured at construction time.
   */
  public long getMaxSize() {
    return maxSize;
  }

  private void logUpdateState() {
    if (!LOG.isDebugEnabled()) {
      return;
    }
    String originalSuffix = "";
    if (origKey == key) {
      originalSuffix = " originally " + origKey;
    }
    LOG.debug("Updating ImageElement for url:{}{}", key, originalSuffix);
  }

  private void renderInitialState(HTMLNode whenJsEnabled) {
    if (wasError) {
      whenJsEnabled.addChild(makeHtmlNodeForParsedTag(originalImg));
      return;
    }
    Map<String, String> attr = originalImg.getAttributesAsMap();
    String sizePart = buildSizeQueryPart(attr);
    attr.put(
        "src", "/imagecreator/?text=+" + FProxyToadlet.l10n("imageinitializing") + "+" + sizePart);
    whenJsEnabled.addChild(makeHtmlNodeForParsedTag(new ParsedTag(originalImg, attr)));
    addHiddenProgressInputs(whenJsEnabled, 0, 1);
  }

  private void renderUpdatedState(HTMLNode whenJsEnabled) {
    FetchResources fetchResources = fetchResources(whenJsEnabled);
    try {
      renderFetchResult(whenJsEnabled, fetchResources.result);
    } finally {
      closeFetchResources(fetchResources);
    }
  }

  private FetchResources fetchResources(HTMLNode whenJsEnabled) {
    FetchResources resources = new FetchResources();
    try {
      resources.waiter =
          tracker.makeFetcher(
              new FProxyFetchCriteria(key, maxSize, null), REFILTER_POLICY.RE_FILTER);
      resources.result = resources.waiter.getResultFast();
    } catch (FetchException _) {
      whenJsEnabled.addChild("div", "error");
    }
    return resources;
  }

  private void closeFetchResources(FetchResources fetchResources) {
    if (fetchResources == null) {
      return;
    }
    FProxyFetchInProgress progress =
        tracker.getFetchInProgress(new FProxyFetchCriteria(key, maxSize, null));
    if (progress == null) {
      return;
    }
    if (fetchResources.waiter != null) {
      progress.close(fetchResources.waiter);
    }
    if (fetchResources.result != null) {
      progress.close(fetchResources.result);
    }
  }

  private void renderFetchResult(HTMLNode whenJsEnabled, FProxyFetchResult fetchResult) {
    if (fetchResult == null) {
      whenJsEnabled.addChild("div", "No fetcher found");
      return;
    }

    if (fetchResult.isFinished() && fetchResult.hasData()) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("ImageElement is completed");
      }
      whenJsEnabled.addChild(makeHtmlNodeForParsedTag(originalImg));
      return;
    }

    if (fetchResult.failed != null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("ImageElement is errorous");
      }
      whenJsEnabled.addChild(makeHtmlNodeForParsedTag(originalImg));
      return;
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("ImageElement is still in progress");
    }
    renderFetchProgress(whenJsEnabled, fetchResult);
  }

  private void renderFetchProgress(HTMLNode whenJsEnabled, FProxyFetchResult fetchResult) {
    int total = fetchResult.requiredBlocks;
    int fetchedPercent = (int) (fetchResult.fetchedBlocks / (double) total * 100);
    Map<String, String> attr = originalImg.getAttributesAsMap();
    String sizePart = buildSizeQueryPart(attr);
    attr.put("src", "/imagecreator/?text=" + fetchedPercent + "%25" + sizePart);
    whenJsEnabled.addChild(makeHtmlNodeForParsedTag(new ParsedTag(originalImg, attr)));
    addHiddenProgressInputs(whenJsEnabled, fetchResult.fetchedBlocks, fetchResult.requiredBlocks);
  }

  private void addHiddenProgressInputs(
      HTMLNode whenJsEnabled, long fetchedBlocks, long requiredBlocks) {
    whenJsEnabled.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {VALUE_HIDDEN, "fetchedBlocks", String.valueOf(fetchedBlocks)});
    whenJsEnabled.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {VALUE_HIDDEN, "requiredBlocks", String.valueOf(requiredBlocks)});
  }

  private static String buildSizeQueryPart(Map<String, String> attributes) {
    if (!attributes.containsKey(ATTR_WIDTH) || !attributes.containsKey(ATTR_HEIGHT)) {
      return "";
    }
    return "&width=" + attributes.get(ATTR_WIDTH) + "&height=" + attributes.get(ATTR_HEIGHT);
  }

  private static final class FetchResources {
    private FProxyFetchResult result;
    private FProxyFetchWaiter waiter;
  }

  private HTMLNode makeHtmlNodeForParsedTag(ParsedTag pt) {
    List<String> attributeNames = new ArrayList<>();
    List<String> attributeValues = new ArrayList<>();
    for (Entry<String, String> att : pt.getAttributesAsMap().entrySet()) {
      attributeNames.add(att.getKey());
      attributeValues.add(att.getValue());
    }
    return new HTMLNode(
        pt.element,
        attributeNames.toArray(new String[] {}),
        attributeValues.toArray(new String[] {}));
  }

  /**
   * Returns a concise, diagnostic string for logging and debugging.
   *
   * <p>The string includes the current effective key, the configured {@link #getMaxSize()} limit,
   * the parsed original image tag, and the computed updater id. It is intended for human inspection
   * and is not a stable serialization format.
   *
   * @return a human-readable description of this element instance.
   */
  @Override
  public String toString() {
    return "ImageElement[key:"
        + key
        + ",maxSize:"
        + maxSize
        + ",originalImg:"
        + originalImg
        + ",updaterId:"
        + getUpdaterId(null)
        + "]";
  }
}
