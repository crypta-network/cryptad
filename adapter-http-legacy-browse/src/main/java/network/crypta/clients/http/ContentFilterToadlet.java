package network.crypta.clients.http;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.client.filter.ContentFilter.FilterStatus;
import network.crypta.client.filter.ContentFilter;
import network.crypta.client.filter.ContentFilterCallbacks;
import network.crypta.client.filter.ContentFilterRequest;
import network.crypta.client.filter.FilterOperation;
import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.client.filter.UnsafeContentTypeException;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.api.HTTPUploadedFile;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.LegacyFileSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Exposes a small HTTP UI that lets advanced users run the content filter against uploaded or local
 * files and inspect the sanitized output.
 *
 * <p>This toadlet acts as the bridge between browser clients and the {@link ContentFilter}. It
 * renders a simple form, validates MIME type and filter intent, and streams the submitted data into
 * the node's filtering pipeline. When configured, it also supports browsing the local filesystem so
 * operators can run ad hoc checks without leaving the web console. Requests are only served when
 * advanced mode and full access are enabled, preventing exposure on public gateways.
 *
 * <p>Typical lifecycle: callers mount the toadlet at {@link #CONTENT_FILTER_PATH}, the browser
 * issues GET to render the form, and POST to submit either an uploaded file or a selection from the
 * local browser. The toadlet streams data into the filter, chooses whether to display or save the
 * result, and writes structured HTML responses with localized messages. The class is not
 * thread-safe by itself but relies on the surrounding server framework for concurrency control.
 *
 * <ul>
 *   <li>Responsibilities: render UI, validate parameters, feed data into the filter, report
 *       outcomes.
 *   <li>Notable behaviors: respects the configurable endpoint path, enforces advanced-mode access,
 *       and cleans up upload parts to conserve memory.
 * </ul>
 *
 * @see LocalFileFilterToadlet
 * @see ContentFilter
 */
public class ContentFilterToadlet extends ContentToadlet implements LinkEnabledCallback {
  private static final Logger LOG = LoggerFactory.getLogger(ContentFilterToadlet.class);

  /**
   * Public route constant retained for compatibility with existing browse code and tests.
   *
   * <p>The canonical value now lives in {@link LegacyContentFilterSupport}, but this alias keeps
   * the historical {@code ContentFilterToadlet.CONTENT_FILTER_PATH} surface intact while admin code
   * switches to the shared-shell helper instead of importing this browse-owned type.
   */
  public static final String CONTENT_FILTER_PATH = LegacyContentFilterSupport.CONTENT_FILTER_PATH;

  private static final String MIME_TYPE_PART = "mime-type";
  private static final String FILTER_OPERATION_PART = "filter-operation";
  private static final String RESULT_HANDLING_PART = "result-handling";
  private static final String INPUT_ELEMENT = "input";
  private static final String VALUE_ATTR = "value";
  private static final String FILENAME_PART = "filename";

  private static final String FILTER_URI_PROPERTY =
      "network.crypta.clients.http.ContentFilterToadlet.loopbackUri";
  private static final URI DEFAULT_FILTER_URI = URI.create("http://127.0.0.1:8888/");

  /**
   * Controls what the node does with filtered output once processing completes.
   *
   * <p>The option is selected by the user via the filter UI and is persisted during round-trips
   * between the main form and the local file browser.
   */
  public enum ResultHandling {
    /** Render the filtered content directly back to the browser in the HTTP response. */
    DISPLAY,
    /** Save the filtered content to the disk using the node's standard download location. */
    SAVE
  }

  /**
   * Creates a content filter toadlet bound to the given HTTP client abstraction.
   *
   * @param client HTTP client utility used for link-aware rendering and helper operations; must not
   *     be {@code null}.
   */
  public ContentFilterToadlet(BrowseContentClient client) {
    super(client);
  }

  @Override
  public String path() {
    return CONTENT_FILTER_PATH;
  }

  /**
   * Indicates whether the toadlet should serve the current request context.
   *
   * <p>Access is granted only when advanced mode is enabled and the caller has full access (or the
   * node is not acting as a public gateway). This gate keeps the filter UI from being reachable in
   * restricted environments.
   *
   * @param ctx request context containing authentication and mode flags; may be {@code null} to
   *     signify no access.
   * @return {@code true} when advanced mode and full access allow serving the request; otherwise
   *     {@code false}.
   */
  @Override
  public boolean isEnabled(ToadletContext ctx) {
    if (ctx == null) return false;
    boolean fullAccess = !container.publicGatewayMode() || ctx.isAllowedFullAccess();
    return ctx.isAdvancedModeEnabled() && fullAccess;
  }

  /**
   * Renders the content filter form for GET requests and returns it as HTML.
   *
   * <p>The method enforces full-access requirements, injects any pending alerts, and builds the
   * filter form with defaults. It never mutates server state and is safe to call repeatedly. When
   * access is denied, it emits an unauthorized response instead of redirecting.
   *
   * @param uri target URI of the request, used for context binding; must not be {@code null}.
   * @param request parsed HTTP request carrying query parameters; must not be {@code null}.
   * @param ctx toadlet context used for authorization, localization, and response writing; must not
   *     be {@code null}.
   * @throws ToadletContextClosedException if the client connection closes before, the response is
   *     fully written.
   * @throws IOException if the response cannot be streamed to the caller.
   * @throws RedirectException if a redirect is required by the underlying framework while building
   *     the page.
   */
  @Override
  public void handleMethodGET(URI uri, final HTTPRequest request, final ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    if (container.publicGatewayMode() && !ctx.isAllowedFullAccess()) {
      sendUnauthorizedPage(ctx);
      return;
    }

    PageMaker pageMaker = ctx.getPageMaker();

    PageNode page = pageMaker.getPageNode(l10n("pageTitle"), ctx);
    HTMLNode contentNode = page.getContentNode();

    contentNode.addChild(ctx.getAlertManager().createSummary());

    contentNode.addChild(createContent(pageMaker, ctx));

    writeHTMLReply(ctx, ReplyHeaders.of(200, "OK", "text/html; charset=utf-8"), page.generate());
  }

  /**
   * Processes POST submissions for both direct uploads and local file selections.
   *
   * <p>The method branches on form parts: launching the local browser, filtering a locally browsed
   * file, or handling an uploaded payload. It validates required fields, preserves stateful
   * parameters between steps, and frees request parts in a {@code finally} block to avoid resource
   * leaks. Access control mirrors {@link #handleMethodGET(URI, HTTPRequest, ToadletContext)}.
   *
   * @param uri the target URI of the request, retained for compatibility with the Toadlet contract,
   *     may be unused by some branches.
   * @param request multipart POST request containing user input and optional file data; must not be
   *     {@code null} and is released after processing.
   * @param ctx context for permission checks, localization, and response handling; must not be
   *     {@code null}.
   * @throws ToadletContextClosedException if the client disconnects before the response completes.
   * @throws IOException if streaming responses or temporary file operations fail.
   * @throws RedirectException if a redirect is required by the framework during processing.
   */
  public void handleMethodPOST(URI uri, final HTTPRequest request, final ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    if (container.publicGatewayMode() && !ctx.isAllowedFullAccess()) {
      sendUnauthorizedPage(ctx);
      return;
    }
    try {
      // Browse... button on the filter page
      if (request.isPartSet("filter-local")) {
        try {
          FilterOperation filterOperation = getFilterOperation(request);
          ResultHandling resultHandling = getResultHandling(request);
          String mimeType = request.getPartAsStringFailsafe(MIME_TYPE_PART, 100);
          String location =
              LocalFileFilterToadlet.BROWSE_PATH
                  + '?'
                  + FILTER_OPERATION_PART
                  + '='
                  + filterOperation
                  + '&'
                  + RESULT_HANDLING_PART
                  + '='
                  + resultHandling
                  + '&'
                  + MIME_TYPE_PART
                  + '='
                  + mimeType;
          MultiValueTable<String, String> responseHeaders =
              MultiValueTable.from("Location", location);
          ctx.sendReplyHeaders(302, "Found", responseHeaders, null, 0);
        } catch (BadRequestException e) {
          handleInvalidPart(e.getInvalidRequestPart(), ctx);
        }
        // Filter button on local file browser
      } else if (request.isPartSet(LocalFileBrowserToadlet.SELECT_FILE)) {
        handleFilterRequest(request, ctx, true);
        // Filter File button on the filter page
      } else if (request.isPartSet("filter-upload")) {
        handleFilterRequest(request, ctx, false);
      } else {
        handleMethodGET(uri, new HTTPRequestImpl(uri, "GET"), ctx);
      }
    } finally {
      request.freeParts();
    }
  }

  private void handleInvalidPart(String invalidPart, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    switch (invalidPart) {
      case FILTER_OPERATION_PART ->
          writeBadRequestError(
              l10n("errorMustSpecifyFilterOperationTitle"),
              l10n("errorMustSpecifyFilterOperation"),
              ctx);
      case RESULT_HANDLING_PART ->
          writeBadRequestError(
              l10n("errorMustSpecifyResultHandlingTitle"),
              l10n("errorMustSpecifyResultHandling"),
              ctx);
      case FILENAME_PART ->
          writeBadRequestError(l10n("errorNoFileSelectedTitle"), l10n("errorNoFileSelected"), ctx);
      default -> writeBadRequestError(l10n("errorBadRequestTitle"), l10n("errorBadRequest"), ctx);
    }
  }

  private HTMLNode createContent(PageMaker pageMaker, ToadletContext ctx) {
    InfoboxNode infobox = pageMaker.getInfobox(l10n("filterFile"), "filter-file", true);
    HTMLNode filterBox = infobox.getOuterNode();
    HTMLNode filterContent = infobox.getContentNode();

    HTMLNode filterForm = ctx.addFormChild(filterContent, CONTENT_FILTER_PATH, "filterForm");

    // apply read filter, write filter, or both
    // ContentFilter currently only supports read filtering; write selection will be added once
    // the filter exposes write-side operations.
    filterForm.addChild(
        INPUT_ELEMENT,
        new String[] {"type", "name", VALUE_ATTR},
        new String[] {"hidden", FILTER_OPERATION_PART, FilterOperation.BOTH.toString()});

    // display in browser or save to disk
    filterForm.addChild(
        INPUT_ELEMENT,
        new String[] {"type", "name", VALUE_ATTR, "id"},
        new String[] {
          "radio",
          RESULT_HANDLING_PART,
          ResultHandling.DISPLAY.toString(),
          "result-handling-display"
        });
    filterForm.addChild(
        "label",
        new String[] {"for"},
        new String[] {"result-handling-display"},
        l10n("displayResultLabel"));
    filterForm.addChild("br");
    filterForm.addChild(
        INPUT_ELEMENT,
        new String[] {"type", "name", VALUE_ATTR, "id"},
        new String[] {
          "radio", RESULT_HANDLING_PART, ResultHandling.SAVE.toString(), "result-handling-save"
        });
    filterForm.addChild(
        "label",
        new String[] {"for"},
        new String[] {"result-handling-save"},
        l10n("saveResultLabel"));
    filterForm.addChild("br");
    filterForm.addChild("br");

    // mime type
    filterForm.addChild("#", l10n("mimeTypeLabel") + ": ");
    filterForm.addChild(
        INPUT_ELEMENT,
        new String[] {"type", "name", VALUE_ATTR},
        new String[] {"text", MIME_TYPE_PART, ""});
    filterForm.addChild("br");
    filterForm.addChild("#", l10n("mimeTypeText"));
    filterForm.addChild("br");
    filterForm.addChild("br");

    // file selection
    if (ctx.isAllowedFullAccess()) {
      filterForm.addChild("#", l10n("filterFileBrowseLabel") + ": ");
      filterForm.addChild(
          INPUT_ELEMENT,
          new String[] {"type", "name", VALUE_ATTR},
          new String[] {"submit", "filter-local", l10n("filterFileBrowseButton") + "..."});
      filterForm.addChild("br");
    }
    filterForm.addChild("#", l10n("filterFileUploadLabel") + ": ");
    filterForm.addChild(
        INPUT_ELEMENT,
        new String[] {"type", "name", VALUE_ATTR},
        new String[] {"file", FILENAME_PART, ""});
    filterForm.addChild("#", " \u00a0 ");
    filterForm.addChild(
        INPUT_ELEMENT,
        new String[] {"type", "name", VALUE_ATTR},
        new String[] {"submit", "filter-upload", l10n("filterFileFilterLabel")});
    filterForm.addChild("#", " \u00a0 ");

    return filterBox;
  }

  private void writeBadRequestError(String header, String message, ToadletContext context)
      throws ToadletContextClosedException, IOException {
    PageMaker pageMaker = context.getPageMaker();
    PageNode page = pageMaker.getPageNode(header, context);
    HTMLNode contentNode = page.getContentNode();
    if (context.isAllowedFullAccess()) {
      contentNode.addChild(context.getAlertManager().createSummary());
    }
    HTMLNode infoboxContent =
        pageMaker.getInfobox("infobox-error", header, contentNode, "filter-error", false);
    infoboxContent.addChild("#", message);
    NodeL10n.getBase()
        .addL10nSubstitution(
            infoboxContent.addChild("div"),
            "ContentFilterToadlet.tryAgainFilterFilePage",
            new String[] {"link"},
            new HTMLNode[] {HTMLNode.link(ContentFilterToadlet.CONTENT_FILTER_PATH)});
    writeHTMLReply(context, 400, "Bad request", page.generate());
  }

  /** Handle a request to filter a file. */
  private void handleFilterRequest(HTTPRequest request, ToadletContext ctx, boolean localFile)
      throws ToadletContextClosedException, IOException {
    try {
      FilterOperation filterOperation = getFilterOperation(request);
      ResultHandling resultHandling = getResultHandling(request);
      String mimeType = request.getPartAsStringFailsafe(MIME_TYPE_PART, 100);
      if (localFile) {
        handleLocalFilterRequest(request, ctx, filterOperation, resultHandling, mimeType);
      } else {
        handleUploadedFilterRequest(request, ctx, filterOperation, resultHandling, mimeType);
      }
    } catch (BadRequestException e) {
      handleInvalidPart(e.getInvalidRequestPart(), ctx);
    }
  }

  private void handleLocalFilterRequest(
      HTTPRequest request,
      ToadletContext ctx,
      FilterOperation filterOperation,
      ResultHandling resultHandling,
      String mimeType)
      throws ToadletContextClosedException, IOException, BadRequestException {
    String filename =
        request.getPartAsStringFailsafe(FILENAME_PART, QueueToadlet.MAX_FILENAME_LENGTH);
    String resolvedMimeType =
        mimeType.isEmpty() ? DefaultMIMETypes.guessMIMEType(filename, false) : mimeType;
    if (filename.isEmpty()) {
      throw new BadRequestException(FILENAME_PART);
    }
    File file = new File(filename);
    try (Bucket bucket = new FileBucket(file, true, false, false, false)) {
      processFilter(bucket, filename, resolvedMimeType, filterOperation, resultHandling, ctx);
    } catch (FileNotFoundException _) {
      writeBadRequestError(
          l10n("errorNoFileOrCannotReadTitle"), cannotReadFileMessage(filename), ctx);
    }
  }

  private void handleUploadedFilterRequest(
      HTTPRequest request,
      ToadletContext ctx,
      FilterOperation filterOperation,
      ResultHandling resultHandling,
      String mimeType)
      throws ToadletContextClosedException, IOException, BadRequestException {
    HTTPUploadedFile file = request.getUploadedFile(FILENAME_PART);
    if (file == null) {
      throw new BadRequestException(FILENAME_PART);
    }
    String filename = file.getFilename();
    String resolvedMimeType = mimeType.isEmpty() ? file.getContentType() : mimeType;
    if (filename.isEmpty()) {
      throw new BadRequestException(FILENAME_PART);
    }
    try (Bucket bucket = file.getData()) {
      processFilter(bucket, filename, resolvedMimeType, filterOperation, resultHandling, ctx);
    } catch (FileNotFoundException _) {
      writeBadRequestError(
          l10n("errorNoFileOrCannotReadTitle"), cannotReadFileMessage(filename), ctx);
    }
  }

  private FilterOperation getFilterOperation(HTTPRequest request) throws BadRequestException {
    String s = request.getPartAsStringFailsafe(FILTER_OPERATION_PART, 100);
    try {
      return FilterOperation.valueOf(s);
    } catch (IllegalArgumentException e) {
      throw new BadRequestException(FILTER_OPERATION_PART, e);
    }
  }

  private ResultHandling getResultHandling(HTTPRequest request) throws BadRequestException {
    String s = request.getPartAsStringFailsafe(RESULT_HANDLING_PART, 100);
    try {
      return ResultHandling.valueOf(s);
    } catch (IllegalArgumentException e) {
      throw new BadRequestException(RESULT_HANDLING_PART, e);
    }
  }

  private void processFilter(
      Bucket bucket,
      String filename,
      String mimeType,
      FilterOperation filterOperation,
      ResultHandling resultHandling,
      ToadletContext ctx)
      throws ToadletContextClosedException, IOException, BadRequestException {
    String resultFilename = makeResultFilename(filename, mimeType);
    handleFilter(bucket, mimeType, filterOperation, resultHandling, resultFilename, ctx);
  }

  private String makeResultFilename(String originalFilename, String mimeType) {
    String filteredFilename;
    int p = originalFilename.indexOf('.', 1);
    if (p > 0) {
      filteredFilename =
          originalFilename.substring(0, p) + ".filtered" + originalFilename.substring(p);
    } else {
      filteredFilename = originalFilename + ".filtered";
    }
    filteredFilename =
        DefaultMIMETypes.forceExtension(
            LegacyFileSupport.sanitizeFileNameWithExtras(filteredFilename, ""), mimeType);
    return filteredFilename;
  }

  private void handleFilter(
      Bucket data,
      String mimeType,
      FilterOperation operation,
      ResultHandling resultHandling,
      String resultFilename,
      ToadletContext ctx)
      throws ToadletContextClosedException, IOException, BadRequestException {
    Bucket resultBucket = ctx.getBucketFactory().makeBucket(-1);
    String resultMimeType = null;
    boolean unsafe = false;
    try {
      FilterStatus status = applyFilter(data, resultBucket, mimeType, operation);
      resultMimeType = status.mimeType;
    } catch (UnsafeContentTypeException _) {
      unsafe = true;
    }

    if (unsafe) {
      sendErrorPage(ctx, 200, l10n("errorUnsafeContentTitle"), l10n("errorUnsafeContent"));
    } else {
      if (resultHandling == null) {
        throw new BadRequestException(RESULT_HANDLING_PART);
      }
      switch (resultHandling) {
        case DISPLAY -> {
          ctx.sendReplyHeaders(200, "OK", null, resultMimeType, resultBucket.size());
          ctx.writeData(resultBucket);
        }
        case SAVE -> {
          MultiValueTable<String, String> headers = new MultiValueTable<>();
          headers.put("Content-Disposition", "attachment; filename=\"" + resultFilename + '"');
          headers.put("Cache-Control", "private");
          headers.put("Content-Transfer-Encoding", "binary");
          ctx.sendReplyHeaders(
              200, "OK", headers, "application/force-download", resultBucket.size());
          ctx.writeData(resultBucket);
        }
        default -> throw new BadRequestException(RESULT_HANDLING_PART);
      }
    }
  }

  private FilterStatus applyFilter(
      Bucket input, Bucket output, String mimeType, FilterOperation operation) throws IOException {
    try (InputStream inputStream = input.getInputStream();
        OutputStream outputStream = output.getOutputStream()) {
      return applyFilter(inputStream, outputStream, mimeType, operation);
    }
  }

  private FilterStatus applyFilter(
      InputStream input, OutputStream output, String mimeType, FilterOperation operation)
      throws IOException {
    validateOperation(operation);
    URI fakeUri = resolveFilterUri();
    ContentFilterRequest request =
        new ContentFilterRequest(input, output, mimeType, null, null, null);
    ContentFilterCallbacks callbacks =
        new ContentFilterCallbacks(fakeUri, null, null, getLinkFilterExceptionProvider());
    return ContentFilter.filter(request, callbacks);
  }

  private LinkFilterExceptionProvider getLinkFilterExceptionProvider() {
    if (container == null) {
      throw new IllegalStateException("ContentFilterToadlet requires a registered container");
    }
    if (container instanceof LinkFilterExceptionProvider provider) {
      return provider;
    }
    throw new IllegalStateException(
        "ContentFilterToadlet container must implement LinkFilterExceptionProvider");
  }

  private void validateOperation(FilterOperation operation) {
    Objects.requireNonNull(operation, "operation");
  }

  private URI resolveFilterUri() {
    String configuredUri = System.getProperty(FILTER_URI_PROPERTY);
    if (configuredUri == null || configuredUri.isBlank()) {
      return DEFAULT_FILTER_URI;
    }
    try {
      return new URI(configuredUri);
    } catch (URISyntaxException e) {
      LOG.warn(
          "Invalid value for {}: {}. Falling back to {}",
          FILTER_URI_PROPERTY,
          configuredUri,
          DEFAULT_FILTER_URI,
          e);
      return DEFAULT_FILTER_URI;
    }
  }

  static String l10n(String key) {
    return LegacyContentFilterSupport.l10n(key);
  }

  private String cannotReadFileMessage(String filename) {
    return NodeL10n.getBase()
        .getString("ContentFilterToadlet.errorNoFileOrCannotRead", "file", filename);
  }
}
