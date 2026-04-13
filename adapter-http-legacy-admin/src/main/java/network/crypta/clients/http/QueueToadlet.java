package network.crypta.clients.http;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.runtime.spi.DarknetConnectionPeerSnapshot;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.DarknetMessagingPort;
import network.crypta.runtime.spi.DarknetPeerRequiredException;
import network.crypta.runtime.spi.QueueBrowserUploadInsertRequest;
import network.crypta.runtime.spi.QueueDownloadPort;
import network.crypta.runtime.spi.QueueDownloadRejectedException;
import network.crypta.runtime.spi.QueueDownloadRequest;
import network.crypta.runtime.spi.QueueInsertFailureReason;
import network.crypta.runtime.spi.QueueInsertOptions;
import network.crypta.runtime.spi.QueueInsertOutcome;
import network.crypta.runtime.spi.QueueInsertPort;
import network.crypta.runtime.spi.QueueInsertRejectedException;
import network.crypta.runtime.spi.QueueLocalDirectoryInsertRequest;
import network.crypta.runtime.spi.QueueLocalFileInsertRequest;
import network.crypta.runtime.spi.QueueMutationPort;
import network.crypta.runtime.spi.QueuePagePort;
import network.crypta.runtime.spi.QueuePageRequest;
import network.crypta.runtime.spi.QueuePageSnapshot;
import network.crypta.runtime.spi.QueuePersistenceStatusSnapshot;
import network.crypta.runtime.spi.QueueSupportPort;
import network.crypta.runtime.spi.QueueUploadedFile;
import network.crypta.runtime.spi.RequestQueueUnavailableException;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.runtime.spi.UnknownPeerException;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.api.HTTPUploadedFile;
import network.crypta.support.io.FileUtil;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Presents and mutates the FProxy request queues for both downloads and uploads.
 *
 * <p>This toadlet serves queue HTML pages and processes form submissions for starting, stopping,
 * deleting, or restarting requests. Live queue reads, mutations, creation paths, support checks,
 * and completion-tracker startup are delegated to runtime ports, while the HTTP layer retains only
 * request parsing, response rendering, and request-context-only placeholders such as alert
 * summaries and form passwords. Instances are bound either to the download or upload queue and
 * reuse shared rendering helpers that build tables, progress cells, and bulk action forms.
 *
 * <p>The class keeps only a lightweight HTTP-facing state: the selected queue side, the optional
 * file-insert wizard link, and the runtime-port bundle used by request handlers. The HTTP server
 * invokes all request-handling entry points on the thread that processes the incoming request, so
 * the toadlet avoids heavyweight daemon work directly and hands that off through the runtime SPI.
 *
 * <ul>
 *   <li>Renders queue pages with sortable columns and per-item actions.
 *   <li>Enforces public-gateway restrictions before mutating queue state.
 *   <li>Ensures queue completion tracking has been started for the selected side.
 *   <li>Keeps queue-specific HTTP parsing and response rendering inside the adapter layer.
 * </ul>
 *
 * @see FProxyRegistrar
 */
public final class QueueToadlet extends Toadlet implements LinkEnabledCallback {
  private static final Logger LOG = LoggerFactory.getLogger(QueueToadlet.class);

  private static final int MAX_IDENTIFIER_LENGTH = 1024 * 1024;
  static final int MAX_FILENAME_LENGTH = 1024 * 1024;
  private static final int MAX_TYPE_LENGTH = 1024;
  static final int MAX_KEY_LENGTH = 1024 * 1024;
  private static final String INPUT_TYPE_CHECKBOX = "checkbox";
  private static final String INPUT_TYPE_SUBMIT = "submit";
  private static final String REMOVE_FINISHED_UPLOADS_REQUEST = "remove_finished_uploads_request";
  private static final String REMOVE_FINISHED_DOWNLOADS_REQUEST =
      "remove_finished_downloads_request";
  private static final String RESTART_REQUEST = "restart_request";
  private static final String DISABLE_FILTER_DATA = "disableFilterData";
  private static final String PANIC = "panic";
  private static final String CONFIRM_PANIC = "confirmpanic";
  private static final String FILTER_DATA = "filterData";
  private static final String RETURN_TYPE_DIRECT = "direct";
  private static final String BULK_DOWNLOADS = "bulkDownloads";
  private static final String TARGET = "target";
  private static final String DOWNLOAD_FILES = "downloadFiles";
  private static final String GROUPED_DOWNLOADS = "grouped-downloads";
  private static final String FILENAME = "filename";
  private static final String FRED_SUFFIX = "-fred-";
  private static final String ERROR_ACCESS_DENIED = "errorAccessDenied";
  private static final String ERROR_ACCESS_DENIED_FILE_KEY = "errorAccessDeniedFile";
  private static final String ERROR_NO_FILE_OR_CANNOT_READ = "errorNoFileOrCannotRead";
  private static final String TOO_MANY_FILES_IN_ONE_FOLDER = "tooManyFilesInOneFolder";
  private static final String COMPRESS_LABEL = ", compress=";
  private static final String CMODE_LABEL = ", cmode=";
  private static final String OVERRIDE_SPLITFILE_KEY_LABEL = ", overrideSplitfileKey=";

  private final QueuePagePort queuePagePort;
  private final TransferAccessPort transferAccessPort;
  private final QueueDownloadPort queueDownloadPort;
  private final QueueInsertPort queueInsertPort;
  private final QueueMutationPort queueMutationPort;
  private final QueueSupportPort queueSupportPort;
  private final DarknetConnectionsPort darknetConnectionsPort;
  private final DarknetMessagingPort darknetMessagingPort;
  private final InsertCompatibilityModes insertCompatibilityModes;
  private FileInsertWizardToadlet fiw;
  private final QueuePostHandler postHandler;

  // Legacy threshold callback removed.

  void setFIW(FileInsertWizardToadlet fiw) {
    this.fiw = fiw;
  }

  private final boolean uploads;

  private static final String KEY_LIST_LOCATION = "listKeys.txt";
  private static final String ALERT_SUMMARY_PLACEHOLDER = "<!--CRYPTA_ALERT_SUMMARY-->";
  private static final String FORM_PASSWORD_PLACEHOLDER = "<!--CRYPTA_QUEUE_FORM_PASSWORD-->";
  private static final String PANIC_BOX_PLACEHOLDER = "<!--CRYPTA_QUEUE_PANIC_BOX-->";
  private static final String ERROR_INVALID_URI = "errorInvalidURI";
  private static final String ERROR_INVALID_URI_TO_U = "errorInvalidURIToU";
  private static final String ERROR_INVALID_URI_TO_D = "errorInvalidURIToD";
  private static final String IDENTIFIER_PREFIX = "identifier-";
  private static final String FILENAME_PREFIX = "filename-";
  private static final String KEY_PREFIX = "key-";
  private static final String REMOVE_REQUEST = "remove_request";
  private static final String DELETE_REQUEST = "delete_request";
  private static final String COMPRESS_FIELD = "compress";
  private static final String COMPATIBILITY_MODE_FIELD = "compatibilityMode";
  private static final String OVERRIDE_SPLITFILE_KEY_FIELD = "overrideSplitfileKey";
  private static final String TAG_INPUT = "input";
  private static final String ATTR_TYPE = "type";
  private static final String ATTR_NAME = "name";
  private static final String ATTR_VALUE = "value";
  private static final String ATTR_CHECKED = "checked";
  private static final String ATTR_CLASS = "class";
  private static final String TAG_LABEL = "label";
  private static final String TAG_TABLE = "table";
  private static final String INPUT_TYPE_HIDDEN = "hidden";
  private static final String INFOBOX_INFORMATION = "infobox-information";
  private static final String INFOBOX_ERROR = "infobox-error";
  private static final String PRIORITY = "priority";
  private static final String SORT_BY = "sortBy";
  private static final String QUEUE_TOADLET_PREFIX = "QueueToadlet.";

  /**
   * Creates a queue toadlet bound to either the upload or download side of the node.
   *
   * <p>The instance immediately ensures daemon-side completion tracking is active for the selected
   * queue side and retains the detached runtime ports needed by the legacy HTTP handlers.
   * Construction performs no heavyweight queue traversal in the HTTP layer, so it is safe to create
   * during HTTP server initialization. The {@code uploads} flag permanently selects which queue
   * this instance renders and which operations it allows; callers should create one instance per
   * queue side.
   *
   * @param uploads {@code true} for upload queues, {@code false} for download queues.
   * @param runtimePorts queue-specific runtime-port bundle used by the legacy HTTP handlers
   */
  public QueueToadlet(boolean uploads, QueueToadletRuntimePorts runtimePorts) {
    super();
    QueueToadletRuntimePorts ports = Objects.requireNonNull(runtimePorts);
    this.queuePagePort = ports.queuePagePort();
    this.transferAccessPort = ports.transferAccessPort();
    this.queueDownloadPort = ports.queueDownloadPort();
    this.queueInsertPort = ports.queueInsertPort();
    this.queueMutationPort = ports.queueMutationPort();
    this.queueSupportPort = ports.queueSupportPort();
    this.darknetConnectionsPort = ports.darknetConnectionsPort();
    this.darknetMessagingPort = ports.darknetMessagingPort();
    this.insertCompatibilityModes = ports.insertCompatibilityModes();
    this.uploads = uploads;
    this.postHandler = new QueuePostHandler();
    ports.queueCompletionPort().ensureTrackingStarted(uploads);
  }

  /**
   * Handles all POST submissions targeting the queue toadlet.
   *
   * <p>The method validates public gateway access, then dispatches to specialized handlers for
   * inserts, deletions, restarts, panic actions, bulk removals, and other queue mutations. Each
   * handler may write an HTTP response or trigger redirects; processing stops after the first
   * handler reports success, and any remaining parts are freed in a {@code finally} block. The
   * method does not perform long-running work itself; any heavy tasks are delegated to asynchronous
   * job runners to keep the HTTP thread responsive.
   *
   * @param uri request URI used when building redirects and locations.
   * @param request parsed request with multipart fields and uploaded data.
   * @param ctx toadlet context for permissions, localization, and responses.
   * @throws ToadletContextClosedException if the client disconnects or the context is otherwise
   *     closed while writing the response body.
   * @throws IOException if an underlying stream operation fails during request or response
   *     handling.
   * @throws RedirectException if a handler chooses to redirect the caller to another path.
   */
  public void handleMethodPOST(URI uri, HTTPRequest request, final ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {

    if (container.publicGatewayMode() && !ctx.isAllowedFullAccess()) {
      sendUnauthorizedPage(ctx);
      return;
    }

    boolean handled;
    try {
      handled = postHandler.handle(request, ctx);
    } finally {
      request.freeParts();
    }
    if (handled) {
      return;
    }
    this.handleMethodGET(uri, new HTTPRequestImpl(uri, "GET"), ctx);
  }

  /**
   * Handles POST submissions that mutate queue state, including inserts, removals, and other
   * actions, so the outer toadlet can stay focused on rendering and request routing.
   */
  private final class QueuePostHandler {
    boolean handle(HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException, RedirectException {
      CheckedHandler[] handlers = {
        () -> handleInsertLocal(request, ctx),
        () -> handleSelectLocation(request),
        () -> handleDeleteRequest(request, ctx),
        () -> handleRemoveRequest(request, ctx),
        () -> handleRemoveFinishedUploads(request, ctx),
        () -> handleRemoveFinishedDownloads(request, ctx),
        () -> handleRestartRequest(request, ctx),
        () -> handlePanic(request, ctx),
        () -> handleConfirmPanic(request, ctx),
        () -> handleDownloadRequest(request, ctx),
        () -> handleBulkDownloads(request, ctx),
        () -> handleChangePriorityActions(request, ctx),
        () -> handleInsertUpload(request, ctx),
        () -> handleLocalFileSelection(request, ctx),
        () -> handleLocalDirSelection(request, ctx),
        () -> handleRecommendRequest(request, ctx),
        () -> handleRecommendUri(request, ctx)
      };
      for (CheckedHandler handler : handlers) {
        if (handler.handle()) {
          return true;
        }
      }
      return false;
    }

    @FunctionalInterface
    private interface CheckedHandler {
      boolean handle() throws ToadletContextClosedException, IOException, RedirectException;
    }

    private boolean handleInsertLocal(HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      if (!request.isPartSet("insert-local")) {
        return false;
      }

      FreenetURI insertURI;
      String keyType = request.getPartAsStringFailsafe("keytype", 10);
      switch (keyType) {
        case "CHK" -> {
          insertURI = new FreenetURI("CHK@");
          if (fiw != null) fiw.reportCanonicalInsert();
        }
        case "SSK" -> {
          insertURI = new FreenetURI("SSK@");
          if (fiw != null) fiw.reportRandomInsert();
        }
        case "specify" -> {
          try {
            String u = request.getPartAsStringFailsafe("key", MAX_KEY_LENGTH);
            insertURI = new FreenetURI(u);
            if (LOG.isDebugEnabled())
              LOG.debug("Insert-local key specified: {} ({})", insertURI, u);
          } catch (MalformedURLException _) {
            writeInsertError(l10n(ERROR_INVALID_URI), l10n(ERROR_INVALID_URI_TO_U), ctx);
            return true;
          }
        }
        case null, default -> {
          writeInsertError(
              l10n("errorMustSpecifyKeyTypeTitle"), l10n("errorMustSpecifyKeyType"), ctx);
          return true;
        }
      }
      MultiValueTable<String, String> responseHeaders =
          MultiValueTable.from(
              "Location",
              LocalFileInsertToadlet.INSERT_BROWSE_PATH
                  + "?key="
                  + insertURI.toASCIIString()
                  + "&"
                  + COMPRESS_FIELD
                  + "="
                  + !request.getPartAsStringFailsafe(COMPRESS_FIELD, 128).isEmpty()
                  + "&"
                  + COMPATIBILITY_MODE_FIELD
                  + "="
                  + request.getPartAsStringFailsafe(COMPATIBILITY_MODE_FIELD, 100)
                  + "&"
                  + OVERRIDE_SPLITFILE_KEY_FIELD
                  + "="
                  + request.getPartAsStringFailsafe(OVERRIDE_SPLITFILE_KEY_FIELD, 65));
      ctx.sendReplyHeaders(302, "Found", responseHeaders, null, 0);
      return true;
    }

    private boolean handleSelectLocation(HTTPRequest request) throws RedirectException {
      if (!request.isPartSet("select-location")) {
        return false;
      }
      try {
        throw new RedirectException(LocalDirectoryToadlet.basePath() + PATH_DOWNLOADS);
      } catch (URISyntaxException _) {
        // Shouldn't happen, a path is defined as such.
      }
      return true;
    }

    private boolean handleDeleteRequest(HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      if (!request.isPartSet(DELETE_REQUEST)
          || request.getPartAsStringFailsafe(DELETE_REQUEST, 128).isEmpty()) {
        return false;
      }
      PageNode page = ctx.getPageMaker().getPageNode(l10n("confirmDeleteTitle"), ctx);
      HTMLNode inner = page.getContentNode();
      HTMLNode content =
          ctx.getPageMaker()
              .getInfobox(
                  "infobox-warning",
                  l10n("confirmDeleteTitle"),
                  inner,
                  "confirm-delete-title",
                  true);

      HTMLNode deleteNode = new HTMLNode("p");
      HTMLNode deleteForm = ctx.addFormChild(deleteNode, path(), "queueDeleteForm");
      HTMLNode infoList = deleteForm.addChild("ul");

      populateDeleteInfoList(request, infoList);
      content.addChild("p", l10n("confirmDelete"));
      content.addChild(deleteNode);
      addDeleteFormButtons(deleteForm);

      writeHTMLReply(ctx, 200, "OK", page.generate());
      return true;
    }

    private void populateDeleteInfoList(HTTPRequest request, HTMLNode infoList) {
      for (String part : request.getParts()) {
        processDeletePart(request, infoList, part);
      }
    }

    private void processDeletePart(HTTPRequest request, HTMLNode infoList, String part) {
      if (!part.startsWith(IDENTIFIER_PREFIX)) {
        return;
      }
      String identifierPart = part.substring(IDENTIFIER_PREFIX.length());
      if (identifierPart.length() > 50) {
        return;
      }
      String identifier =
          request.getPartAsStringFailsafe(
              IDENTIFIER_PREFIX + identifierPart, MAX_IDENTIFIER_LENGTH);
      if (identifier == null) {
        return;
      }
      String filename =
          request.getPartAsStringFailsafe(FILENAME_PREFIX + identifierPart, MAX_FILENAME_LENGTH);
      String keyString =
          request.getPartAsStringFailsafe(KEY_PREFIX + identifierPart, MAX_KEY_LENGTH);
      String type = request.getPartAsStringFailsafe("type-" + identifierPart, MAX_TYPE_LENGTH);
      String size = request.getPartAsStringFailsafe("size-" + identifierPart, 50);
      if (filename != null) {
        addFilenameLine(infoList, keyString, filename);
      }
      if (type != null && !type.isEmpty()) {
        addMimeTypeLine(request, infoList, type);
      }
      if (size != null) {
        HTMLNode line = infoList.addChild("li");
        line.addChild("#", NodeL10n.getBase().getString("FProxyToadlet.sizeLabel") + " " + size);
      }
      infoList.addChild("#", l10n("deleteFileFromTemp"));
      infoList.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE, ATTR_CHECKED},
          new String[] {
            INPUT_TYPE_CHECKBOX, IDENTIFIER_PREFIX + identifierPart, identifier, ATTR_CHECKED
          });
    }

    private void addMimeTypeLine(HTTPRequest request, HTMLNode infoList, String type) {
      HTMLNode line = infoList.addChild("li");
      boolean finalized = request.isPartSet("finalizedType");
      line.addChild(
          "#",
          NodeL10n.getBase()
              .getString(
                  "FProxyToadlet." + (finalized ? "mimeType" : "expectedMimeType"),
                  new String[] {"mime"},
                  new String[] {type}));
    }

    private void addFilenameLine(HTMLNode infoList, String keyString, String filename) {
      HTMLNode line = infoList.addChild("li");
      line.addChild("#", NodeL10n.getBase().getString("FProxyToadlet.filenameLabel") + " ");
      if (keyString != null) {
        line.addChild("a", "href", "/" + keyString, filename);
      } else {
        line.addChild("#", filename);
      }
    }

    private void addDeleteFormButtons(HTMLNode deleteForm) {
      deleteForm.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {
            INPUT_TYPE_SUBMIT, REMOVE_REQUEST, NodeL10n.getBase().getString("Toadlet.yes")
          });
      deleteForm.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {INPUT_TYPE_SUBMIT, "cancel", NodeL10n.getBase().getString("Toadlet.no")});
    }

    private boolean handleRemoveRequest(HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      if (!request.isPartSet(REMOVE_REQUEST)
          || request.getPartAsStringFailsafe(REMOVE_REQUEST, 128).isEmpty()) {
        return false;
      }
      try {
        queueMutationPort.removeRequests(extractSelectedIdentifiers(request));
      } catch (RequestQueueUnavailableException _) {
        sendPersistenceDisabledError(ctx);
        return true;
      }
      writePermanentRedirect(ctx, "Done", path());
      return true;
    }

    private boolean handleRemoveFinishedUploads(HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      if (!request.isPartSet(REMOVE_FINISHED_UPLOADS_REQUEST)
          || request.getPartAsStringFailsafe(REMOVE_FINISHED_UPLOADS_REQUEST, 128).isEmpty()) {
        return false;
      }
      try {
        queueMutationPort.removeFinishedUploads();
      } catch (RequestQueueUnavailableException _) {
        sendPersistenceDisabledError(ctx);
        return true;
      }
      writePermanentRedirect(ctx, "Done", path());
      return true;
    }

    private boolean handleRemoveFinishedDownloads(HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      if (!request.isPartSet(REMOVE_FINISHED_DOWNLOADS_REQUEST)
          || request.getPartAsStringFailsafe(REMOVE_FINISHED_DOWNLOADS_REQUEST, 128).isEmpty()) {
        return false;
      }
      try {
        queueMutationPort.removeFinishedDownloads();
      } catch (RequestQueueUnavailableException _) {
        sendPersistenceDisabledError(ctx);
        return true;
      }
      writePermanentRedirect(ctx, "Done", path());
      return true;
    }

    private boolean handleRestartRequest(HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      if (!request.isPartSet(RESTART_REQUEST)
          || request.getPartAsStringFailsafe(RESTART_REQUEST, 128).isEmpty()) {
        return false;
      }
      boolean disableFilterData = request.isPartSet(DISABLE_FILTER_DATA);
      try {
        queueMutationPort.restartRequests(extractSelectedIdentifiers(request), disableFilterData);
      } catch (RequestQueueUnavailableException _) {
        sendPersistenceDisabledError(ctx);
        return true;
      }
      writePermanentRedirect(ctx, "Done", path());
      return true;
    }

    private boolean handlePanic(HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      if (!request.isPartSet(PANIC) || request.getPartAsStringFailsafe(PANIC, 128).isEmpty()) {
        return false;
      }
      if (SimpleToadletServer.noConfirmPanic) {
        queueSupportPort.beginPanic();
        sendPanicingPage(ctx);
        queueSupportPort.finishPanic();
      } else {
        sendConfirmPanicPage(ctx);
      }
      return true;
    }

    private boolean handleConfirmPanic(HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      if (!request.isPartSet(CONFIRM_PANIC)
          || request.getPartAsStringFailsafe(CONFIRM_PANIC, 128).isEmpty()) {
        return false;
      }
      queueSupportPort.beginPanic();
      sendPanicingPage(ctx);
      queueSupportPort.finishPanic();
      return true;
    }

    private boolean handleDownloadRequest(HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      if (!request.isPartSet("download")) {
        return false;
      }
      if (!request.isPartSet("key")) {
        writeError(l10n("errorNoKey"), l10n("errorNoKeyToD"), ctx);
        return true;
      }
      String expectedMIMEType = null;
      if (request.isPartSet("type")) {
        expectedMIMEType = request.getPartAsStringFailsafe("type", MAX_TYPE_LENGTH);
      }
      String fetchUri = request.getPartAsStringFailsafe("key", MAX_KEY_LENGTH);
      try {
        new FreenetURI(fetchUri);
      } catch (MalformedURLException _) {
        writeError(l10n(ERROR_INVALID_URI), l10n(ERROR_INVALID_URI_TO_D), ctx);
        return true;
      }
      String persistence = request.getPartAsStringFailsafe("persistence", 32);
      String returnType = request.getPartAsStringFailsafe("return-type", 32);
      boolean filterData = request.isPartSet(FILTER_DATA);
      String downloadPath;
      File downloadsDir = null;
      if (request.isPartSet("path") && !isDiskDownloadDisabledOrUnsafe(ctx)) {
        downloadPath = request.getPartAsStringFailsafe("path", MAX_FILENAME_LENGTH);
        try {
          downloadsDir = getDownloadsDir(downloadPath);
        } catch (DownloadTargetNotAllowedException e) {
          downloadDisallowedPage(e, downloadPath, ctx);
          return true;
        }
      } else {
        returnType = RETURN_TYPE_DIRECT;
      }
      try {
        queueDownloadPort.enqueueDownload(
            new QueueDownloadRequest(
                fetchUri, filterData, expectedMIMEType, persistence, returnType, downloadsDir));
      } catch (QueueDownloadRejectedException _) {
        writeError(l10n("errorDToDisk"), l10n("errorDToDiskConfig"), ctx);
        return true;
      } catch (RequestQueueUnavailableException _) {
        sendPersistenceDisabledError(ctx);
        return true;
      }
      writePermanentRedirect(ctx, "Done", path());
      return true;
    }

    private boolean handleBulkDownloads(HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      if (!request.isPartSet(BULK_DOWNLOADS)) {
        return false;
      }

      String[] keys = readBulkDownloadKeys(request, ctx);
      if (keys.length == 0) {
        return true;
      }

      DownloadTarget downloadTarget = resolveDownloadTarget(request, ctx);
      if (downloadTarget == null) {
        return true;
      }

      BulkDownloadResult result =
          enqueueBulkDownloads(keys, request.isPartSet(FILTER_DATA), downloadTarget);
      renderBulkDownloadResult(ctx, result);
      return true;
    }

    private String[] readBulkDownloadKeys(HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      String bulkDownloadsAsString = request.getPartAsStringFailsafe(BULK_DOWNLOADS, 262144);
      String[] keys = bulkDownloadsAsString.split("\n");
      if (bulkDownloadsAsString.isEmpty() || (keys.length < 1)) {
        writePermanentRedirect(ctx, "Done", path());
        return new String[0];
      }
      return keys;
    }

    private DownloadTarget resolveDownloadTarget(HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      String target = request.getPartAsStringFailsafe(TARGET, 128);
      if (target == null || target.isEmpty()) target = RETURN_TYPE_DIRECT;

      if (!request.isPartSet("path")) {
        return new DownloadTarget(target, null);
      }
      if (isDiskDownloadDisabledOrUnsafe(ctx)) {
        return new DownloadTarget(RETURN_TYPE_DIRECT, null);
      }

      String downloadPath = request.getPartAsStringFailsafe("path", MAX_FILENAME_LENGTH);
      try {
        return new DownloadTarget(target, getDownloadsDir(downloadPath));
      } catch (DownloadTargetNotAllowedException e) {
        downloadDisallowedPage(e, downloadPath, ctx);
        return null;
      }
    }

    private BulkDownloadResult enqueueBulkDownloads(
        String[] keys, boolean filterData, DownloadTarget downloadTarget) {
      List<String> success = new ArrayList<>();
      List<String> failure = new ArrayList<>();

      for (int i = 0; i < keys.length; i++) {
        String currentKey = keys[i].trim();
        if (currentKey.isEmpty()) {
          continue;
        }

        try {
          FreenetURI fetchURI = new FreenetURI(currentKey);
          queueDownloadPort.enqueueDownload(
              new QueueDownloadRequest(
                  currentKey,
                  filterData,
                  null,
                  "forever",
                  downloadTarget.target(),
                  downloadTarget.downloadsDir()));
          success.add(fetchURI.toString(true, false));
        } catch (Exception e) {
          failure.add(currentKey);
          LOG.error(
              "An error occured while attempting to download key({}) : {} : {}",
              i,
              currentKey,
              e.getMessage());
        }
      }
      return new BulkDownloadResult(success, failure);
    }

    private void renderBulkDownloadResult(ToadletContext ctx, BulkDownloadResult result)
        throws ToadletContextClosedException, IOException {
      boolean displayFailureBox = !result.failure().isEmpty();
      boolean displaySuccessBox = !result.success().isEmpty();

      PageNode page = ctx.getPageMaker().getPageNode(l10n(DOWNLOAD_FILES), ctx);
      HTMLNode contentNode = page.getContentNode();

      HTMLNode alertContent =
          ctx.getPageMaker()
              .getInfobox(
                  (displayFailureBox ? "infobox-warning" : "infobox-info"),
                  l10n(DOWNLOAD_FILES),
                  contentNode,
                  GROUPED_DOWNLOADS,
                  true);
      if (displaySuccessBox) {
        HTMLNode successDiv = alertContent.addChild("ul");
        successDiv.addChild(
            "#", l10n("enqueuedSuccessfully", "number", String.valueOf(result.success().size())));
        for (String s : result.success()) {
          successDiv.addChild("li").addChild("#", s);
        }
        successDiv.addChild("br");
      }
      if (displayFailureBox) {
        HTMLNode failureDiv = alertContent.addChild("ul");
        failureDiv.addChild(
            "#", l10n("enqueuedFailure", "number", String.valueOf(result.failure().size())));
        for (String f : result.failure()) {
          failureDiv.addChild("li").addChild("#", f);
        }
        failureDiv.addChild("br");
      }
      alertContent.addChild(
          "a", "href", path(), NodeL10n.getBase().getString("Toadlet.returnToQueuepage"));
      writeHTMLReply(ctx, 200, "OK", page.generate());
    }

    /** Signals that the requested download target is not allowed for this queue operation. */
    private static final class DownloadTargetNotAllowedException extends Exception {
      private DownloadTargetNotAllowedException() {}
    }

    private record DownloadTarget(String target, File downloadsDir) {}

    private record BulkDownloadResult(List<String> success, List<String> failure) {}

    @SuppressWarnings({"java:S6206", "ClassCanBeRecord"})
    private static final class InsertUploadContext {
      private final String insertUri;
      private final QueueUploadedFile file;
      private final boolean compress;
      private final String identifier;
      private final String compatibilityMode;
      private final byte[] overrideSplitfileKey;
      private final String filenameForKey;

      private InsertUploadContext(
          String insertUri,
          QueueUploadedFile file,
          boolean compress,
          String identifier,
          String compatibilityMode,
          byte[] overrideSplitfileKey,
          String filenameForKey) {
        this.insertUri = insertUri;
        this.file = file;
        this.compress = compress;
        this.identifier = identifier;
        this.compatibilityMode = compatibilityMode;
        this.overrideSplitfileKey = overrideSplitfileKey;
        this.filenameForKey = filenameForKey;
      }

      String insertUri() {
        return insertUri;
      }

      QueueUploadedFile file() {
        return file;
      }

      boolean compress() {
        return compress;
      }

      String identifier() {
        return identifier;
      }

      String compatibilityMode() {
        return compatibilityMode;
      }

      byte[] overrideSplitfileKey() {
        return overrideSplitfileKey;
      }

      String filenameForKey() {
        return filenameForKey;
      }

      @Override
      public boolean equals(Object o) {
        if (!(o instanceof InsertUploadContext other)) {
          return false;
        }
        return compress == other.compress
            && Objects.equals(insertUri, other.insertUri)
            && Objects.equals(file, other.file)
            && Objects.equals(identifier, other.identifier)
            && Objects.equals(compatibilityMode, other.compatibilityMode)
            && Arrays.equals(overrideSplitfileKey, other.overrideSplitfileKey)
            && Objects.equals(filenameForKey, other.filenameForKey);
      }

      @Override
      public int hashCode() {
        int result =
            Objects.hash(insertUri, file, compress, identifier, compatibilityMode, filenameForKey);
        return 31 * result + Arrays.hashCode(overrideSplitfileKey);
      }

      @Override
      public @NotNull String toString() {
        return "InsertUploadContext{"
            + "insertUri="
            + insertUri
            + ", file="
            + file
            + COMPRESS_LABEL
            + compress
            + ", identifier='"
            + identifier
            + '\''
            + CMODE_LABEL
            + compatibilityMode
            + OVERRIDE_SPLITFILE_KEY_LABEL
            + Arrays.toString(overrideSplitfileKey)
            + ", filenameForKey='"
            + filenameForKey
            + '\''
            + '}';
      }
    }

    @SuppressWarnings({"java:S6206", "ClassCanBeRecord"})
    private static final class InsertOptions {
      private final boolean compress;
      private final String compatibilityMode;
      private final byte[] overrideSplitfileKey;
      private final String target;

      private InsertOptions(
          boolean compress, String compatibilityMode, byte[] overrideSplitfileKey, String target) {
        this.compress = compress;
        this.compatibilityMode = compatibilityMode;
        this.overrideSplitfileKey = overrideSplitfileKey;
        this.target = target;
      }

      boolean compress() {
        return compress;
      }

      String compatibilityMode() {
        return compatibilityMode;
      }

      byte[] overrideSplitfileKey() {
        return overrideSplitfileKey;
      }

      String target() {
        return target;
      }

      @Override
      public boolean equals(Object o) {
        if (!(o instanceof InsertOptions other)) {
          return false;
        }
        return compress == other.compress
            && Objects.equals(compatibilityMode, other.compatibilityMode)
            && Arrays.equals(overrideSplitfileKey, other.overrideSplitfileKey)
            && Objects.equals(target, other.target);
      }

      @Override
      public int hashCode() {
        int result = Objects.hash(compress, compatibilityMode, target);
        return 31 * result + Arrays.hashCode(overrideSplitfileKey);
      }

      @Override
      public @NotNull String toString() {
        return "InsertOptions{"
            + COMPRESS_LABEL
            + compress
            + CMODE_LABEL
            + compatibilityMode
            + OVERRIDE_SPLITFILE_KEY_LABEL
            + Arrays.toString(overrideSplitfileKey)
            + ", target='"
            + target
            + '\''
            + '}';
      }
    }

    private record LocalFileInsertParams(
        File file, String id, String contentType, String uri, InsertOptions options) {

      boolean compress() {
        return options.compress();
      }

      String compatibilityMode() {
        return options.compatibilityMode();
      }

      byte[] overrideSplitfileKey() {
        return options.overrideSplitfileKey();
      }

      String target() {
        return options.target();
      }

      @Override
      public boolean equals(Object o) {
        return o
                instanceof
                LocalFileInsertParams(
                    var otherFile,
                    var otherId,
                    var otherContentType,
                    var otherUri,
                    var otherOptions)
            && Objects.equals(file, otherFile)
            && Objects.equals(id, otherId)
            && Objects.equals(contentType, otherContentType)
            && Objects.equals(uri, otherUri)
            && Objects.equals(options, otherOptions);
      }

      @Override
      public int hashCode() {
        return Objects.hash(file, id, contentType, uri, options);
      }

      @Override
      public @NotNull String toString() {
        return "LocalFileInsertParams{"
            + "file="
            + file
            + ", id='"
            + id
            + '\''
            + ", contentType='"
            + contentType
            + '\''
            + ", uri="
            + uri
            + ", options="
            + options
            + '}';
      }
    }

    @SuppressWarnings({"java:S6206", "ClassCanBeRecord"})
    private static final class LocalDirInsertParams {
      private final File file;
      private final String identifier;
      private final String uri;
      private final boolean compress;
      private final String compatibilityMode;
      private final byte[] overrideSplitfileKey;

      private LocalDirInsertParams(
          File file,
          String identifier,
          String uri,
          boolean compress,
          String compatibilityMode,
          byte[] overrideSplitfileKey) {
        this.file = file;
        this.identifier = identifier;
        this.uri = uri;
        this.compress = compress;
        this.compatibilityMode = compatibilityMode;
        this.overrideSplitfileKey = overrideSplitfileKey;
      }

      File file() {
        return file;
      }

      String identifier() {
        return identifier;
      }

      String uri() {
        return uri;
      }

      boolean compress() {
        return compress;
      }

      String compatibilityMode() {
        return compatibilityMode;
      }

      byte[] overrideSplitfileKey() {
        return overrideSplitfileKey;
      }

      @Override
      public boolean equals(Object o) {
        if (!(o instanceof LocalDirInsertParams other)) {
          return false;
        }
        return compress == other.compress
            && Objects.equals(compatibilityMode, other.compatibilityMode)
            && Objects.equals(file, other.file)
            && Objects.equals(identifier, other.identifier)
            && Objects.equals(uri, other.uri)
            && Arrays.equals(overrideSplitfileKey, other.overrideSplitfileKey);
      }

      @Override
      public int hashCode() {
        int result = Objects.hash(file, identifier, uri, compress, compatibilityMode);
        return 31 * result + Arrays.hashCode(overrideSplitfileKey);
      }

      @Override
      public @NotNull String toString() {
        return "LocalDirInsertParams{"
            + "file="
            + file
            + ", identifier='"
            + identifier
            + '\''
            + ", uri="
            + uri
            + COMPRESS_LABEL
            + compress
            + CMODE_LABEL
            + compatibilityMode
            + OVERRIDE_SPLITFILE_KEY_LABEL
            + Arrays.toString(overrideSplitfileKey)
            + '}';
      }
    }

    private boolean handleChangePriorityActions(HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      if (request.isPartSet("change_priority_top")) {
        handleChangePriority(request, ctx, "_top");
        return true;
      }
      if (request.isPartSet("change_priority_bottom")) {
        handleChangePriority(request, ctx, "_bottom");
        return true;
      }
      return false;
    }

    private boolean handleInsertUpload(HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      if (request.getPartAsStringFailsafe("insert", 128).isEmpty()) {
        return false;
      }
      InsertUploadContext params = parseInsertUploadRequest(request, ctx);
      if (params == null) {
        return true;
      }

      try {
        QueueInsertOutcome outcome =
            queueInsertPort.enqueueBrowserUploadInsert(
                new QueueBrowserUploadInsertRequest(
                    params.insertUri(),
                    params.identifier(),
                    params.file(),
                    new QueueInsertOptions(
                        params.compress(),
                        params.compatibilityMode(),
                        params.overrideSplitfileKey()),
                    params.filenameForKey()));
        handleInsertOutcome(outcome, ctx);
      } catch (QueueInsertRejectedException e) {
        handleBrowserUploadInsertRejection(e.reason(), params, ctx);
      } catch (RequestQueueUnavailableException _) {
        sendPersistenceDisabledError(ctx);
      } catch (IOException e) {
        writeInternalError(e, ctx);
      }
      return true;
    }

    private InsertUploadContext parseInsertUploadRequest(HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      String keyType = request.getPartAsStringFailsafe("keytype", 10);
      String insertUri = parseInsertURI(keyType, request, ctx);
      if (insertUri == null) {
        return null;
      }

      HTTPUploadedFile file = request.getUploadedFile(FILENAME);
      if (file == null || file.getFilename().trim().isEmpty()) {
        writeInsertError(l10n("errorNoFileSelected"), l10n("errorNoFileSelectedU"), ctx);
        return null;
      }

      boolean compress = !request.getPartAsStringFailsafe(COMPRESS_FIELD, 128).isEmpty();
      String identifier = file.getFilename() + FRED_SUFFIX + System.currentTimeMillis();
      String compatibilityMode = parseCompatibilityMode(request);
      byte[] overrideSplitfileKey =
          normalizeOverrideSplitfileKey(parseOverrideSplitfileKey(request));
      String filenameForKey =
          insertUri.startsWith("CHK@") || "SSK".equals(keyType) ? file.getFilename() : null;

      return new InsertUploadContext(
          insertUri,
          toQueueUploadedFile(file),
          compress,
          identifier,
          compatibilityMode,
          overrideSplitfileKey,
          filenameForKey);
    }

    private String parseInsertURI(String keyType, HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      try {
        if ("CHK".equals(keyType)) {
          if (fiw != null) fiw.reportCanonicalInsert();
          return "CHK@";
        }
        if ("SSK".equals(keyType)) {
          if (fiw != null) fiw.reportRandomInsert();
          return "SSK@";
        }
        if ("specify".equals(keyType)) {
          String uri = request.getPartAsStringFailsafe("key", MAX_KEY_LENGTH);
          FreenetURI insertURI = new FreenetURI(uri);
          if (LOG.isDebugEnabled())
            LOG.debug("Insert upload key specified: {} ({})", insertURI, uri);
          return insertURI.toString();
        }
        writeInsertError(
            l10n("errorMustSpecifyKeyTypeTitle"), l10n("errorMustSpecifyKeyType"), ctx);
        return null;
      } catch (MalformedURLException _) {
        writeInsertError(l10n(ERROR_INVALID_URI), l10n(ERROR_INVALID_URI_TO_U), ctx);
        return null;
      }
    }

    private String parseCompatibilityMode(HTTPRequest request) {
      String compatibilityMode = request.getPartAsStringFailsafe(COMPATIBILITY_MODE_FIELD, 100);
      if (compatibilityMode.isEmpty()) {
        return insertCompatibilityModes.defaultModeName();
      }
      if ("COMPAT_CURRENT".equals(compatibilityMode)) {
        return insertCompatibilityModes.defaultModeName();
      }
      if (insertCompatibilityModes.supportedModeNames().contains(compatibilityMode)) {
        return compatibilityMode;
      }
      throw new IllegalArgumentException(compatibilityMode);
    }

    private QueueUploadedFile toQueueUploadedFile(HTTPUploadedFile file) {
      Bucket uploadData = file.getData();
      return new QueueUploadedFile(
          file.getFilename(),
          file.getContentType(),
          uploadData.size(),
          uploadData::getInputStreamUnbuffered);
    }

    private byte[] parseOverrideSplitfileKey(HTTPRequest request) {
      String rawKey = request.getPartAsStringFailsafe(OVERRIDE_SPLITFILE_KEY_FIELD, 65);
      if (rawKey != null && !rawKey.isEmpty()) {
        return hexToBytes(rawKey);
      }
      return new byte[0];
    }

    private byte[] normalizeOverrideSplitfileKey(byte[] overrideSplitfileKey) {
      return overrideSplitfileKey.length == 0 ? null : overrideSplitfileKey;
    }

    private static byte[] hexToBytes(String hex) {
      int length = hex.length();
      if ((length & 1) != 0) {
        return new byte[0];
      }
      byte[] out = new byte[length / 2];
      for (int i = 0; i < length; i += 2) {
        int hi = Character.digit(hex.charAt(i), 16);
        int lo = Character.digit(hex.charAt(i + 1), 16);
        if (hi < 0 || lo < 0) {
          return new byte[0];
        }
        out[i / 2] = (byte) ((hi << 4) + lo);
      }
      return out;
    }

    private void handleInsertOutcome(QueueInsertOutcome outcome, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      switch (outcome) {
        case STARTED, IDENTIFIER_COLLISION, METADATA_UNRESOLVED ->
            writePermanentRedirect(ctx, "Done", path());
      }
    }

    private void handleBrowserUploadInsertRejection(
        QueueInsertFailureReason reason, InsertUploadContext params, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      switch (reason) {
        case ACCESS_DENIED ->
            writeInsertError(
                l10n(ERROR_ACCESS_DENIED),
                l10n(ERROR_ACCESS_DENIED_FILE_KEY, "file", params.file().filename()),
                ctx);
        case SOURCE_NOT_FOUND ->
            writeInsertError(
                l10n(ERROR_NO_FILE_OR_CANNOT_READ),
                l10n(ERROR_ACCESS_DENIED_FILE_KEY, "file", params.file().filename()),
                ctx);
        case TOO_MANY_FILES ->
            writeInsertError(
                l10n(TOO_MANY_FILES_IN_ONE_FOLDER), l10n(TOO_MANY_FILES_IN_ONE_FOLDER), ctx);
      }
    }

    private void handleLocalFileInsertRejection(
        QueueInsertFailureReason reason, LocalFileInsertParams params, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      switch (reason) {
        case ACCESS_DENIED ->
            writeError(
                l10n(ERROR_ACCESS_DENIED),
                l10n(
                    ERROR_ACCESS_DENIED_FILE_KEY,
                    new String[] {"file"},
                    new String[] {params.file().getName()}),
                ctx);
        case SOURCE_NOT_FOUND ->
            writeError(
                l10n(ERROR_NO_FILE_OR_CANNOT_READ),
                l10n(ERROR_ACCESS_DENIED_FILE_KEY, "file", params.target()),
                ctx);
        case TOO_MANY_FILES ->
            writeError(l10n(TOO_MANY_FILES_IN_ONE_FOLDER), l10n(TOO_MANY_FILES_IN_ONE_FOLDER), ctx);
      }
    }

    private void handleLocalDirectoryInsertRejection(
        QueueInsertFailureReason reason, LocalDirInsertParams params, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      switch (reason) {
        case ACCESS_DENIED ->
            writeError(
                l10n(ERROR_ACCESS_DENIED),
                l10n(ERROR_ACCESS_DENIED_FILE_KEY, "file", params.file().toString()),
                ctx);
        case SOURCE_NOT_FOUND ->
            writeError(
                l10n(ERROR_NO_FILE_OR_CANNOT_READ),
                l10n(ERROR_ACCESS_DENIED_FILE_KEY, "file", params.file().toString()),
                ctx);
        case TOO_MANY_FILES ->
            writeError(l10n(TOO_MANY_FILES_IN_ONE_FOLDER), l10n(TOO_MANY_FILES_IN_ONE_FOLDER), ctx);
      }
    }

    private boolean handleLocalFileSelection(HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      if (!request.isPartSet(LocalFileBrowserToadlet.SELECT_FILE)) {
        return false;
      }

      LocalFileInsertParams params = parseLocalFileParams(request, ctx);
      if (params == null) {
        return true;
      }

      try {
        QueueInsertOutcome outcome =
            queueInsertPort.enqueueLocalFileInsert(
                new QueueLocalFileInsertRequest(
                    params.file(),
                    params.uri(),
                    params.id(),
                    params.contentType(),
                    new QueueInsertOptions(
                        params.compress(),
                        params.compatibilityMode(),
                        params.overrideSplitfileKey()),
                    params.target()));
        handleInsertOutcome(outcome, ctx);
      } catch (QueueInsertRejectedException e) {
        handleLocalFileInsertRejection(e.reason(), params, ctx);
      } catch (RequestQueueUnavailableException _) {
        sendPersistenceDisabledError(ctx);
      } catch (IOException e) {
        writeInternalError(e, ctx);
      }
      return true;
    }

    private LocalFileInsertParams parseLocalFileParams(HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      String filename = request.getPartAsStringFailsafe(FILENAME, MAX_FILENAME_LENGTH);
      if (LOG.isDebugEnabled()) LOG.debug("Insert local file selection: {}", filename);

      File file = new File(filename);
      String identifier = file.getName() + FRED_SUFFIX + System.currentTimeMillis();
      String contentType = DefaultMIMETypes.guessMIMEType(filename, false);
      String key = request.getPartAsStringFailsafe("key", MAX_KEY_LENGTH);
      boolean compress = request.isPartSet(COMPRESS_FIELD);
      String compatibilityMode = parseCompatibilityMode(request);
      byte[] overrideSplitfileKey =
          normalizeOverrideSplitfileKey(parseOverrideSplitfileKey(request));
      FreenetURI furi;
      if (key != null) {
        try {
          furi = new FreenetURI(key);
        } catch (MalformedURLException _) {
          writeError(l10n(ERROR_INVALID_URI), l10n(ERROR_INVALID_URI_TO_U), ctx);
          return null;
        }
      } else {
        furi = new FreenetURI("CHK@");
      }

      String target = (furi.getDocName() != null) ? null : file.getName();
      InsertOptions options =
          new InsertOptions(compress, compatibilityMode, overrideSplitfileKey, target);
      return new LocalFileInsertParams(file, identifier, contentType, furi.toString(), options);
    }

    private boolean handleLocalDirSelection(HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      if (!request.isPartSet(LocalFileBrowserToadlet.SELECT_DIR)) {
        return false;
      }

      LocalDirInsertParams params = parseLocalDirParams(request, ctx);
      if (params == null) {
        return true;
      }

      try {
        QueueInsertOutcome outcome =
            queueInsertPort.enqueueLocalDirectoryInsert(
                new QueueLocalDirectoryInsertRequest(
                    params.file(),
                    params.uri(),
                    params.identifier(),
                    new QueueInsertOptions(
                        params.compress(),
                        params.compatibilityMode(),
                        params.overrideSplitfileKey())));
        handleInsertOutcome(outcome, ctx);
      } catch (QueueInsertRejectedException e) {
        handleLocalDirectoryInsertRejection(e.reason(), params, ctx);
      } catch (RequestQueueUnavailableException _) {
        sendPersistenceDisabledError(ctx);
      } catch (IOException e) {
        writeInternalError(e, ctx);
      }
      return true;
    }

    private LocalDirInsertParams parseLocalDirParams(HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      String filename = request.getPartAsStringFailsafe(FILENAME, MAX_FILENAME_LENGTH);
      if (LOG.isDebugEnabled()) LOG.debug("Insert local directory selection: {}", filename);

      File file = new File(filename);
      String identifier = file.getName() + FRED_SUFFIX + System.currentTimeMillis();
      String key = request.getPartAsStringFailsafe("key", MAX_KEY_LENGTH);
      boolean compress = request.isPartSet(COMPRESS_FIELD);
      String compatibilityMode = parseCompatibilityMode(request);
      byte[] overrideSplitfileKey =
          normalizeOverrideSplitfileKey(parseOverrideSplitfileKey(request));
      FreenetURI furi;
      if (key != null) {
        try {
          furi = new FreenetURI(key);
        } catch (MalformedURLException _) {
          writeError(l10n(ERROR_INVALID_URI), l10n(ERROR_INVALID_URI_TO_U), ctx);
          return null;
        }
      } else {
        furi = new FreenetURI("CHK@");
      }
      return new LocalDirInsertParams(
          file, identifier, furi.toString(), compress, compatibilityMode, overrideSplitfileKey);
    }

    private boolean handleRecommendRequest(HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      if (!request.isPartSet("recommend_request")) {
        return false;
      }
      PageNode page = ctx.getPageMaker().getPageNode(l10n("recommendToFriendsTitle"), ctx);
      HTMLNode inner = page.getContentNode();

      HTMLNode content =
          ctx.getPageMaker()
              .getInfobox(
                  INFOBOX_INFORMATION,
                  l10n("recommendToFriendsTitle"),
                  inner,
                  "recommend-to-friends-title",
                  true);

      HTMLNode firstNode = content.addChild("p");
      HTMLNode form = ctx.addFormChild(firstNode, path(), "recommendForm");
      List<String> identifierParts = extractIdentifierParts(request);
      int index = addFilenameInputsIfPresent(request, form, identifierParts);
      addKeyInputs(request, form, identifierParts, index);

      form.addChild(TAG_LABEL, "for", "descB", (l10n("recommendDescription") + ' '));
      form.addChild("br");
      form.addChild(
          "textarea",
          new String[] {"id", "name", "row", "cols"},
          new String[] {"descB", "description", "3", "70"});
      form.addChild("br");
      boolean fProxyJavascriptEnabled = ctx.getContainer().isFProxyJavascriptEnabled();
      if (fProxyJavascriptEnabled) {
        form.addChild(
            "script",
            new String[] {ATTR_TYPE, "src"},
            new String[] {"text/javascript", "/static/js/checkall.js"});
      }
      HTMLNode peerTable = form.addChild(TAG_TABLE, ATTR_CLASS, "darknet_connections");
      if (fProxyJavascriptEnabled) {
        HTMLNode headerRow = peerTable.addChild("tr");
        headerRow
            .addChild("th")
            .addChild(
                TAG_INPUT,
                new String[] {ATTR_TYPE, "onclick"},
                new String[] {INPUT_TYPE_CHECKBOX, "checkAll(this, 'darknet_connections')"});
        headerRow.addChild("th", l10n("recommendToFriends"));
      } else {
        peerTable.addChild("tr").addChild("th", "colspan", "2", l10n("recommendToFriends"));
      }
      for (DarknetConnectionPeerSnapshot peer : darknetConnectionsPort.listPeers()) {
        HTMLNode peerRow = peerTable.addChild("tr", ATTR_CLASS, "darknet_connections_normal");
        peerRow
            .addChild("td", ATTR_CLASS, "peer-marker")
            .addChild(
                TAG_INPUT,
                new String[] {ATTR_TYPE, ATTR_NAME},
                new String[] {INPUT_TYPE_CHECKBOX, "node_" + peer.selectionToken()});
        peerRow.addChild("td", ATTR_CLASS, "peer-name").addChild("#", peer.displayName());
      }

      form.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {INPUT_TYPE_SUBMIT, "recommend_uri", l10n("recommend")});

      writeHTMLReply(ctx, 200, "OK", page.generate());
      return true;
    }

    private List<String> extractIdentifierParts(HTTPRequest request) {
      List<String> parts = new ArrayList<>();
      for (String part : request.getParts()) {
        if (part.startsWith(IDENTIFIER_PREFIX)) {
          String trimmed = part.substring(IDENTIFIER_PREFIX.length());
          if (trimmed.length() <= 50) {
            parts.add(trimmed);
          }
        }
      }
      return parts;
    }

    private int addFilenameInputsIfPresent(
        HTTPRequest request, HTMLNode form, List<String> identifierParts) {
      if (!request.isPartSet(FILENAME)) {
        return 0;
      }
      int index = 0;
      for (String part : identifierParts) {
        String filename =
            request.getPartAsStringFailsafe(FILENAME_PREFIX + part, MAX_FILENAME_LENGTH);
        if (filename == null || filename.isEmpty()) {
          continue;
        }
        HTMLNode inputNode = form.addChild(TAG_INPUT);
        inputNode.addAttribute(ATTR_TYPE, "text");
        inputNode.addAttribute(ATTR_VALUE, filename);
        inputNode.addAttribute("readonly", "readonly");
        form.addChild(
            TAG_INPUT,
            new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
            new String[] {INPUT_TYPE_HIDDEN, FILENAME_PREFIX + index, filename});
        index++;
      }
      if (index > 0) {
        form.addChild("br");
      }
      return index;
    }

    private void addKeyInputs(
        HTTPRequest request, HTMLNode form, List<String> identifierParts, int startIndex) {
      int index = startIndex;
      for (String part : identifierParts) {
        String key = request.getPartAsStringFailsafe(KEY_PREFIX + part, MAX_KEY_LENGTH);
        if (key == null || key.isEmpty()) {
          continue;
        }
        form.addChild("#", l10n("key") + ":");
        form.addChild("br");
        form.addChild("#", key);
        form.addChild("br");
        form.addChild(
            TAG_INPUT,
            new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
            new String[] {INPUT_TYPE_HIDDEN, KEY_PREFIX + index, key});
        index++;
      }
    }

    private boolean handleRecommendUri(HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      if (!request.isPartSet("recommend_uri")) {
        return false;
      }
      String description = request.getPartAsStringFailsafe("description", 32768);
      List<String> uris = new ArrayList<>();
      for (String part : request.getParts()) {
        if (!part.startsWith(KEY_PREFIX)) continue;
        String key = request.getPartAsStringFailsafe(part, MAX_KEY_LENGTH);
        try {
          new FreenetURI(key);
          uris.add(key);
        } catch (MalformedURLException _) {
          writeError(l10n(ERROR_INVALID_URI), l10n(ERROR_INVALID_URI_TO_U), ctx);
          return true;
        }
      }

      if (!uris.isEmpty()) {
        for (DarknetConnectionPeerSnapshot peer : darknetConnectionsPort.listPeers()) {
          if (!request.isPartSet("node_" + peer.selectionToken())) {
            continue;
          }
          try {
            darknetMessagingPort.recommendDownloads(peer.nodeIdentifier(), uris, description);
          } catch (UnknownPeerException | DarknetPeerRequiredException e) {
            LOG.warn(
                "Skipping queue recommendation for unresolved peer {}", peer.nodeIdentifier(), e);
          }
        }
      }
      writePermanentRedirect(ctx, "Done", path());
      return true;
    }

    private void handleChangePriority(HTTPRequest request, ToadletContext ctx, String suffix)
        throws ToadletContextClosedException, IOException {
      short newPriority = Short.parseShort(request.getPartAsStringFailsafe(PRIORITY + suffix, 32));
      try {
        queueMutationPort.changePriority(extractSelectedIdentifiers(request), newPriority);
      } catch (RequestQueueUnavailableException _) {
        sendPersistenceDisabledError(ctx);
        return;
      }
      writePermanentRedirect(ctx, "Done", path());
    }

    private List<String> extractSelectedIdentifiers(HTTPRequest request) {
      List<String> identifiers = new ArrayList<>();
      for (String part : request.getParts()) {
        if (!part.startsWith(IDENTIFIER_PREFIX)) {
          continue;
        }
        String identifierPart = part.substring(IDENTIFIER_PREFIX.length());
        if (identifierPart.length() <= 50) {
          identifiers.add(request.getPartAsStringFailsafe(part, MAX_IDENTIFIER_LENGTH));
        }
      }
      return identifiers;
    }

    private void writeError(String header, String message, ToadletContext context)
        throws ToadletContextClosedException, IOException {
      QueueToadlet.this.writeError(header, message, context, true, false);
    }

    private void writeInsertError(String header, String message, ToadletContext context)
        throws ToadletContextClosedException, IOException {
      QueueToadlet.this.writeError(header, message, context, false, true);
    }

    private void downloadDisallowedPage(
        DownloadTargetNotAllowedException e, String downloadPath, ToadletContext ctx)
        throws IOException, ToadletContextClosedException {
      PageNode page = ctx.getPageMaker().getPageNode(l10n(DOWNLOAD_FILES), ctx);
      HTMLNode contentNode = page.getContentNode();
      LOG.warn("Download disallowed for path {}", downloadPath, e);
      HTMLNode alert =
          ctx.getPageMaker()
              .getInfobox(
                  "infobox-alert", l10n(DOWNLOAD_FILES), contentNode, GROUPED_DOWNLOADS, true);
      alert.addChild("ul", l10n("downloadDisallowed", "directory", downloadPath));
      alert.addChild(
          "a", "href", path(), NodeL10n.getBase().getString("Toadlet.returnToQueuepage"));
      writeHTMLReply(ctx, 200, "OK", page.generate());
    }

    private boolean isDiskDownloadDisabledOrUnsafe(ToadletContext ctx) {
      return queueDownloadPort.isDiskDownloadDisabled()
          || (ctx.getContainer().publicGatewayMode() && !ctx.isAllowedFullAccess());
    }

    private File getDownloadsDir(String downloadPath) throws DownloadTargetNotAllowedException {
      File downloadsDir = new File(downloadPath);
      // Invalid if it's disallowed, doesn't exist, isn't a directory, or can't be created.
      if (!transferAccessPort.allowDownloadTo(downloadsDir)
          || !((downloadsDir.exists() && downloadsDir.isDirectory()) || !downloadsDir.mkdirs())) {
        throw new DownloadTargetNotAllowedException();
      }
      return downloadsDir;
    }

    private void sendPanicingPage(ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      writeHTMLReply(
          ctx, 200, "OK", LegacyWelcomePageSupport.sendRestartingPageInner(ctx).generate());
    }

    private void sendConfirmPanicPage(ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      PageNode page = ctx.getPageMaker().getPageNode(l10n("confirmPanicButtonPageTitle"), ctx);
      HTMLNode contentNode = page.getContentNode();

      HTMLNode content =
          ctx.getPageMaker()
              .getInfobox(
                  INFOBOX_ERROR,
                  l10n("confirmPanicButtonPageTitle"),
                  contentNode,
                  "confirm-panic",
                  true)
              .addChild("div", ATTR_CLASS, "infobox-content");

      content.addChild("p", l10n("confirmPanicButton"));

      HTMLNode form = ctx.addFormChild(content, path(), "confirmPanicButton");
      form.addChild("p")
          .addChild(
              TAG_INPUT,
              new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
              new String[] {INPUT_TYPE_SUBMIT, CONFIRM_PANIC, l10n("confirmPanicButtonYes")});
      form.addChild("p")
          .addChild(
              TAG_INPUT,
              new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
              new String[] {INPUT_TYPE_SUBMIT, "noconfirmpanic", l10n("confirmPanicButtonNo")});

      if (uploads) content.addChild("p").addChild("a", "href", path(), l10n("backToUploadsPage"));
      else content.addChild("p").addChild("a", "href", path(), l10n("backToDownloadsPage"));

      writeHTMLReply(ctx, 200, "OK", page.generate());
    }
  }

  private void sendPersistenceDisabledError(ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    QueuePersistenceStatusSnapshot persistenceStatus = queueSupportPort.persistenceStatus();
    String title = l10n("awaitingPasswordTitle" + (uploads ? "Uploads" : "Downloads"));
    if (persistenceStatus.awaitingPassword()) {
      PageNode page = ctx.getPageMaker().getPageNode(title, ctx);
      HTMLNode contentNode = page.getContentNode();

      HTMLNode infoboxContent =
          ctx.getPageMaker().getInfobox(INFOBOX_ERROR, title, contentNode, null, true);

      SecurityLevelsToadlet.generatePasswordFormPage(
          new PasswordFormOptions(false, false, false, false, null, path()),
          container,
          infoboxContent);

      addHomepageLink(infoboxContent);

      writeHTMLReply(ctx, 500, "Internal Server Error", page.generate());
      return;
    }
    if (persistenceStatus.stopping())
      sendErrorPage(ctx, 200, l10n("shuttingDownTitle"), l10n("shuttingDown"));
    else
      sendErrorPage(
          ctx,
          200,
          l10n("persistenceBrokenTitle"),
          l10n(
              "persistenceBroken",
              new String[] {"TEMPDIR", "DBFILE"},
              new String[] {
                FileUtil.getCanonicalFile(persistenceStatus.persistentTempDir()).toString()
                    + File.separator,
                persistenceStatus.databasePath()
              }));
  }

  private void writeError(
      String header,
      String message,
      ToadletContext context,
      boolean returnToQueuePage,
      boolean returnToInsertPage)
      throws ToadletContextClosedException, IOException {
    PageMaker pageMaker = context.getPageMaker();
    PageNode page = pageMaker.getPageNode(header, context);
    HTMLNode contentNode = page.getContentNode();
    if (context.isAllowedFullAccess())
      contentNode.addChild(context.getAlertManager().createSummary());
    HTMLNode infoboxContent =
        pageMaker.getInfobox(INFOBOX_ERROR, header, contentNode, "queue-error", false);
    infoboxContent.addChild("#", message);
    if (returnToQueuePage)
      NodeL10n.getBase()
          .addL10nSubstitution(
              infoboxContent.addChild("div"),
              QUEUE_TOADLET_PREFIX + "returnToQueuePage",
              new String[] {"link"},
              new HTMLNode[] {HTMLNode.link(path())});
    else if (returnToInsertPage)
      NodeL10n.getBase()
          .addL10nSubstitution(
              infoboxContent.addChild("div"),
              QUEUE_TOADLET_PREFIX + "tryAgainUploadFilePage",
              new String[] {"link"},
              new HTMLNode[] {HTMLNode.link(FileInsertWizardToadlet.PATH)});
    writeHTMLReply(context, 400, "Bad request", page.generate());
  }

  /**
   * Handles GET requests for the queue page and auxiliary endpoints.
   *
   * <p>The method enforces public-gateway restrictions, determines the requested intent (full HTML
   * view, count-only view, or key list export), and either renders synchronously or schedules
   * background work to assemble results. When intent requires background computation, the method
   * waits for the job result and writes the response in the same HTTP request cycle. Errors related
   * to persistence or disabled FCP are mapped to user-friendly pages instead of propagating raw
   * exceptions.
   *
   * @param uri request URI used to compute paths and redirects.
   * @param request parsed request with query parameters and path suffixes.
   * @param ctx toadlet context providing permissions, localization, and replies.
   * @throws ToadletContextClosedException if the client disconnects or the context closes while
   *     sending the response.
   * @throws IOException if an I/O error occurs while reading request data or writing the reply.
   * @throws RedirectException if the request should be redirected to a different path.
   */
  @Override
  public void handleMethodGET(URI uri, final HTTPRequest request, final ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {

    if (!queueSupportPort.isQueueBackendEnabled()) {
      writeError(l10n("fcpIsMissing"), l10n("pleaseEnableFCP"), ctx, false, false);
      return;
    }

    if (container.publicGatewayMode() && !ctx.isAllowedFullAccess()) {
      sendUnauthorizedPage(ctx);
      return;
    }

    try {
      RequestIntent intent = parseRequestIntent(request);
      switch (intent) {
        case NORMAL ->
            writeQueueSnapshot(
                ctx,
                queuePagePort.renderPage(
                    new QueuePageRequest(
                        uploads,
                        ctx.getPageMaker().advancedMode(request, this.container),
                        request.isParameterSet(SORT_BY) ? request.getParam(SORT_BY) : null,
                        request.isParameterSet("reversed"))));
        case COUNT -> writeQueueSnapshot(ctx, queuePagePort.renderCountPage(uploads));
        case KEY_LIST ->
            this.writeReply(
                ctx,
                ReplyHeaders.of(200, "OK", "text/plain"),
                queuePagePort.renderKeyList(uploads));
      }
    } catch (RequestQueueUnavailableException _) {
      sendPersistenceDisabledError(ctx);
    }
  }

  private void writeQueueSnapshot(ToadletContext ctx, QueuePageSnapshot snapshot)
      throws ToadletContextClosedException, IOException {
    PageNode page = ctx.getPageMaker().getPageNode(snapshot.pageTitle(), ctx);
    page.getContentNode()
        .addChild("%", injectRuntimePlaceholders(snapshot.contentHtmlTemplate(), ctx));
    writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private String injectRuntimePlaceholders(String contentHtmlTemplate, ToadletContext ctx) {
    return contentHtmlTemplate
        .replace(ALERT_SUMMARY_PLACEHOLDER, renderAlertSummary(ctx))
        .replace(FORM_PASSWORD_PLACEHOLDER, renderFormPasswordInput(ctx))
        .replace(PANIC_BOX_PLACEHOLDER, renderPanicBox(ctx));
  }

  private String renderAlertSummary(ToadletContext ctx) {
    if (!ctx.isAllowedFullAccess()) {
      return "";
    }
    return ctx.getAlertManager().createSummary().generate();
  }

  private String renderFormPasswordInput(ToadletContext ctx) {
    return new HTMLNode(
            TAG_INPUT,
            new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
            new String[] {INPUT_TYPE_HIDDEN, "formPassword", ctx.getFormPassword()})
        .generate();
  }

  private String renderPanicBox(ToadletContext ctx) {
    if (!SimpleToadletServer.isPanicButtonToBeShown) {
      return "";
    }
    return createPanicBox(ctx.getPageMaker(), ctx).generate();
  }

  private RequestIntent parseRequestIntent(final HTTPRequest request) {
    String requestPath = request.getPath().substring(path().length());
    return switch (requestPath) {
      case "countRequests.html", "/countRequests.html" -> RequestIntent.COUNT;
      case KEY_LIST_LOCATION -> RequestIntent.KEY_LIST;
      default -> RequestIntent.NORMAL;
    };
  }

  private enum RequestIntent {
    NORMAL,
    COUNT,
    KEY_LIST
  }

  private HTMLNode createPanicBox(PageMaker pageMaker, ToadletContext ctx) {
    InfoboxNode infobox =
        pageMaker.getInfobox("infobox-alert", l10n("panicButtonTitle"), "panic-button", true);
    HTMLNode panicBox = infobox.getOuterNode();
    HTMLNode panicForm = ctx.addFormChild(infobox.getContentNode(), path(), "queuePanicForm");
    panicForm.addChild(
        "#",
        (SimpleToadletServer.noConfirmPanic
                ? l10n("panicButtonNoConfirmation")
                : l10n("panicButtonWithConfirmation"))
            + ' ');
    panicForm.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {INPUT_TYPE_SUBMIT, PANIC, l10n("panicButton")});
    return panicBox;
  }

  static String l10n(String key) {
    return NodeL10n.getBase().getString(QUEUE_TOADLET_PREFIX + key);
  }

  static String l10n(String key, String pattern, String value) {
    return NodeL10n.getBase().getString(QUEUE_TOADLET_PREFIX + key, pattern, value);
  }

  static String l10n(String key, String[] pattern, String[] value) {
    return NodeL10n.getBase().getString(QUEUE_TOADLET_PREFIX + key, pattern, value);
  }

  /**
   * Reports whether the queue toadlet is enabled for the current request context.
   *
   * <p>The queue UI is available when the node is not operating in public-gateway mode or when the
   * caller has full access permissions in the provided context. The check is intentionally
   * conservative and does not attempt to infer permissions from other request attributes. Callers
   * should pass the same context used for rendering to keep enablement decisions consistent.
   *
   * @param ctx context used to evaluate permissions; may be {@code null}.
   * @return {@code true} when the queue UI should be exposed to callers.
   */
  @Override
  public boolean isEnabled(ToadletContext ctx) {
    return !container.publicGatewayMode() || (ctx != null && ctx.isAllowedFullAccess());
  }

  private static final String DEFAULT_UPLOADS_SEGMENT = "uploads";

  static final String PATH_UPLOADS =
      normalizePath(System.getProperty("queue.uploads.path", DEFAULT_UPLOADS_SEGMENT));
  static final String PATH_DOWNLOADS = LegacyHttpPaths.DOWNLOADS_PATH;

  /**
   * Returns the base path used by this toadlet to serve queue content.
   *
   * <p>The path is selected at construction time based on whether the instance is bound to uploads
   * or downloads, and it always includes leading and trailing slashes. The value is stable for the
   * lifetime of the instance and is used to build redirect targets and relative links.
   *
   * @return normalized base path with leading and trailing slashes.
   */
  @Override
  public String path() {
    if (uploads) return PATH_UPLOADS;
    else return PATH_DOWNLOADS;
  }

  private static String normalizePath(String rawPath) {
    String normalized = rawPath;
    if (!normalized.startsWith("/")) {
      normalized = '/' + normalized;
    }
    if (!normalized.endsWith("/")) {
      normalized = normalized + '/';
    }
    return normalized;
  }
}
