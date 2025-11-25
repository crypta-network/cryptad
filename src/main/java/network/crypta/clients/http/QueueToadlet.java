package network.crypta.clients.http;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.HighLevelSimpleClientImpl;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.MetadataUnresolvedException;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.PersistentJob;
import network.crypta.client.async.TooManyFilesInsertException;
import network.crypta.client.filter.ContentFilter;
import network.crypta.client.filter.FilterMIMEType;
import network.crypta.client.filter.KnownUnsafeContentTypeException;
import network.crypta.clients.fcp.ClientGet;
import network.crypta.clients.fcp.ClientPut;
import network.crypta.clients.fcp.ClientPut.COMPRESS_STATE;
import network.crypta.clients.fcp.ClientPutBase.UploadFrom;
import network.crypta.clients.fcp.ClientPutDir;
import network.crypta.clients.fcp.ClientRequest;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.clients.fcp.DownloadRequestStatus;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.IdentifierCollisionException;
import network.crypta.clients.fcp.NotAllowedException;
import network.crypta.clients.fcp.RequestCompletionCallback;
import network.crypta.clients.fcp.RequestStatus;
import network.crypta.clients.fcp.UploadDirRequestStatus;
import network.crypta.clients.fcp.UploadFileRequestStatus;
import network.crypta.clients.fcp.UploadRequestStatus;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestStarter;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.node.useralerts.StoringUserEvent;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.support.Fields;
import network.crypta.support.HTMLNode;
import network.crypta.support.HexUtil;
import network.crypta.support.MultiValueTable;
import network.crypta.support.SizeUtil;
import network.crypta.support.TimeUtil;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.api.HTTPUploadedFile;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class QueueToadlet extends Toadlet
    implements RequestCompletionCallback, LinkEnabledCallback {
  private static final Logger LOG = LoggerFactory.getLogger(QueueToadlet.class);

  public enum QueueColumn {
    IDENTIFIER,
    SIZE,
    MIME_TYPE,
    PERSISTENCE,
    KEY,
    FILENAME,
    PRIORITY,
    FILES,
    TOTAL_SIZE,
    PROGRESS,
    REASON,
    LAST_ACTIVITY,
    LAST_FAILURE,
    COMPAT_MODE
  }

  private enum QueueType {
    COMPLETED_DOWNLOAD_TO_TEMP(true, false, false),
    COMPLETED_DOWNLOAD_TO_DISK(true, false, false),
    COMPLETED_UPLOAD(true, false, true),
    COMPLETED_DIR_UPLOAD(true, false, true),
    FAILED_DOWNLOAD(false, true, false),
    FAILED_UPLOAD(false, true, true),
    FAILED_DIR_UPLOAD(false, true, true),
    FAILED_BAD_MIME_TYPE(false, true, false),
    FAILED_UNKNOWN_MIME_TYPE(false, true, false),
    UNCOMPLETED_DOWNLOAD(false, false, false),
    UNCOMPLETED_UPLOAD(false, false, true),
    UNCOMPLETED_DIR_UPLOAD(false, false, true);

    final boolean isCompleted;
    final boolean isFailed;
    final boolean isUpload;

    QueueType(boolean isCompleted, boolean isFailed, boolean isUpload) {
      this.isCompleted = isCompleted;
      this.isFailed = isFailed;
      this.isUpload = isUpload;
    }
  }

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
  private static final String ERROR_SAME_FILE_MESSAGE =
      "Cannot put same file twice in same millisecond";
  private static final String ERROR_ACCESS_DENIED_FILE_KEY = "errorAccessDeniedFile";
  private static final String ERROR_NO_FILE_OR_CANNOT_READ = "errorNoFileOrCannotRead";

  private final NodeClientCore core;
  final FCPServer fcp;
  private FileInsertWizardToadlet fiw;

  // Legacy threshold callback removed.

  void setFIW(FileInsertWizardToadlet fiw) {
    this.fiw = fiw;
  }

  private boolean isReversed = false;
  private final boolean uploads;

  private static final String KEY_LIST_LOCATION = "listKeys.txt";
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
  private static final String ATTR_STYLE = "style";
  private static final String ATTR_TITLE = "title";
  private static final String TAG_LABEL = "label";
  private static final String TAG_TABLE = "table";
  private static final String INPUT_TYPE_HIDDEN = "hidden";
  private static final String INFOBOX_INFORMATION = "infobox-information";
  private static final String INFOBOX_ERROR = "infobox-error";
  private static final String PRIORITY = "priority";
  private static final String STATUS_FAILED_UPLOAD = "failedU";
  private static final String COMPLETED_REQUESTS = "completed_requests";
  private static final String FAILED_REQUESTS = "failed_requests";
  private static final String REQUESTS_IN_PROGRESS = "requests_in_progress";
  private static final String UNKNOWN = "unknown";
  private static final String CSS_WIDTH_PREFIX = "width: ";
  private static final String BULK_DOWNLOAD_SELECT_OPTION_DISK = "bulkDownloadSelectOptionDisk";
  private static final String BULK_DOWNLOAD_SELECT_OPTION_DIRECT = "bulkDownloadSelectOptionDirect";
  private static final String FILTER_DATA_MESSAGE = "filterDataMessage";
  private static final String INSERT_CONTEXT_COMPATIBILITY_MODE_PREFIX =
      "InsertContext.CompatibilityMode.";
  private static final String COMPLETED_LIST_PREFIX = "completed.list.";
  private static final String NO_URI_FOR_FINISHED_REQUEST =
      "No URI for supposedly finished request {}";
  private static final String QUEUE_TOADLET_PREFIX = "QueueToadlet.";
  private static final String USER_ALERT_HIDE = "UserAlert.hide";

  public QueueToadlet(
      NodeClientCore core, FCPServer fcp, HighLevelSimpleClient client, boolean uploads) {
    super(client);
    this.core = core;
    this.fcp = fcp;
    this.uploads = uploads;
    if (fcp == null) throw new NullPointerException();
    fcp.setCompletionCallback(this);
    try {
      loadCompletedIdentifiers();
    } catch (PersistenceDisabledException e) {
      // The user will know soon enoughUpdate Toadlet.java
    }
  }

  public void handleMethodPOST(URI uri, HTTPRequest request, final ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {

    if (container.publicGatewayMode() && !ctx.isAllowedFullAccess()) {
      sendUnauthorizedPage(ctx);
      return;
    }

    try {
      CheckedHandler[] handlers = {
        () -> handleInsertLocal(request, ctx),
        () -> handleSelectLocation(request, ctx),
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
          return;
        }
      }
    } finally {
      request.freeParts();
    }
    this.handleMethodGET(uri, new HTTPRequestImpl(uri, "GET"), ctx);
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
    if ("CHK".equals(keyType)) {
      insertURI = new FreenetURI("CHK@");
      if (fiw != null) fiw.reportCanonicalInsert();
    } else if ("SSK".equals(keyType)) {
      insertURI = new FreenetURI("SSK@");
      if (fiw != null) fiw.reportRandomInsert();
    } else if ("specify".equals(keyType)) {
      try {
        String u = request.getPartAsStringFailsafe("key", MAX_KEY_LENGTH);
        insertURI = new FreenetURI(u);
        if (LOG.isDebugEnabled()) LOG.debug("Inserting key: {} ({})", insertURI, u);
      } catch (MalformedURLException mue1) {
        writeError(l10n(ERROR_INVALID_URI), l10n(ERROR_INVALID_URI_TO_U), ctx, false, true);
        return true;
      }
    } else {
      writeError(
          l10n("errorMustSpecifyKeyTypeTitle"), l10n("errorMustSpecifyKeyType"), ctx, false, true);
      return true;
    }
    MultiValueTable<String, String> responseHeaders =
        MultiValueTable.from(
            "Location",
            LocalFileInsertToadlet.PATH
                + "?key="
                + insertURI.toASCIIString()
                + "&"
                + COMPRESS_FIELD
                + "="
                + (!(request.getPartAsStringFailsafe(COMPRESS_FIELD, 128).isEmpty()))
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

  private boolean handleSelectLocation(HTTPRequest request, ToadletContext ctx)
      throws RedirectException {
    if (!request.isPartSet("select-location")) {
      return false;
    }
    try {
      throw new RedirectException(LocalDirectoryToadlet.basePath() + PATH_DOWNLOADS);
    } catch (URISyntaxException e) {
      // Shouldn't happen, path is defined as such.
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
                "infobox-warning", l10n("confirmDeleteTitle"), inner, "confirm-delete-title", true);

    HTMLNode deleteNode = new HTMLNode("p");
    HTMLNode deleteForm = ctx.addFormChild(deleteNode, path(), "queueDeleteForm");
    HTMLNode infoList = deleteForm.addChild("ul");

    populateDeleteInfoList(request, infoList);
    content.addChild("p", l10n("confirmDelete"));
    content.addChild(deleteNode);
    addDeleteFormButtons(deleteForm);

    this.writeHTMLReply(ctx, 200, "OK", page.generate());
    return true;
  }

  private void populateDeleteInfoList(HTTPRequest request, HTMLNode infoList) {
    for (String part : request.getParts()) {
      if (!part.startsWith(IDENTIFIER_PREFIX)) continue;
      part = part.substring(IDENTIFIER_PREFIX.length());
      if (part.length() > 50) continue;

      String identifier =
          request.getPartAsStringFailsafe(IDENTIFIER_PREFIX + part, MAX_IDENTIFIER_LENGTH);
      if (identifier == null) continue;
      String filename =
          request.getPartAsStringFailsafe(FILENAME_PREFIX + part, MAX_FILENAME_LENGTH);
      String keyString = request.getPartAsStringFailsafe(KEY_PREFIX + part, MAX_KEY_LENGTH);
      String type = request.getPartAsStringFailsafe("type-" + part, MAX_TYPE_LENGTH);
      String size = request.getPartAsStringFailsafe("size-" + part, 50);
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
          new String[] {INPUT_TYPE_CHECKBOX, IDENTIFIER_PREFIX + part, identifier, ATTR_CHECKED});
    }
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

    String identifier = "";
    try {
      for (String part : request.getParts()) {
        if (!part.startsWith(IDENTIFIER_PREFIX)) continue;
        identifier = part.substring(IDENTIFIER_PREFIX.length());
        if (identifier.length() > 50) continue;
        identifier = request.getPartAsStringFailsafe(part, MAX_IDENTIFIER_LENGTH);
        if (LOG.isDebugEnabled()) LOG.debug("Removing {}", identifier);
        fcp.removeGlobalRequestBlocking(identifier);
      }
    } catch (PersistenceDisabledException e) {
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
    String identifier = "";
    try {
      RequestStatus[] reqs = fcp.getGlobalRequests();
      for (RequestStatus r : reqs) {
        if (r instanceof UploadFileRequestStatus upload) {
          if (upload.hasSucceeded()) {
            identifier = upload.getIdentifier();
            fcp.removeGlobalRequestBlocking(identifier);
          }
        }
      }
    } catch (PersistenceDisabledException e) {
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
    String identifier = "";
    try {
      RequestStatus[] reqs = fcp.getGlobalRequests();
      for (RequestStatus r : reqs) {
        if (r instanceof DownloadRequestStatus download) {
          if (download.isPersistent()
              && download.hasSucceeded()
              && download.isTotalFinalized()
              && !download.toTempSpace()) {
            identifier = download.getIdentifier();
            fcp.removeGlobalRequestBlocking(identifier);
          }
        }
      }
    } catch (PersistenceDisabledException e) {
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

    String identifier = "";
    for (String part : request.getParts()) {
      if (!part.startsWith(IDENTIFIER_PREFIX)) continue;
      identifier = part.substring(IDENTIFIER_PREFIX.length());
      if (identifier.length() > 50) continue;
      identifier = request.getPartAsStringFailsafe(part, MAX_IDENTIFIER_LENGTH);
      if (LOG.isDebugEnabled()) LOG.debug("Restarting {}", identifier);
      try {
        fcp.restartBlocking(identifier, disableFilterData);
      } catch (PersistenceDisabledException e) {
        sendPersistenceDisabledError(ctx);
        return true;
      }
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
      core.getNode().killMasterKeysFile();
      core.getNode().panic();
      sendPanicingPage(ctx);
      core.getNode().finishPanic();
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
    core.getNode().killMasterKeysFile();
    core.getNode().panic();
    sendPanicingPage(ctx);
    core.getNode().finishPanic();
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
    FreenetURI fetchURI;
    try {
      fetchURI = new FreenetURI(request.getPartAsStringFailsafe("key", MAX_KEY_LENGTH));
    } catch (MalformedURLException e) {
      writeError(l10n(ERROR_INVALID_URI), l10n(ERROR_INVALID_URI_TO_D), ctx);
      return true;
    }
    String persistence = request.getPartAsStringFailsafe("persistence", 32);
    String returnType = request.getPartAsStringFailsafe("return-type", 32);
    boolean filterData = request.isPartSet(FILTER_DATA);
    String downloadPath;
    File downloadsDir = null;
    if (request.isPartSet("path") && !FProxyToadlet.isDownloadDisabledOrUnsafe(ctx, core)) {
      downloadPath = request.getPartAsStringFailsafe("path", MAX_FILENAME_LENGTH);
      try {
        downloadsDir = getDownloadsDir(downloadPath);
      } catch (NotAllowedException e) {
        downloadDisallowedPage(e, downloadPath, ctx);
        return true;
      }
    } else {
      returnType = RETURN_TYPE_DIRECT;
    }
    try {
      fcp.makePersistentGlobalRequestBlocking(
          fetchURI, filterData, expectedMIMEType, persistence, returnType, false, downloadsDir);
    } catch (NotAllowedException e) {
      this.writeError(l10n("errorDToDisk"), l10n("errorDToDiskConfig"), ctx);
      return true;
    } catch (PersistenceDisabledException e) {
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
    if (keys == null || keys.length == 0) {
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
      return null;
    }
    return keys;
  }

  private DownloadTarget resolveDownloadTarget(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    String target = request.getPartAsStringFailsafe(TARGET, 128);
    if (target == null) target = RETURN_TYPE_DIRECT;

    if (!request.isPartSet("path") || FProxyToadlet.isDownloadDisabledOrUnsafe(ctx, core)) {
      return new DownloadTarget(target, null);
    }

    String downloadPath = request.getPartAsStringFailsafe("path", MAX_FILENAME_LENGTH);
    try {
      return new DownloadTarget(target, getDownloadsDir(downloadPath));
    } catch (NotAllowedException e) {
      downloadDisallowedPage(e, downloadPath, ctx);
      return null;
    }
  }

  private BulkDownloadResult enqueueBulkDownloads(
      String[] keys, boolean filterData, DownloadTarget downloadTarget) {
    LinkedList<String> success = new LinkedList<>();
    LinkedList<String> failure = new LinkedList<>();

    for (int i = 0; i < keys.length; i++) {
      String currentKey = keys[i].trim();
      if (currentKey.isEmpty()) {
        continue;
      }

      try {
        FreenetURI fetchURI = new FreenetURI(currentKey);
        fcp.makePersistentGlobalRequestBlocking(
            fetchURI,
            filterData,
            null,
            "forever",
            downloadTarget.target(),
            false,
            downloadTarget.downloadsDir());
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

  private record DownloadTarget(String target, File downloadsDir) {}

  private record BulkDownloadResult(List<String> success, List<String> failure) {}

  private record InsertUploadContext(
      FreenetURI insertURI,
      HTTPUploadedFile file,
      boolean compress,
      String identifier,
      CompatibilityMode cmode,
      byte[] overrideSplitfileKey,
      String filenameForKey) {}

  private record LocalFileInsertParams(
      File file,
      String id,
      String contentType,
      FreenetURI uri,
      boolean compress,
      CompatibilityMode cmode,
      byte[] overrideSplitfileKey,
      String target) {}

  private record LocalDirInsertParams(
      File file,
      String identifier,
      FreenetURI uri,
      boolean compress,
      byte[] overrideSplitfileKey) {}

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

    final RandomAccessBucket copiedBucket = copyUploadedFile(params.file());
    final CountDownLatch done = new CountDownLatch(1);

    if (!queueInsertUpload(params, copiedBucket, done, ctx)) {
      return true;
    }

    awaitInsertCompletion(done);
    return true;
  }

  private InsertUploadContext parseInsertUploadRequest(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    String keyType = request.getPartAsStringFailsafe("keytype", 10);
    FreenetURI insertURI = parseInsertURI(keyType, request, ctx);
    if (insertURI == null) {
      return null;
    }

    HTTPUploadedFile file = request.getUploadedFile(FILENAME);
    if (file == null || file.getFilename().trim().isEmpty()) {
      writeError(l10n("errorNoFileSelected"), l10n("errorNoFileSelectedU"), ctx, false, true);
      return null;
    }

    boolean compress = !request.getPartAsStringFailsafe(COMPRESS_FIELD, 128).isEmpty();
    String identifier = file.getFilename() + FRED_SUFFIX + System.currentTimeMillis();
    CompatibilityMode cmode = parseCompatibilityMode(request);
    byte[] overrideSplitfileKey = parseOverrideSplitfileKey(request);
    String filenameForKey =
        insertURI.getKeyType().equals("CHK") || "SSK".equals(keyType) ? file.getFilename() : null;

    return new InsertUploadContext(
        insertURI, file, compress, identifier, cmode, overrideSplitfileKey, filenameForKey);
  }

  private FreenetURI parseInsertURI(String keyType, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    try {
      if ("CHK".equals(keyType)) {
        if (fiw != null) fiw.reportCanonicalInsert();
        return new FreenetURI("CHK@");
      }
      if ("SSK".equals(keyType)) {
        if (fiw != null) fiw.reportRandomInsert();
        return new FreenetURI("SSK@");
      }
      if ("specify".equals(keyType)) {
        String uri = request.getPartAsStringFailsafe("key", MAX_KEY_LENGTH);
        FreenetURI insertURI = new FreenetURI(uri);
        if (LOG.isDebugEnabled()) LOG.debug("Inserting key: {} ({})", insertURI, uri);
        return insertURI;
      }
      writeError(
          l10n("errorMustSpecifyKeyTypeTitle"), l10n("errorMustSpecifyKeyType"), ctx, false, true);
      return null;
    } catch (MalformedURLException e) {
      writeError(l10n(ERROR_INVALID_URI), l10n(ERROR_INVALID_URI_TO_U), ctx, false, true);
      return null;
    }
  }

  private CompatibilityMode parseCompatibilityMode(HTTPRequest request) {
    String compatibilityMode = request.getPartAsStringFailsafe(COMPATIBILITY_MODE_FIELD, 100);
    if (compatibilityMode.isEmpty()) {
      return CompatibilityMode.COMPAT_DEFAULT.intern();
    }
    return CompatibilityMode.valueOf(compatibilityMode).intern();
  }

  private byte[] parseOverrideSplitfileKey(HTTPRequest request) {
    String rawKey = request.getPartAsStringFailsafe(OVERRIDE_SPLITFILE_KEY_FIELD, 65);
    if (rawKey != null && !rawKey.isEmpty()) {
      return HexUtil.hexToBytes(rawKey);
    }
    return null;
  }

  private RandomAccessBucket copyUploadedFile(HTTPUploadedFile file) throws IOException {
    RandomAccessBucket copiedBucket =
        core.getPersistentTempBucketFactory().makeBucket(file.getData().size());
    BucketTools.copy(file.getData(), copiedBucket);
    return copiedBucket;
  }

  private boolean queueInsertUpload(
      InsertUploadContext params,
      RandomAccessBucket copiedBucket,
      CountDownLatch done,
      ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    try {
      core.getClientLayerPersister()
          .queue(
              new PersistentJob() {

                @Override
                public String toString() {
                  return "QueueToadlet StartInsert";
                }

                @Override
                public boolean run(ClientContext context) {
                  try {
                    return runInsertUploadJob(params, copiedBucket, ctx);
                  } catch (IOException | ToadletContextClosedException e) {
                    return false;
                  } finally {
                    done.countDown();
                  }
                }
              },
              NativeThread.PriorityLevel.HIGH_PRIORITY.value + 1);
      return true;
    } catch (PersistenceDisabledException e) {
      sendPersistenceDisabledError(ctx);
      return false;
    }
  }

  private boolean runInsertUploadJob(
      InsertUploadContext params, RandomAccessBucket copiedBucket, ToadletContext ctx)
      throws IOException, ToadletContextClosedException {
    try {
      ClientPut clientPut = buildClientPut(params, copiedBucket);
      if (clientPut != null && !startClientPut(clientPut, ctx)) {
        return false;
      }
      writePermanentRedirect(ctx, "Done", path());
      return true;
    } catch (IdentifierCollisionException e) {
      LOG.error(ERROR_SAME_FILE_MESSAGE);
      writePermanentRedirect(ctx, "Done", path());
      return false;
    } catch (NotAllowedException e) {
      writeError(
          l10n("errorAccessDenied"),
          l10n(ERROR_ACCESS_DENIED_FILE_KEY, "file", params.file().getFilename()),
          ctx,
          false,
          true);
      return false;
    } catch (FileNotFoundException e) {
      writeError(
          l10n(ERROR_NO_FILE_OR_CANNOT_READ),
          l10n(ERROR_ACCESS_DENIED_FILE_KEY, "file", params.file().getFilename()),
          ctx,
          false,
          true);
      return false;
    } catch (MalformedURLException e) {
      writeError(l10n(ERROR_INVALID_URI), l10n(ERROR_INVALID_URI_TO_U), ctx, false, true);
      return false;
    } catch (MetadataUnresolvedException e) {
      LOG.error("Unresolved metadata in starting insert from data uploaded from browser: {}", e, e);
      writePermanentRedirect(ctx, "Done", path());
      return false;
    } catch (Throwable t) {
      writeInternalError(t, ctx);
      return false;
    }
  }

  private ClientPut buildClientPut(InsertUploadContext params, RandomAccessBucket copiedBucket)
      throws MalformedURLException,
          NotAllowedException,
          FileNotFoundException,
          MetadataUnresolvedException,
          IdentifierCollisionException,
          IOException {
    return new ClientPut(
        fcp.getGlobalForeverClient(),
        params.insertURI(),
        params.identifier(),
        Integer.MAX_VALUE,
        null,
        RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS,
        Persistence.FOREVER,
        null,
        false,
        !params.compress(),
        -1,
        UploadFrom.DIRECT,
        null,
        params.file().getContentType(),
        copiedBucket,
        null,
        params.filenameForKey(),
        false,
        false,
        Node.FORK_ON_CACHEABLE_DEFAULT,
        HighLevelSimpleClientImpl.EXTRA_INSERTS_SINGLE_BLOCK,
        HighLevelSimpleClientImpl.EXTRA_INSERTS_SPLITFILE_HEADER,
        false,
        params.cmode(),
        params.overrideSplitfileKey(),
        false,
        fcp.getCore());
  }

  private boolean startClientPut(ClientPut clientPut, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    try {
      fcp.startBlocking(clientPut);
      return true;
    } catch (IdentifierCollisionException e) {
      LOG.error(ERROR_SAME_FILE_MESSAGE);
      writePermanentRedirect(ctx, "Done", path());
      return false;
    } catch (PersistenceDisabledException e) {
      // Impossible???
      return true;
    }
  }

  private void awaitInsertCompletion(CountDownLatch done) {
    while (done.getCount() > 0) {
      try {
        done.await();
      } catch (InterruptedException ignored) {
        // Ignore
      }
    }
  }

  private boolean handleLocalFileSelection(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!request.isPartSet(LocalFileBrowserToadlet.selectFile)) {
      return false;
    }

    LocalFileInsertParams params = parseLocalFileParams(request, ctx);
    if (params == null) {
      return true;
    }

    CountDownLatch done = new CountDownLatch(1);
    if (!queueLocalFileInsert(params, done, ctx)) {
      return true;
    }

    awaitInsertCompletion(done);
    return true;
  }

  private LocalFileInsertParams parseLocalFileParams(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    String filename = request.getPartAsStringFailsafe(FILENAME, MAX_FILENAME_LENGTH);
    if (LOG.isDebugEnabled()) LOG.debug("Inserting local file: {}", filename);

    File file = new File(filename);
    String identifier = file.getName() + FRED_SUFFIX + System.currentTimeMillis();
    String contentType = DefaultMIMETypes.guessMIMEType(filename, false);
    String key = request.getPartAsStringFailsafe("key", MAX_KEY_LENGTH);
    boolean compress = request.isPartSet(COMPRESS_FIELD);
    CompatibilityMode cmode = parseCompatibilityMode(request);
    byte[] overrideSplitfileKey = parseOverrideSplitfileKey(request);
    FreenetURI furi;
    if (key != null) {
      try {
        furi = new FreenetURI(key);
      } catch (MalformedURLException e) {
        writeError(l10n(ERROR_INVALID_URI), l10n(ERROR_INVALID_URI_TO_U), ctx);
        return null;
      }
    } else {
      furi = new FreenetURI("CHK@");
    }

    String target = (furi.getDocName() != null) ? null : file.getName();
    return new LocalFileInsertParams(
        file, identifier, contentType, furi, compress, cmode, overrideSplitfileKey, target);
  }

  private boolean queueLocalFileInsert(
      LocalFileInsertParams params, CountDownLatch done, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    try {
      core.getClientLayerPersister()
          .queue(
              createLocalFileInsertJob(params, done, ctx),
              NativeThread.PriorityLevel.HIGH_PRIORITY.value + 1);
      return true;
    } catch (PersistenceDisabledException e) {
      sendPersistenceDisabledError(ctx);
      return false;
    }
  }

  private PersistentJob createLocalFileInsertJob(
      LocalFileInsertParams params, CountDownLatch done, ToadletContext ctx) {
    return new PersistentJob() {

      @Override
      public String toString() {
        return "QueueToadlet StartLocalFileInsert";
      }

      @Override
      public boolean run(ClientContext context) {
        try {
          return startLocalFileInsert(params, ctx);
        } catch (IOException | ToadletContextClosedException e) {
          return false;
        } finally {
          done.countDown();
        }
      }
    };
  }

  private boolean startLocalFileInsert(LocalFileInsertParams params, ToadletContext ctx)
      throws IOException, ToadletContextClosedException {
    FileBucket bucket = new FileBucket(params.file(), true, false, false, false);
    boolean handedOff = false;
    try {
      ClientPut clientPut = createLocalFileClientPut(params, bucket);
      if (LOG.isDebugEnabled()) {
        LOG.debug("Started global request to insert {} to CHK@ as {}", params.file(), params.id());
      }
      if (clientPut != null) {
        try {
          fcp.startBlocking(clientPut);
          handedOff = true;
        } catch (IdentifierCollisionException e) {
          LOG.error(ERROR_SAME_FILE_MESSAGE);
          writePermanentRedirect(ctx, "Done", path());
          return false;
        } catch (PersistenceDisabledException e) {
          // Impossible???
        }
      }
      writePermanentRedirect(ctx, "Done", path());
      return true;
    } catch (IdentifierCollisionException e) {
      LOG.error(ERROR_SAME_FILE_MESSAGE);
      writePermanentRedirect(ctx, "Done", path());
      return false;
    } catch (MalformedURLException e) {
      writeError(l10n(ERROR_INVALID_URI), l10n(ERROR_INVALID_URI_TO_U), ctx);
      return false;
    } catch (FileNotFoundException e) {
      writeError(
          l10n(ERROR_NO_FILE_OR_CANNOT_READ),
          l10n(ERROR_ACCESS_DENIED_FILE_KEY, "file", params.target()),
          ctx);
      return false;
    } catch (NotAllowedException e) {
      writeError(
          l10n("errorAccessDenied"),
          l10n(
              ERROR_ACCESS_DENIED_FILE_KEY,
              new String[] {"file"},
              new String[] {params.file().getName()}),
          ctx);
      return false;
    } catch (MetadataUnresolvedException e) {
      LOG.error("Unresolved metadata in starting insert from data from file: {}", e, e);
      writePermanentRedirect(ctx, "Done", path());
      return false;
    } finally {
      if (!handedOff) {
        bucket.free();
      }
    }
  }

  private ClientPut createLocalFileClientPut(LocalFileInsertParams params, FileBucket bucket)
      throws MalformedURLException,
          NotAllowedException,
          FileNotFoundException,
          MetadataUnresolvedException,
          IdentifierCollisionException,
          IOException {
    return new ClientPut(
        fcp.getGlobalForeverClient(),
        params.uri(),
        params.id(),
        Integer.MAX_VALUE,
        null,
        RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS,
        Persistence.FOREVER,
        null,
        false,
        !params.compress(),
        -1,
        UploadFrom.DISK,
        params.file(),
        params.contentType(),
        bucket,
        null,
        params.target(),
        false,
        false,
        Node.FORK_ON_CACHEABLE_DEFAULT,
        HighLevelSimpleClientImpl.EXTRA_INSERTS_SINGLE_BLOCK,
        HighLevelSimpleClientImpl.EXTRA_INSERTS_SPLITFILE_HEADER,
        false,
        params.cmode(),
        params.overrideSplitfileKey(),
        false,
        fcp.getCore());
  }

  private boolean handleLocalDirSelection(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!request.isPartSet(LocalFileBrowserToadlet.selectDir)) {
      return false;
    }

    LocalDirInsertParams params = parseLocalDirParams(request, ctx);
    if (params == null) {
      return true;
    }

    CountDownLatch done = new CountDownLatch(1);
    if (!queueLocalDirInsert(params, done, ctx)) {
      return true;
    }

    awaitInsertCompletion(done);
    return true;
  }

  private LocalDirInsertParams parseLocalDirParams(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    String filename = request.getPartAsStringFailsafe(FILENAME, MAX_FILENAME_LENGTH);
    if (LOG.isDebugEnabled()) LOG.debug("Inserting local directory: {}", filename);

    File file = new File(filename);
    String identifier = file.getName() + FRED_SUFFIX + System.currentTimeMillis();
    String key = request.getPartAsStringFailsafe("key", MAX_KEY_LENGTH);
    boolean compress = request.isPartSet(COMPRESS_FIELD);
    byte[] overrideSplitfileKey = parseOverrideSplitfileKey(request);
    FreenetURI furi;
    if (key != null) {
      try {
        furi = new FreenetURI(key);
      } catch (MalformedURLException e) {
        writeError(l10n(ERROR_INVALID_URI), l10n(ERROR_INVALID_URI_TO_U), ctx);
        return null;
      }
    } else {
      furi = new FreenetURI("CHK@");
    }
    return new LocalDirInsertParams(file, identifier, furi, compress, overrideSplitfileKey);
  }

  private boolean queueLocalDirInsert(
      LocalDirInsertParams params, CountDownLatch done, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    try {
      core.getClientLayerPersister()
          .queue(
              createLocalDirInsertJob(params, done, ctx),
              NativeThread.PriorityLevel.HIGH_PRIORITY.value + 1);
      return true;
    } catch (PersistenceDisabledException e) {
      sendPersistenceDisabledError(ctx);
      return false;
    }
  }

  private PersistentJob createLocalDirInsertJob(
      LocalDirInsertParams params, CountDownLatch done, ToadletContext ctx) {
    return new PersistentJob() {

      @Override
      public String toString() {
        return "QueueToadlet StartLocalDirInsert";
      }

      @Override
      public boolean run(ClientContext context) {
        try {
          return startLocalDirInsert(params, ctx);
        } catch (IOException | ToadletContextClosedException e) {
          return false;
        } finally {
          done.countDown();
        }
      }
    };
  }

  private boolean startLocalDirInsert(LocalDirInsertParams params, ToadletContext ctx)
      throws IOException, ToadletContextClosedException {
    try {
      ClientPutDir clientPutDir = createLocalDirPut(params);
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Started global request to insert dir {} to {} as {}",
            params.file(),
            params.uri(),
            params.identifier());
      }
      if (clientPutDir != null) {
        try {
          fcp.startBlocking(clientPutDir);
        } catch (IdentifierCollisionException e) {
          LOG.error(ERROR_SAME_FILE_MESSAGE);
          writePermanentRedirect(ctx, "Done", path());
          return false;
        } catch (PersistenceDisabledException e) {
          sendPersistenceDisabledError(ctx);
          return false;
        }
      }
      writePermanentRedirect(ctx, "Done", path());
      return true;
    } catch (MalformedURLException e) {
      writeError(l10n(ERROR_INVALID_URI), l10n(ERROR_INVALID_URI_TO_U), ctx);
      return false;
    } catch (FileNotFoundException e) {
      writeError(
          l10n(ERROR_NO_FILE_OR_CANNOT_READ),
          l10n(ERROR_ACCESS_DENIED_FILE_KEY, "file", params.file().toString()),
          ctx);
      return false;
    } catch (TooManyFilesInsertException e) {
      writeError(l10n("tooManyFilesInOneFolder"), l10n("tooManyFilesInOneFolder"), ctx);
      return false;
    }
  }

  private ClientPutDir createLocalDirPut(LocalDirInsertParams params)
      throws IOException, TooManyFilesInsertException {
    return new ClientPutDir(
        fcp.getGlobalForeverClient(),
        params.uri(),
        params.identifier(),
        Integer.MAX_VALUE,
        RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS,
        Persistence.FOREVER,
        null,
        false,
        !params.compress(),
        -1,
        params.file(),
        null,
        false,
        false,
        true,
        false,
        false,
        Node.FORK_ON_CACHEABLE_DEFAULT,
        HighLevelSimpleClientImpl.EXTRA_INSERTS_SINGLE_BLOCK,
        HighLevelSimpleClientImpl.EXTRA_INSERTS_SPLITFILE_HEADER,
        false,
        params.overrideSplitfileKey(),
        fcp.getCore());
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
    index = addKeyInputs(request, form, identifierParts, index);

    form.addChild(TAG_LABEL, "for", "descB", (l10n("recommendDescription") + ' '));
    form.addChild("br");
    form.addChild(
        "textarea",
        new String[] {"id", "name", "row", "cols"},
        new String[] {"descB", "description", "3", "70"});
    form.addChild("br");
    if (core.getNode().isFProxyJavascriptEnabled()) {
      form.addChild(
          "script",
          new String[] {ATTR_TYPE, "src"},
          new String[] {"text/javascript", "/static/js/checkall.js"});
    }
    HTMLNode peerTable = form.addChild(TAG_TABLE, ATTR_CLASS, "darknet_connections");
    if (core.getNode().isFProxyJavascriptEnabled()) {
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
    for (DarknetPeerNode peer : core.getNode().getDarknetConnections()) {
      HTMLNode peerRow = peerTable.addChild("tr", ATTR_CLASS, "darknet_connections_normal");
      peerRow
          .addChild("td", ATTR_CLASS, "peer-marker")
          .addChild(
              TAG_INPUT,
              new String[] {ATTR_TYPE, ATTR_NAME},
              new String[] {INPUT_TYPE_CHECKBOX, "node_" + peer.hashCode()});
      peerRow.addChild("td", ATTR_CLASS, "peer-name").addChild("#", peer.getName());
    }

    form.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {INPUT_TYPE_SUBMIT, "recommend_uri", l10n("recommend")});

    this.writeHTMLReply(ctx, 200, "OK", page.generate());
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

  private int addKeyInputs(
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
    return index;
  }

  private boolean handleRecommendUri(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!request.isPartSet("recommend_uri")) {
      return false;
    }
    String description = request.getPartAsStringFailsafe("description", 32768);
    ArrayList<FreenetURI> uris = new ArrayList<>();
    for (String part : request.getParts()) {
      if (!part.startsWith(KEY_PREFIX)) continue;
      String key = request.getPartAsStringFailsafe(part, MAX_KEY_LENGTH);
      try {
        FreenetURI furi = new FreenetURI(key);
        uris.add(furi);
      } catch (MalformedURLException e) {
        writeError(l10n(ERROR_INVALID_URI), l10n(ERROR_INVALID_URI_TO_U), ctx);
        return true;
      }
    }

    for (DarknetPeerNode peer : core.getNode().getDarknetConnections()) {
      if (request.isPartSet("node_" + peer.hashCode())) {
        for (FreenetURI furi : uris) peer.sendDownloadFeed(furi, description);
      }
    }
    writePermanentRedirect(ctx, "Done", path());
    return true;
  }

  private void handleChangePriority(HTTPRequest request, ToadletContext ctx, String suffix)
      throws ToadletContextClosedException, IOException {
    short newPriority = Short.parseShort(request.getPartAsStringFailsafe(PRIORITY + suffix, 32));
    String identifier = "";
    for (String part : request.getParts()) {
      if (part.startsWith(IDENTIFIER_PREFIX)) {
        identifier = part.substring(IDENTIFIER_PREFIX.length());
        if (identifier.length() <= 50) {
          identifier = request.getPartAsStringFailsafe(part, MAX_IDENTIFIER_LENGTH);
          try {
            fcp.modifyGlobalRequestBlocking(identifier, null, newPriority);
          } catch (PersistenceDisabledException e) {
            sendPersistenceDisabledError(ctx);
            return;
          }
        }
      }
    }
    writePermanentRedirect(ctx, "Done", path());
  }

  private void downloadDisallowedPage(
      NotAllowedException e, String downloadPath, ToadletContext ctx)
      throws IOException, ToadletContextClosedException {
    PageNode page = ctx.getPageMaker().getPageNode(l10n(DOWNLOAD_FILES), ctx);
    HTMLNode contentNode = page.getContentNode();
    LOG.warn(e.toString());
    HTMLNode alert =
        ctx.getPageMaker()
            .getInfobox(
                "infobox-alert", l10n(DOWNLOAD_FILES), contentNode, GROUPED_DOWNLOADS, true);
    alert.addChild("ul", l10n("downloadDisallowed", "directory", downloadPath));
    alert.addChild("a", "href", path(), NodeL10n.getBase().getString("Toadlet.returnToQueuepage"));
    writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private File getDownloadsDir(String downloadPath) throws NotAllowedException {
    File downloadsDir = new File(downloadPath);
    // Invalid if it's disallowed, doesn't exist, isn't a directory, or can't be created.
    if (!core.allowDownloadTo(downloadsDir)
        || !((downloadsDir.exists() && downloadsDir.isDirectory()) || !downloadsDir.mkdirs())) {
      throw new NotAllowedException();
    }
    return downloadsDir;
  }

  private void sendPanicingPage(ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    writeHTMLReply(ctx, 200, "OK", WelcomeToadlet.sendRestartingPageInner(ctx).generate());
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

  private void sendPersistenceDisabledError(ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    String title = l10n("awaitingPasswordTitle" + (uploads ? "Uploads" : "Downloads"));
    if (core.getNode().awaitingPassword()) {
      PageNode page = ctx.getPageMaker().getPageNode(title, ctx);
      HTMLNode contentNode = page.getContentNode();

      HTMLNode infoboxContent =
          ctx.getPageMaker().getInfobox(INFOBOX_ERROR, title, contentNode, null, true);

      SecurityLevelsToadlet.generatePasswordFormPage(
          false, container, infoboxContent, false, false, false, null, path());

      addHomepageLink(infoboxContent);

      writeHTMLReply(ctx, 500, "Internal Server Error", page.generate());
      return;
    }
    if (core.getNode().isStopping())
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
                FileUtil.getCanonicalFile(core.getPersistentTempDir()).toString() + File.separator,
                core.getNode().getDatabasePath()
              }));
  }

  private void writeError(String header, String message, ToadletContext context)
      throws ToadletContextClosedException, IOException {
    writeError(header, message, context, true, false);
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

  public void handleMethodGET(URI uri, final HTTPRequest request, final ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {

    if (!fcp.isEnabled()) {
      writeError(l10n("fcpIsMissing"), l10n("pleaseEnableFCP"), ctx, false, false);
      return;
    }

    if (container.publicGatewayMode() && !ctx.isAllowedFullAccess()) {
      sendUnauthorizedPage(ctx);
      return;
    }

    RequestIntent intent = parseRequestIntent(request);
    PageMaker pageMaker = ctx.getPageMaker();

    if (intent == RequestIntent.NORMAL) {
      renderQueuePage(request, ctx, pageMaker);
      return;
    }

    OutputWrapper output = enqueueIntentJob(intent, ctx, pageMaker);
    if (output == null) {
      return; // error already handled
    }

    OutputWrapper result = waitForOutput(output);
    writeOutput(ctx, result);
  }

  private void renderQueuePage(HTTPRequest request, ToadletContext ctx, PageMaker pageMaker)
      throws ToadletContextClosedException, IOException {
    try {
      RequestStatus[] reqs = fcp.getGlobalRequests();
      HTMLNode pageNode = handleGetInner(pageMaker, reqs, request, ctx);
      writeHTMLReply(ctx, 200, "OK", new MultiValueTable<>(), pageNode.generate());
    } catch (PersistenceDisabledException e) {
      sendPersistenceDisabledError(ctx);
    }
  }

  private OutputWrapper enqueueIntentJob(
      RequestIntent intent, ToadletContext ctx, PageMaker pageMaker)
      throws ToadletContextClosedException, IOException {
    OutputWrapper ow = new OutputWrapper();
    boolean count = intent == RequestIntent.COUNT;
    try {
      core.getClientContext()
          .jobRunner
          .queue(
              new PersistentJob() {

                @Override
                public String toString() {
                  return "QueueToadlet ShowQueue";
                }

                @Override
                public boolean run(ClientContext context) {
                  HTMLNode pageNode = null;
                  String plainText = null;
                  try {
                    if (count) {
                      pageNode = buildCountPage(pageMaker, ctx);
                    } else {
                      plainText = buildKeysList(context);
                    }
                    return false;
                  } finally {
                    synchronized (ow) {
                      ow.done = true;
                      ow.pageNode = pageNode;
                      ow.plainText = plainText;
                      ow.notifyAll();
                    }
                  }
                }
                // Do not use maximal priority: There may be exceptional cases which have higher
                // priority than the UI, to get rid of excessive garbage for example.
              },
              NativeThread.PriorityLevel.HIGH_PRIORITY.value);
    } catch (PersistenceDisabledException e1) {
      sendPersistenceDisabledError(ctx);
      return null;
    }
    return ow;
  }

  private HTMLNode buildCountPage(PageMaker pageMaker, ToadletContext ctx) {
    long queued =
        core.getRequestStarters().chkFetchSchedulerBulk.countPersistentWaitingKeys()
            + core.getRequestStarters().chkFetchSchedulerRT.countPersistentWaitingKeys();
    LOG.debug("Total waiting CHKs: {}", queued);
    long reallyQueued =
        core.getRequestStarters().chkFetchSchedulerBulk.countQueuedRequests()
            + core.getRequestStarters().chkFetchSchedulerRT.countQueuedRequests();
    LOG.debug("Total queued CHK requests (including transient): {}", reallyQueued);
    PageNode page = pageMaker.getPageNode(l10n(ATTR_TITLE), ctx);
    HTMLNode pageNode = page.getOuterNode();
    HTMLNode contentNode = page.getContentNode();
    if (ctx.isAllowedFullAccess()) {
      contentNode.addChild(ctx.getAlertManager().createSummary());
    }
    HTMLNode infoboxContent =
        pageMaker.getInfobox(
            INFOBOX_INFORMATION, "Queued requests status", contentNode, null, false);
    infoboxContent.addChild("p", "Total awaiting CHKs: " + queued);
    infoboxContent.addChild("p", "Total queued CHK requests: " + reallyQueued);
    return pageNode;
  }

  private String buildKeysList(ClientContext context) {
    try {
      return makeKeysList(context, uploads);
    } catch (PersistenceDisabledException e) {
      return null;
    }
  }

  private OutputWrapper waitForOutput(OutputWrapper ow) {
    synchronized (ow) {
      while (!ow.done) {
        try {
          ow.wait();
        } catch (InterruptedException e) {
          // Ignore and continue waiting
        }
      }
      return ow;
    }
  }

  private void writeOutput(ToadletContext ctx, OutputWrapper result)
      throws ToadletContextClosedException, IOException {
    if (result.pageNode != null) {
      writeHTMLReply(ctx, 200, "OK", new MultiValueTable<>(), result.pageNode.generate());
    } else if (result.plainText != null) {
      this.writeReply(ctx, 200, "text/plain", "OK", result.plainText);
    } else if (core.killedDatabase()) {
      sendPersistenceDisabledError(ctx);
    } else {
      this.writeError("Internal error", "Internal error", ctx);
    }
  }

  private RequestIntent parseRequestIntent(final HTTPRequest request) {
    String requestPath = request.getPath().substring(path().length());
    if (requestPath.isEmpty()) {
      return RequestIntent.NORMAL;
    }
    if (requestPath.equals("countRequests.html") || requestPath.equals("/countRequests.html")) {
      return RequestIntent.COUNT;
    }
    if (requestPath.equals(KEY_LIST_LOCATION)) {
      return RequestIntent.KEY_LIST;
    }
    return RequestIntent.NORMAL;
  }

  private static final class OutputWrapper {
    boolean done;
    HTMLNode pageNode;
    String plainText;
  }

  private enum RequestIntent {
    NORMAL,
    COUNT,
    KEY_LIST
  }

  protected String makeKeysList(ClientContext context, boolean inserts)
      throws PersistenceDisabledException {
    RequestStatus[] reqs = fcp.getGlobalRequests();

    StringBuilder sb = new StringBuilder();

    for (RequestStatus req : reqs) {
      if (!inserts && req instanceof DownloadRequestStatus get) {
        FreenetURI uri = get.getURI();
        sb.append(uri.toString());
        sb.append("\n");
      } else if (inserts && req instanceof UploadRequestStatus put) {
        FreenetURI uri = put.getURI();
        if (uri != null) {
          sb.append(uri);
          sb.append("\n");
        }
      }
    }
    return sb.toString();
  }

  private HTMLNode handleGetInner(
      PageMaker pageMaker, RequestStatus[] reqs, final HTTPRequest request, ToadletContext ctx) {

    QueuePartitions partitions = partitionRequests(reqs);
    if (!partitions.hasAny()) {
      return sendEmptyQueuePage(ctx, pageMaker);
    }

    Comparator<RequestStatus> jobComparator = createJobComparator(request);
    sortPartitions(partitions, jobComparator);
    logTotals(partitions);

    String pageName = buildPageName(partitions);
    PageNode page = pageMaker.getPageNode(pageName, ctx);
    HTMLNode pageNode = page.getOuterNode();
    HTMLNode contentNode = page.getContentNode();

    addAlertSummary(contentNode, ctx);
    addNavigationBar(pageMaker, partitions, contentNode);

    String[] priorityClasses = buildPriorityClasses();
    boolean advancedModeEnabled = pageMaker.advancedMode(request, this.container);

    addLegend(pageMaker, partitions, contentNode, priorityClasses, advancedModeEnabled);
    addPanicBoxIfNeeded(pageMaker, ctx, contentNode);

    QueueColumn[] advancedModeFailure =
        new QueueColumn[] {
          QueueColumn.IDENTIFIER,
          QueueColumn.FILENAME,
          QueueColumn.SIZE,
          QueueColumn.MIME_TYPE,
          QueueColumn.PROGRESS,
          QueueColumn.REASON,
          QueueColumn.PERSISTENCE,
          QueueColumn.KEY
        };

    QueueColumn[] simpleModeFailure =
        new QueueColumn[] {
          QueueColumn.FILENAME,
          QueueColumn.SIZE,
          QueueColumn.PROGRESS,
          QueueColumn.REASON,
          QueueColumn.KEY
        };

    addCompletedSections(
        pageMaker, ctx, contentNode, partitions, priorityClasses, advancedModeEnabled);
    addFailureSections(
        pageMaker,
        ctx,
        contentNode,
        partitions,
        priorityClasses,
        advancedModeEnabled,
        advancedModeFailure,
        simpleModeFailure);
    addMimeFailureSections(
        pageMaker,
        ctx,
        contentNode,
        partitions,
        priorityClasses,
        advancedModeEnabled,
        jobComparator);
    addUncompletedSections(
        pageMaker, ctx, contentNode, partitions, priorityClasses, advancedModeEnabled);

    if (!uploads) {
      contentNode.addChild(createBulkDownloadForm(ctx, pageMaker));
    }

    return pageNode;
  }

  private void addLegend(
      PageMaker pageMaker,
      QueuePartitions partitions,
      HTMLNode contentNode,
      String[] priorityClasses,
      boolean advancedModeEnabled) {
    HTMLNode legendContent =
        pageMaker.getInfobox("legend", l10n("legend"), contentNode, "queue-legend", true);
    HTMLNode legendTable = legendContent.addChild(TAG_TABLE, ATTR_CLASS, "queue");
    HTMLNode legendRow = legendTable.addChild("tr");
    for (int i = 0; i < 7; i++) {
      if (i > RequestStarter.INTERACTIVE_PRIORITY_CLASS
          || advancedModeEnabled
          || i <= partitions.lowestQueuedPrio)
        legendRow.addChild("td", ATTR_CLASS, PRIORITY + i, priorityClasses[i]);
    }
  }

  private void addAlertSummary(HTMLNode contentNode, ToadletContext ctx) {
    if (ctx.isAllowedFullAccess()) {
      contentNode.addChild(ctx.getAlertManager().createSummary());
    }
  }

  private String[] buildPriorityClasses() {
    return new String[] {
      l10n("priority0"),
      l10n("priority1"),
      l10n("priority2"),
      l10n("priority3"),
      l10n("priority4"),
      l10n("priority5"),
      l10n("priority6")
    };
  }

  private void addPanicBoxIfNeeded(PageMaker pageMaker, ToadletContext ctx, HTMLNode contentNode) {
    if (SimpleToadletServer.isPanicButtonToBeShown) {
      contentNode.addChild(createPanicBox(pageMaker, ctx));
    }
  }

  private void addCompletedSections(
      PageMaker pageMaker,
      ToadletContext ctx,
      HTMLNode contentNode,
      QueuePartitions partitions,
      String[] priorityClasses,
      boolean advancedModeEnabled) {
    addCompletedDownloadToTempSection(
        pageMaker, ctx, contentNode, partitions, priorityClasses, advancedModeEnabled);
    addCompletedDownloadToDiskSection(
        pageMaker, ctx, contentNode, partitions, priorityClasses, advancedModeEnabled);
    addCompletedUploadSection(
        pageMaker, ctx, contentNode, partitions, priorityClasses, advancedModeEnabled);
    addCompletedDirUploadSection(
        pageMaker, ctx, contentNode, partitions, priorityClasses, advancedModeEnabled);
  }

  private void addCompletedDownloadToTempSection(
      PageMaker pageMaker,
      ToadletContext ctx,
      HTMLNode contentNode,
      QueuePartitions partitions,
      String[] priorityClasses,
      boolean advancedModeEnabled) {
    if (partitions.completedDownloadToTemp.isEmpty()) {
      return;
    }
    contentNode.addChild("a", "id", "completedDownloadToTemp");
    HTMLNode completedDownloadsToTempContent =
        pageMaker.getInfobox(
            COMPLETED_REQUESTS,
            l10n(
                "completedDinTempDirectory",
                new String[] {"size"},
                new String[] {String.valueOf(partitions.completedDownloadToTemp.size())}),
            contentNode,
            "request-completed",
            false);
    QueueColumn[] columns =
        advancedModeEnabled
            ? new QueueColumn[] {
              QueueColumn.IDENTIFIER,
              QueueColumn.SIZE,
              QueueColumn.MIME_TYPE,
              QueueColumn.PERSISTENCE,
              QueueColumn.KEY,
              QueueColumn.COMPAT_MODE
            }
            : new QueueColumn[] {QueueColumn.SIZE, QueueColumn.KEY};
    completedDownloadsToTempContent.addChild(
        createRequestTable(
            pageMaker,
            ctx,
            partitions.completedDownloadToTemp,
            columns,
            priorityClasses,
            advancedModeEnabled,
            "completed-temp",
            QueueType.COMPLETED_DOWNLOAD_TO_TEMP));
  }

  private void addCompletedDownloadToDiskSection(
      PageMaker pageMaker,
      ToadletContext ctx,
      HTMLNode contentNode,
      QueuePartitions partitions,
      String[] priorityClasses,
      boolean advancedModeEnabled) {
    if (partitions.completedDownloadToDisk.isEmpty()) {
      return;
    }
    contentNode.addChild("a", "id", "completedDownloadToDisk");
    HTMLNode completedToDiskInfoboxContent =
        pageMaker.getInfobox(
            COMPLETED_REQUESTS,
            l10n(
                "completedDinDownloadDirectory",
                new String[] {"size"},
                new String[] {String.valueOf(partitions.completedDownloadToDisk.size())}),
            contentNode,
            "request-completed",
            false);
    QueueColumn[] columns =
        advancedModeEnabled
            ? new QueueColumn[] {
              QueueColumn.IDENTIFIER,
              QueueColumn.FILENAME,
              QueueColumn.SIZE,
              QueueColumn.MIME_TYPE,
              QueueColumn.PERSISTENCE,
              QueueColumn.KEY,
              QueueColumn.COMPAT_MODE
            }
            : new QueueColumn[] {QueueColumn.FILENAME, QueueColumn.SIZE, QueueColumn.KEY};
    completedToDiskInfoboxContent.addChild(
        createRequestTable(
            pageMaker,
            ctx,
            partitions.completedDownloadToDisk,
            columns,
            priorityClasses,
            advancedModeEnabled,
            "completed-disk",
            QueueType.COMPLETED_DOWNLOAD_TO_DISK));
  }

  private void addCompletedUploadSection(
      PageMaker pageMaker,
      ToadletContext ctx,
      HTMLNode contentNode,
      QueuePartitions partitions,
      String[] priorityClasses,
      boolean advancedModeEnabled) {
    if (partitions.completedUpload.isEmpty()) {
      return;
    }
    contentNode.addChild("a", "id", "completedUpload");
    HTMLNode completedUploadInfoboxContent =
        pageMaker.getInfobox(
            COMPLETED_REQUESTS,
            l10n(
                "completedU",
                new String[] {"size"},
                new String[] {String.valueOf(partitions.completedUpload.size())}),
            contentNode,
            "download-completed",
            false);
    QueueColumn[] columns =
        advancedModeEnabled
            ? new QueueColumn[] {
              QueueColumn.IDENTIFIER,
              QueueColumn.FILENAME,
              QueueColumn.SIZE,
              QueueColumn.MIME_TYPE,
              QueueColumn.PERSISTENCE,
              QueueColumn.KEY
            }
            : new QueueColumn[] {QueueColumn.FILENAME, QueueColumn.SIZE, QueueColumn.KEY};
    completedUploadInfoboxContent.addChild(
        createRequestTable(
            pageMaker,
            ctx,
            partitions.completedUpload,
            columns,
            priorityClasses,
            advancedModeEnabled,
            "completed-upload-file",
            QueueType.COMPLETED_UPLOAD));
  }

  private void addCompletedDirUploadSection(
      PageMaker pageMaker,
      ToadletContext ctx,
      HTMLNode contentNode,
      QueuePartitions partitions,
      String[] priorityClasses,
      boolean advancedModeEnabled) {
    if (partitions.completedDirUpload.isEmpty()) {
      return;
    }
    contentNode.addChild("a", "id", "completedDirUpload");
    HTMLNode completedUploadDirContent =
        pageMaker.getInfobox(
            COMPLETED_REQUESTS,
            l10n(
                "completedUDirectory",
                new String[] {"size"},
                new String[] {String.valueOf(partitions.completedDirUpload.size())}),
            contentNode,
            "download-completed",
            false);
    QueueColumn[] columns =
        advancedModeEnabled
            ? new QueueColumn[] {
              QueueColumn.IDENTIFIER,
              QueueColumn.FILES,
              QueueColumn.TOTAL_SIZE,
              QueueColumn.PERSISTENCE,
              QueueColumn.KEY
            }
            : new QueueColumn[] {QueueColumn.FILES, QueueColumn.TOTAL_SIZE, QueueColumn.KEY};
    completedUploadDirContent.addChild(
        createRequestTable(
            pageMaker,
            ctx,
            partitions.completedDirUpload,
            columns,
            priorityClasses,
            advancedModeEnabled,
            "completed-upload-dir",
            QueueType.COMPLETED_DIR_UPLOAD));
  }

  private void addUncompletedSections(
      PageMaker pageMaker,
      ToadletContext ctx,
      HTMLNode contentNode,
      QueuePartitions partitions,
      String[] priorityClasses,
      boolean advancedModeEnabled) {
    if (!partitions.uncompletedDownload.isEmpty()) {
      contentNode.addChild("a", "id", "uncompletedDownload");
      HTMLNode uncompletedContent =
          pageMaker.getInfobox(
              REQUESTS_IN_PROGRESS,
              l10n(
                  "wipD",
                  new String[] {"size"},
                  new String[] {String.valueOf(partitions.uncompletedDownload.size())}),
              contentNode,
              "download-progressing",
              false);
      if (advancedModeEnabled) {
        uncompletedContent.addChild(
            createRequestTable(
                pageMaker,
                ctx,
                partitions.uncompletedDownload,
                new QueueColumn[] {
                  QueueColumn.IDENTIFIER,
                  QueueColumn.PRIORITY,
                  QueueColumn.SIZE,
                  QueueColumn.MIME_TYPE,
                  QueueColumn.PROGRESS,
                  QueueColumn.LAST_ACTIVITY,
                  /* FIXME: This column has been disabled since it will always show
                   * "never" even if parts of the file transfer failed due to temporary
                   * reasons such as "data not found" / "route not found" / etc. This is
                   * due to shortcomings in the underlying event framework. Please
                   * re-enable it once the underlying issue is fixed:
                   * https://bugs.freenetproject.org/view.php?id=6526 */
                  // QueueColumn.LAST_FAILURE,
                  QueueColumn.PERSISTENCE,
                  QueueColumn.FILENAME,
                  QueueColumn.KEY,
                  QueueColumn.COMPAT_MODE
                },
                priorityClasses,
                advancedModeEnabled,
                "uncompleted-download",
                QueueType.UNCOMPLETED_DOWNLOAD));
      } else {
        uncompletedContent.addChild(
            createRequestTable(
                pageMaker,
                ctx,
                partitions.uncompletedDownload,
                new QueueColumn[] {
                  QueueColumn.PRIORITY,
                  QueueColumn.SIZE,
                  QueueColumn.PROGRESS,
                  QueueColumn.LAST_ACTIVITY,
                  QueueColumn.KEY
                },
                priorityClasses,
                advancedModeEnabled,
                "uncompleted-download",
                QueueType.UNCOMPLETED_DOWNLOAD));
      }
    }

    if (!partitions.uncompletedUpload.isEmpty()) {
      contentNode.addChild("a", "id", "uncompletedUpload");
      HTMLNode uncompletedContent =
          pageMaker.getInfobox(
              REQUESTS_IN_PROGRESS,
              l10n(
                  "wipU",
                  new String[] {"size"},
                  new String[] {String.valueOf(partitions.uncompletedUpload.size())}),
              contentNode,
              "upload-progressing",
              false);
      if (advancedModeEnabled) {
        uncompletedContent.addChild(
            createRequestTable(
                pageMaker,
                ctx,
                partitions.uncompletedUpload,
                new QueueColumn[] {
                  QueueColumn.IDENTIFIER,
                  QueueColumn.PRIORITY,
                  QueueColumn.SIZE,
                  QueueColumn.MIME_TYPE,
                  QueueColumn.PROGRESS,
                  QueueColumn.LAST_ACTIVITY,
                  /* FIXME: This column has been disabled since it will always show
                   * "never" even if parts of the file transfer failed due to temporary
                   * reasons such as "data not found" / "route not found" / etc. This is
                   * due to shortcomings in the underlying event framework. Please
                   * re-enable it once the underlying issue is fixed:
                   * https://bugs.freenetproject.org/view.php?id=6526 */
                  // QueueColumn.LAST_FAILURE,
                  QueueColumn.PERSISTENCE,
                  QueueColumn.FILENAME,
                  QueueColumn.KEY
                },
                priorityClasses,
                advancedModeEnabled,
                "uncompleted-upload-file",
                QueueType.UNCOMPLETED_UPLOAD));
      } else {
        uncompletedContent.addChild(
            createRequestTable(
                pageMaker,
                ctx,
                partitions.uncompletedUpload,
                new QueueColumn[] {
                  QueueColumn.PRIORITY,
                  QueueColumn.FILENAME,
                  QueueColumn.SIZE,
                  QueueColumn.PROGRESS,
                  QueueColumn.LAST_ACTIVITY,
                  QueueColumn.KEY
                },
                priorityClasses,
                advancedModeEnabled,
                "uncompleted-upload-file",
                QueueType.UNCOMPLETED_UPLOAD));
      }
    }

    if (!partitions.uncompletedDirUpload.isEmpty()) {
      contentNode.addChild("a", "id", "uncompletedDirUpload");
      HTMLNode uncompletedContent =
          pageMaker.getInfobox(
              REQUESTS_IN_PROGRESS,
              l10n(
                  "wipDU",
                  new String[] {"size"},
                  new String[] {String.valueOf(partitions.uncompletedDirUpload.size())}),
              contentNode,
              "download-progressing upload-progressing",
              false);
      if (advancedModeEnabled) {
        uncompletedContent.addChild(
            createRequestTable(
                pageMaker,
                ctx,
                partitions.uncompletedDirUpload,
                new QueueColumn[] {
                  QueueColumn.IDENTIFIER, QueueColumn.FILES, QueueColumn.PRIORITY,
                  QueueColumn.TOTAL_SIZE, QueueColumn.PROGRESS, QueueColumn.LAST_ACTIVITY,
                  /* FIXME: This column has been disabled since it will always show
                   * "never" even if parts of the file transfer failed due to temporary
                   * reasons such as "data not found" / "route not found" / etc. This is
                   * due to shortcomings in the underlying event framework. Please
                   * re-enable it once the underlying issue is fixed:
                   * https://bugs.freenetproject.org/view.php?id=6526 */
                  // QueueColumn.LAST_FAILURE,
                  QueueColumn.PERSISTENCE, QueueColumn.KEY
                },
                priorityClasses,
                advancedModeEnabled,
                "uncompleted-upload-dir",
                QueueType.UNCOMPLETED_DIR_UPLOAD));
      } else {
        uncompletedContent.addChild(
            createRequestTable(
                pageMaker,
                ctx,
                partitions.uncompletedDirUpload,
                new QueueColumn[] {
                  QueueColumn.PRIORITY,
                  QueueColumn.FILES,
                  QueueColumn.TOTAL_SIZE,
                  QueueColumn.PROGRESS,
                  QueueColumn.LAST_ACTIVITY,
                  QueueColumn.KEY
                },
                priorityClasses,
                advancedModeEnabled,
                "uncompleted-upload-dir",
                QueueType.UNCOMPLETED_DIR_UPLOAD));
      }
    }
  }

  private void addFailureSections(
      PageMaker pageMaker,
      ToadletContext ctx,
      HTMLNode contentNode,
      QueuePartitions partitions,
      String[] priorityClasses,
      boolean advancedModeEnabled,
      QueueColumn[] advancedModeFailure,
      QueueColumn[] simpleModeFailure) {
    if (!partitions.failedDownload.isEmpty()) {
      contentNode.addChild("a", "id", "failedDownload");
      HTMLNode failedContent =
          pageMaker.getInfobox(
              FAILED_REQUESTS,
              l10n(
                  "failedD",
                  new String[] {"size"},
                  new String[] {String.valueOf(partitions.failedDownload.size())}),
              contentNode,
              "download-failed",
              false);
      if (advancedModeEnabled) {
        failedContent.addChild(
            createRequestTable(
                pageMaker,
                ctx,
                partitions.failedDownload,
                advancedModeFailure,
                priorityClasses,
                advancedModeEnabled,
                "failed-download",
                QueueType.FAILED_DOWNLOAD));
      } else {
        failedContent.addChild(
            createRequestTable(
                pageMaker,
                ctx,
                partitions.failedDownload,
                simpleModeFailure,
                priorityClasses,
                advancedModeEnabled,
                "failed-download",
                QueueType.FAILED_DOWNLOAD));
      }
    }

    if (!partitions.failedUpload.isEmpty()) {
      contentNode.addChild("a", "id", "failedUpload");
      HTMLNode failedContent =
          pageMaker.getInfobox(
              FAILED_REQUESTS,
              l10n(
                  STATUS_FAILED_UPLOAD,
                  new String[] {"size"},
                  new String[] {String.valueOf(partitions.failedUpload.size())}),
              contentNode,
              "upload-failed",
              false);
      if (advancedModeEnabled) {
        failedContent.addChild(
            createRequestTable(
                pageMaker,
                ctx,
                partitions.failedUpload,
                advancedModeFailure,
                priorityClasses,
                advancedModeEnabled,
                "failed-upload-file",
                QueueType.FAILED_UPLOAD));
      } else {
        failedContent.addChild(
            createRequestTable(
                pageMaker,
                ctx,
                partitions.failedUpload,
                simpleModeFailure,
                priorityClasses,
                advancedModeEnabled,
                "failed-upload-file",
                QueueType.FAILED_UPLOAD));
      }
    }

    if (!partitions.failedDirUpload.isEmpty()) {
      contentNode.addChild("a", "id", "failedDirUpload");
      HTMLNode failedContent =
          pageMaker.getInfobox(
              FAILED_REQUESTS,
              l10n(
                  STATUS_FAILED_UPLOAD,
                  new String[] {"size"},
                  new String[] {String.valueOf(partitions.failedDirUpload.size())}),
              contentNode,
              "upload-failed",
              false);
      if (advancedModeEnabled) {
        failedContent.addChild(
            createRequestTable(
                pageMaker,
                ctx,
                partitions.failedDirUpload,
                new QueueColumn[] {
                  QueueColumn.IDENTIFIER,
                  QueueColumn.FILES,
                  QueueColumn.TOTAL_SIZE,
                  QueueColumn.PROGRESS,
                  QueueColumn.REASON,
                  QueueColumn.PERSISTENCE,
                  QueueColumn.KEY
                },
                priorityClasses,
                advancedModeEnabled,
                "failed-upload-dir",
                QueueType.FAILED_DIR_UPLOAD));
      } else {
        failedContent.addChild(
            createRequestTable(
                pageMaker,
                ctx,
                partitions.failedDirUpload,
                new QueueColumn[] {
                  QueueColumn.FILES,
                  QueueColumn.TOTAL_SIZE,
                  QueueColumn.PROGRESS,
                  QueueColumn.REASON,
                  QueueColumn.KEY
                },
                priorityClasses,
                advancedModeEnabled,
                "failed-upload-dir",
                QueueType.FAILED_DIR_UPLOAD));
      }
    }
  }

  private void addMimeFailureSections(
      PageMaker pageMaker,
      ToadletContext ctx,
      HTMLNode contentNode,
      QueuePartitions partitions,
      String[] priorityClasses,
      boolean advancedModeEnabled,
      Comparator<RequestStatus> jobComparator) {
    addBadMimeFailures(
        pageMaker,
        ctx,
        contentNode,
        partitions,
        priorityClasses,
        advancedModeEnabled,
        jobComparator);
    addUnknownMimeFailures(
        pageMaker,
        ctx,
        contentNode,
        partitions,
        priorityClasses,
        advancedModeEnabled,
        jobComparator);
  }

  private void addBadMimeFailures(
      PageMaker pageMaker,
      ToadletContext ctx,
      HTMLNode contentNode,
      QueuePartitions partitions,
      String[] priorityClasses,
      boolean advancedModeEnabled,
      Comparator<RequestStatus> jobComparator) {
    if (partitions.failedBadMIMEType.isEmpty()) {
      return;
    }
    String[] types = partitions.failedBadMIMEType.keySet().toArray(new String[0]);
    Arrays.sort(types);
    for (String type : types) {
      LinkedList<DownloadRequestStatus> getters = partitions.failedBadMIMEType.get(type);
      String atype = type.replace("-", "--").replace('/', '-');
      contentNode.addChild("a", "id", "failedDownload-badtype-" + atype);
      FilterMIMEType typeHandler = ContentFilter.getMIMEType(type);
      HTMLNode failedContent =
          pageMaker.getInfobox(
              FAILED_REQUESTS,
              l10n(
                  "failedDBadMIME",
                  new String[] {"size", "type"},
                  new String[] {String.valueOf(getters.size()), type}),
              contentNode,
              "download-failed-" + atype,
              false);
      KnownUnsafeContentTypeException e = new KnownUnsafeContentTypeException(typeHandler);
      failedContent.addChild("p", l10n("badMIMETypeIntro", "type", type));
      List<String> detail = e.details();
      if (detail != null && !detail.isEmpty()) {
        HTMLNode list = failedContent.addChild("ul");
        for (String s : detail) {
          list.addChild("li", s);
        }
      }
      failedContent.addChild("p", l10n("mimeProblemFetchAnyway"));
      Collections.sort(getters, jobComparator);
      QueueColumn[] columns =
          advancedModeEnabled
              ? new QueueColumn[] {
                QueueColumn.IDENTIFIER,
                QueueColumn.FILENAME,
                QueueColumn.SIZE,
                QueueColumn.PERSISTENCE,
                QueueColumn.KEY
              }
              : new QueueColumn[] {QueueColumn.FILENAME, QueueColumn.SIZE, QueueColumn.KEY};
      failedContent.addChild(
          createRequestTable(
              pageMaker,
              ctx,
              getters,
              columns,
              priorityClasses,
              advancedModeEnabled,
              "failed-download-file-badmime",
              type,
              QueueType.FAILED_BAD_MIME_TYPE));
    }
  }

  private void addUnknownMimeFailures(
      PageMaker pageMaker,
      ToadletContext ctx,
      HTMLNode contentNode,
      QueuePartitions partitions,
      String[] priorityClasses,
      boolean advancedModeEnabled,
      Comparator<RequestStatus> jobComparator) {
    if (partitions.failedUnknownMIMEType.isEmpty()) {
      return;
    }
    String[] types = partitions.failedUnknownMIMEType.keySet().toArray(new String[0]);
    Arrays.sort(types);
    for (String type : types) {
      LinkedList<DownloadRequestStatus> getters = partitions.failedUnknownMIMEType.get(type);
      String atype = type.replace("-", "--").replace('/', '-');
      contentNode.addChild("a", "id", "failedDownload-unknowntype-" + atype);
      HTMLNode failedContent =
          pageMaker.getInfobox(
              FAILED_REQUESTS,
              l10n(
                  "failedDUnknownMIME",
                  new String[] {"size", "type"},
                  new String[] {String.valueOf(getters.size()), type}),
              contentNode,
              "download-failed-" + atype,
              false);
      failedContent.addChild(
          "p",
          NodeL10n.getBase().getString("UnknownContentTypeException.explanation", "type", type));
      failedContent.addChild("p", l10n("mimeProblemFetchAnyway"));
      Collections.sort(getters, jobComparator);
      QueueColumn[] columns =
          advancedModeEnabled
              ? new QueueColumn[] {
                QueueColumn.IDENTIFIER,
                QueueColumn.FILENAME,
                QueueColumn.SIZE,
                QueueColumn.PERSISTENCE,
                QueueColumn.KEY
              }
              : new QueueColumn[] {QueueColumn.FILENAME, QueueColumn.SIZE, QueueColumn.KEY};
      failedContent.addChild(
          createRequestTable(
              pageMaker,
              ctx,
              getters,
              columns,
              priorityClasses,
              advancedModeEnabled,
              "failed-download-file-unknownmime",
              type,
              QueueType.FAILED_UNKNOWN_MIME_TYPE));
    }
  }

  private void addNavigationBar(
      PageMaker pageMaker, QueuePartitions partitions, HTMLNode contentNode) {
    InfoboxNode infobox = pageMaker.getInfobox("navbar", l10n("requestNavigation"), null, false);
    HTMLNode navigationBar = infobox.getOuterNode();
    HTMLNode navigationContent = infobox.getContentNode().addChild("ul");
    boolean includeNavigationBar = false;
    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            !partitions.completedDownloadToTemp.isEmpty(),
            "#completedDownloadToTemp",
            l10n(
                "completedDtoTemp",
                new String[] {"size"},
                new String[] {String.valueOf(partitions.completedDownloadToTemp.size())}));
    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            !partitions.completedDownloadToDisk.isEmpty(),
            "#completedDownloadToDisk",
            l10n(
                "completedDtoDisk",
                new String[] {"size"},
                new String[] {String.valueOf(partitions.completedDownloadToDisk.size())}));
    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            !partitions.completedUpload.isEmpty(),
            "#completedUpload",
            l10n(
                "completedU",
                new String[] {"size"},
                new String[] {String.valueOf(partitions.completedUpload.size())}));
    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            !partitions.completedDirUpload.isEmpty(),
            "#completedDirUpload",
            l10n(
                "completedDU",
                new String[] {"size"},
                new String[] {String.valueOf(partitions.completedDirUpload.size())}));
    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            !partitions.failedDownload.isEmpty(),
            "#failedDownload",
            l10n(
                "failedD",
                new String[] {"size"},
                new String[] {String.valueOf(partitions.failedDownload.size())}));
    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            !partitions.failedUpload.isEmpty(),
            "#failedUpload",
            l10n(
                STATUS_FAILED_UPLOAD,
                new String[] {"size"},
                new String[] {String.valueOf(partitions.failedUpload.size())}));
    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            !partitions.failedDirUpload.isEmpty(),
            "#failedDirUpload",
            l10n(
                "failedDU",
                new String[] {"size"},
                new String[] {String.valueOf(partitions.failedDirUpload.size())}));

    addNavigationMimeSections(navigationContent, partitions);

    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            !partitions.uncompletedDownload.isEmpty(),
            "#uncompletedDownload",
            l10n(
                "DinProgress",
                new String[] {"size"},
                new String[] {String.valueOf(partitions.uncompletedDownload.size())}));
    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            !partitions.uncompletedUpload.isEmpty(),
            "#uncompletedUpload",
            l10n(
                "UinProgress",
                new String[] {"size"},
                new String[] {String.valueOf(partitions.uncompletedUpload.size())}));
    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            !partitions.uncompletedDirUpload.isEmpty(),
            "#uncompletedDirUpload",
            l10n(
                "DUinProgress",
                new String[] {"size"},
                new String[] {String.valueOf(partitions.uncompletedDirUpload.size())}));
    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            partitions.totalQueuedDownloadSize > 0,
            null,
            l10n(
                "totalQueuedDownloads",
                "size",
                SizeUtil.formatSize(partitions.totalQueuedDownloadSize)));
    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            partitions.totalQueuedUploadSize > 0,
            null,
            l10n(
                "totalQueuedUploads",
                "size",
                SizeUtil.formatSize(partitions.totalQueuedUploadSize)));

    navigationContent.addChild("li").addChild("a", "href", KEY_LIST_LOCATION, l10n("openKeyList"));

    if (includeNavigationBar) {
      contentNode.addChild(navigationBar);
    }
  }

  private void addNavigationMimeSections(HTMLNode navigationContent, QueuePartitions partitions) {
    if (!partitions.failedUnknownMIMEType.isEmpty()) {
      String[] types = partitions.failedUnknownMIMEType.keySet().toArray(new String[0]);
      Arrays.sort(types);
      for (String type : types) {
        String atype = type.replace("-", "--").replace('/', '-');
        addNavigationItem(
            navigationContent,
            true,
            "#failedDownload-unknowntype-" + atype,
            l10n(
                "failedDUnknownMIME",
                new String[] {"size", "type"},
                new String[] {
                  String.valueOf(partitions.failedUnknownMIMEType.get(type).size()), type
                }));
      }
    }
    if (!partitions.failedBadMIMEType.isEmpty()) {
      String[] types = partitions.failedBadMIMEType.keySet().toArray(new String[0]);
      Arrays.sort(types);
      for (String type : types) {
        String atype = type.replace("-", "--").replace('/', '-');
        addNavigationItem(
            navigationContent,
            true,
            "#failedDownload-badtype-" + atype,
            l10n(
                "failedDBadMIME",
                new String[] {"size", "type"},
                new String[] {
                  String.valueOf(partitions.failedBadMIMEType.get(type).size()), type
                }));
      }
    }
  }

  private boolean addNavigationItem(
      HTMLNode navigationContent, boolean condition, String href, String text) {
    if (!condition) {
      return false;
    }
    HTMLNode li = navigationContent.addChild("li");
    if (href != null) {
      li.addChild("a", "href", href, text);
    } else {
      li.addChild("#", text);
    }
    return true;
  }

  private String buildPageName(QueuePartitions partitions) {
    if (uploads)
      return "("
          + (partitions.uncompletedDirUpload.size() + partitions.uncompletedUpload.size())
          + '/'
          + (partitions.failedDirUpload.size() + partitions.failedUpload.size())
          + '/'
          + (partitions.completedDirUpload.size() + partitions.completedUpload.size())
          + ") "
          + l10n("titleUploads");
    return "("
        + partitions.uncompletedDownload.size()
        + '/'
        + partitions.failedDownload.size()
        + '/'
        + (partitions.completedDownloadToDisk.size() + partitions.completedDownloadToTemp.size())
        + ") "
        + l10n("titleDownloads");
  }

  private void sortPartitions(QueuePartitions partitions, Comparator<RequestStatus> jobComparator) {
    Collections.sort(partitions.completedDownloadToDisk, jobComparator);
    Collections.sort(partitions.completedDownloadToTemp, jobComparator);
    Collections.sort(partitions.completedUpload, jobComparator);
    Collections.sort(partitions.completedDirUpload, jobComparator);
    Collections.sort(partitions.failedDownload, jobComparator);
    Collections.sort(partitions.failedUpload, jobComparator);
    Collections.sort(partitions.failedDirUpload, jobComparator);
    Collections.sort(partitions.uncompletedDownload, jobComparator);
    Collections.sort(partitions.uncompletedUpload, jobComparator);
    Collections.sort(partitions.uncompletedDirUpload, jobComparator);
  }

  private void logTotals(QueuePartitions partitions) {
    LOG.debug(
        "Total queued downloads: {}", SizeUtil.formatSize(partitions.totalQueuedDownloadSize));
    LOG.debug("Total queued uploads: {}", SizeUtil.formatSize(partitions.totalQueuedUploadSize));
  }

  private Comparator<RequestStatus> createJobComparator(final HTTPRequest request) {
    Comparator<RequestStatus> baseComparator = selectComparator(request);
    boolean reversed = request.isParameterSet("reversed");

    return (first, second) -> {
      if (first == second) {
        return 0; // Short cut.
      }
      int result = baseComparator.compare(first, second);
      if (result == 0) {
        return 0;
      }
      isReversed = reversed;
      return reversed ? -Integer.signum(result) : Integer.signum(result);
    };
  }

  private Comparator<RequestStatus> selectComparator(HTTPRequest request) {
    if (!request.isParameterSet("sortBy")) {
      return this::compareByPriorityThenId;
    }

    return switch (request.getParam("sortBy")) {
      case "id" -> this::compareById;
      case "size" -> this::compareBySize;
      case "progress" -> this::compareByProgress;
      case "lastActivity" -> this::compareByLastActivity;
      case "lastFailure" -> this::compareByLastFailure;
      default -> this::compareByPriorityThenId;
    };
  }

  private int compareById(RequestStatus first, RequestStatus second) {
    int result = first.getIdentifier().compareToIgnoreCase(second.getIdentifier());
    if (result == 0) {
      result = first.getIdentifier().compareTo(second.getIdentifier());
    }
    return result;
  }

  private int compareBySize(RequestStatus first, RequestStatus second) {
    return Fields.compare(first.getTotalBlocks(), second.getTotalBlocks());
  }

  private int compareByProgress(RequestStatus first, RequestStatus second) {
    boolean firstFinalized = first.isTotalFinalized();
    boolean secondFinalized = second.isTotalFinalized();
    if (firstFinalized && !secondFinalized) {
      return 1;
    }
    if (secondFinalized && !firstFinalized) {
      return -1;
    }
    double firstProgress = ((double) first.getFetchedBlocks()) / ((double) first.getMinBlocks());
    double secondProgress = ((double) second.getFetchedBlocks()) / ((double) second.getMinBlocks());
    return Fields.compare(firstProgress, secondProgress);
  }

  private int compareByLastActivity(RequestStatus first, RequestStatus second) {
    return Fields.compare(first.getLastSuccess(), second.getLastSuccess());
  }

  private int compareByLastFailure(RequestStatus first, RequestStatus second) {
    return Fields.compare(first.getLastFailure(), second.getLastFailure());
  }

  private int compareByPriorityThenId(RequestStatus first, RequestStatus second) {
    int result = Fields.compare(first.getPriority(), second.getPriority());
    if (result == 0) {
      result = first.getIdentifier().compareTo(second.getIdentifier());
    }
    return result;
  }

  private QueuePartitions partitionRequests(RequestStatus[] reqs) {
    QueuePartitions partitions = new QueuePartitions();
    if (LOG.isDebugEnabled()) LOG.debug("Request count: {}", reqs.length);
    if (reqs.length < 1) {
      return partitions;
    }

    for (RequestStatus req : reqs) {
      if (req instanceof DownloadRequestStatus download && !uploads) {
        handleDownloadPartition(download, partitions);
      } else if (req instanceof UploadFileRequestStatus upload && uploads) {
        handleUploadFilePartition(upload, partitions);
      } else if (req instanceof UploadDirRequestStatus upload && uploads) {
        handleUploadDirPartition(upload, partitions);
      }
    }
    return partitions;
  }

  private void handleUploadDirPartition(UploadDirRequestStatus upload, QueuePartitions partitions) {
    if (upload.hasSucceeded()) {
      partitions.completedDirUpload.add(upload);
    } else if (upload.hasFinished()) {
      partitions.failedDirUpload.add(upload);
    } else {
      short prio = upload.getPriority();
      if (prio < partitions.lowestQueuedPrio) partitions.lowestQueuedPrio = prio;
      partitions.uncompletedDirUpload.add(upload);
    }
    long size = upload.getTotalDataSize();
    if (size > 0) partitions.totalQueuedUploadSize += size;
    partitions.added = true;
  }

  private void handleUploadFilePartition(
      UploadFileRequestStatus upload, QueuePartitions partitions) {
    if (upload.hasSucceeded()) {
      partitions.completedUpload.add(upload);
    } else if (upload.hasFinished()) {
      partitions.failedUpload.add(upload);
    } else {
      short prio = upload.getPriority();
      if (prio < partitions.lowestQueuedPrio) partitions.lowestQueuedPrio = prio;
      partitions.uncompletedUpload.add(upload);
    }
    long size = upload.getDataSize();
    if (size > 0) partitions.totalQueuedUploadSize += size;
    partitions.added = true;
  }

  private void handleDownloadPartition(DownloadRequestStatus download, QueuePartitions partitions) {
    if (download.hasSucceeded()) {
      if (download.toTempSpace()) partitions.completedDownloadToTemp.add(download);
      else partitions.completedDownloadToDisk.add(download);
    } else if (download.hasFinished()) {
      FetchExceptionMode failureCode = download.getFailureCode();
      String mimeType = download.getMIMEType();
      if (mimeType == null
          && (failureCode == FetchExceptionMode.CONTENT_VALIDATION_UNKNOWN_MIME
              || failureCode == FetchExceptionMode.CONTENT_VALIDATION_BAD_MIME)) {
        LOG.error(
            "MIME type is null but failure code is {} for {} : {}",
            FetchException.getMessage(failureCode),
            download.getIdentifier(),
            download.getURI());
        mimeType = DefaultMIMETypes.DEFAULT_MIME_TYPE;
      }
      if (failureCode == FetchExceptionMode.CONTENT_VALIDATION_UNKNOWN_MIME) {
        mimeType = ContentFilter.stripMIMEType(mimeType);
        LinkedList<DownloadRequestStatus> list =
            partitions.failedUnknownMIMEType.computeIfAbsent(mimeType, key -> new LinkedList<>());
        list.add(download);
      } else if (failureCode == FetchExceptionMode.CONTENT_VALIDATION_BAD_MIME) {
        mimeType = ContentFilter.stripMIMEType(mimeType);
        FilterMIMEType type = ContentFilter.getMIMEType(mimeType);
        LinkedList<DownloadRequestStatus> list;
        if (type == null) {
          LOG.error(
              "Bad MIME failure code yet MIME is {} which does not have a handler!", mimeType);
          list =
              partitions.failedUnknownMIMEType.computeIfAbsent(mimeType, key -> new LinkedList<>());
        } else {
          list = partitions.failedBadMIMEType.computeIfAbsent(mimeType, key -> new LinkedList<>());
        }
        list.add(download);
      } else {
        partitions.failedDownload.add(download);
      }
    } else {
      short prio = download.getPriority();
      if (prio < partitions.lowestQueuedPrio) partitions.lowestQueuedPrio = prio;
      partitions.uncompletedDownload.add(download);
      long size = download.getDataSize();
      if (size > 0) partitions.totalQueuedDownloadSize += size;
    }
    partitions.added = true;
  }

  private static final class QueuePartitions {
    final LinkedList<DownloadRequestStatus> completedDownloadToDisk = new LinkedList<>();
    final LinkedList<DownloadRequestStatus> completedDownloadToTemp = new LinkedList<>();
    final LinkedList<UploadFileRequestStatus> completedUpload = new LinkedList<>();
    final LinkedList<UploadDirRequestStatus> completedDirUpload = new LinkedList<>();

    final LinkedList<DownloadRequestStatus> failedDownload = new LinkedList<>();
    final LinkedList<UploadFileRequestStatus> failedUpload = new LinkedList<>();
    final LinkedList<UploadDirRequestStatus> failedDirUpload = new LinkedList<>();

    final LinkedList<DownloadRequestStatus> uncompletedDownload = new LinkedList<>();
    final LinkedList<UploadFileRequestStatus> uncompletedUpload = new LinkedList<>();
    final LinkedList<UploadDirRequestStatus> uncompletedDirUpload = new LinkedList<>();

    final Map<String, LinkedList<DownloadRequestStatus>> failedUnknownMIMEType = new HashMap<>();
    final Map<String, LinkedList<DownloadRequestStatus>> failedBadMIMEType = new HashMap<>();

    short lowestQueuedPrio = RequestStarter.PAUSED_PRIORITY_CLASS;
    long totalQueuedDownloadSize = 0;
    long totalQueuedUploadSize = 0;
    boolean added = false;

    boolean hasAny() {
      return added;
    }
  }

  private HTMLNode sendEmptyQueuePage(ToadletContext ctx, PageMaker pageMaker) {
    PageNode page =
        pageMaker.getPageNode(l10n(ATTR_TITLE + (uploads ? "Uploads" : "Downloads")), ctx);
    HTMLNode pageNode = page.getOuterNode();
    HTMLNode contentNode = page.getContentNode();
    /* add alert summary box */
    if (ctx.isAllowedFullAccess()) contentNode.addChild(ctx.getAlertManager().createSummary());
    HTMLNode infoboxContent =
        pageMaker.getInfobox(
            INFOBOX_INFORMATION, l10n("globalQueueIsEmpty"), contentNode, "queue-empty", true);
    infoboxContent.addChild("#", l10n("noTaskOnGlobalQueue"));
    if (!uploads) contentNode.addChild(createBulkDownloadForm(ctx, pageMaker));
    return pageNode;
  }

  private HTMLNode createReasonCell(String failureReason) {
    HTMLNode reasonCell = new HTMLNode("td", ATTR_CLASS, "request-reason");
    if (failureReason == null) {
      reasonCell.addChild("span", ATTR_CLASS, "failure_reason_unknown", l10n(UNKNOWN));
    } else {
      reasonCell.addChild("span", ATTR_CLASS, "failure_reason_is", failureReason);
    }
    return reasonCell;
  }

  public static HTMLNode createProgressCell(
      boolean advancedMode,
      boolean started,
      COMPRESS_STATE compressing,
      int fetched,
      int failed,
      int fatallyFailed,
      int min,
      int total,
      boolean finalized,
      boolean upload) {
    HTMLNode progressCell = new HTMLNode("td", ATTR_CLASS, "request-progress");
    if (handleEarlyProgressMessages(advancedMode, started, compressing, progressCell)) {
      return progressCell;
    }

    int adjustedTotal = adjustTotal(advancedMode, min, total);

    if ((fetched < 0) || (adjustedTotal <= 0)) {
      progressCell.addChild("span", ATTR_CLASS, "progress_fraction_unknown", l10n(UNKNOWN));
    } else {
      addProgressBar(
          progressCell, fetched, failed, fatallyFailed, min, adjustedTotal, finalized, upload);
    }
    return progressCell;
  }

  private static boolean handleEarlyProgressMessages(
      boolean advancedMode, boolean started, COMPRESS_STATE compressing, HTMLNode progressCell) {
    if (!started) {
      progressCell.addChild("#", l10n("starting"));
      return true;
    }
    if (compressing == COMPRESS_STATE.WAITING && advancedMode) {
      progressCell.addChild("#", l10n("awaitingCompression"));
      return true;
    }
    if (compressing != COMPRESS_STATE.WORKING) {
      progressCell.addChild("#", l10n("compressing"));
      return true;
    }
    return false;
  }

  private static int adjustTotal(boolean advancedMode, int min, int total) {
    return (!advancedMode || total < min) ? min : total;
  }

  private static void addProgressBar(
      HTMLNode progressCell,
      int fetched,
      int failed,
      int fatallyFailed,
      int min,
      int total,
      boolean finalized,
      boolean upload) {
    int fetchedPercent = (int) (fetched / (double) total * 100);
    int failedPercent = (int) (failed / (double) total * 100);
    int fatallyFailedPercent = (int) (fatallyFailed / (double) total * 100);
    int minPercent = (int) (min / (double) total * 100);
    HTMLNode progressBar = progressCell.addChild("div", ATTR_CLASS, "progressbar");
    progressBar.addChild(
        "div",
        new String[] {ATTR_CLASS, ATTR_STYLE},
        new String[] {"progressbar-done", CSS_WIDTH_PREFIX + fetchedPercent + "%;"});

    if (failed > 0) {
      progressBar.addChild(
          "div",
          new String[] {ATTR_CLASS, ATTR_STYLE},
          new String[] {"progressbar-failed", CSS_WIDTH_PREFIX + failedPercent + "%;"});
    }
    if (fatallyFailed > 0) {
      progressBar.addChild(
          "div",
          new String[] {ATTR_CLASS, ATTR_STYLE},
          new String[] {"progressbar-failed2", CSS_WIDTH_PREFIX + fatallyFailedPercent + "%;"});
    }
    if ((fetched + failed + fatallyFailed) < min) {
      progressBar.addChild(
          "div",
          new String[] {ATTR_CLASS, ATTR_STYLE},
          new String[] {
            "progressbar-min", CSS_WIDTH_PREFIX + (minPercent - fetchedPercent) + "%;"
          });
    }

    NumberFormat nf = NumberFormat.getInstance();
    nf.setMaximumFractionDigits(1);
    String prefix = '(' + Integer.toString(fetched) + "/ " + min + "): ";
    addProgressTitle(progressBar, fetched, min, finalized, upload, nf, prefix);
  }

  private static void addProgressTitle(
      HTMLNode progressBar,
      int fetched,
      int min,
      boolean finalized,
      boolean upload,
      NumberFormat nf,
      String prefix) {
    String percentText = nf.format((int) ((fetched / (double) min) * 1000) / 10.0) + '%';
    if (finalized) {
      progressBar.addChild(
          "div",
          new String[] {ATTR_CLASS, ATTR_TITLE},
          new String[] {"progress_fraction_finalized", prefix + l10n("progressbarAccurate")},
          percentText);
      return;
    }
    String text = fetched + " (" + percentText + "??)";
    progressBar.addChild(
        "div",
        new String[] {ATTR_CLASS, ATTR_TITLE},
        new String[] {
          "progress_fraction_not_finalized",
          prefix
              + NodeL10n.getBase()
                  .getString(
                      upload
                          ? QUEUE_TOADLET_PREFIX + "uploadProgressbarNotAccurate"
                          : QUEUE_TOADLET_PREFIX + "progressbarNotAccurate")
        },
        text);
  }

  private HTMLNode createNumberCell(int numberOfFiles) {
    HTMLNode numberCell = new HTMLNode("td", ATTR_CLASS, "request-files");
    numberCell.addChild("span", ATTR_CLASS, "number_of_files", String.valueOf(numberOfFiles));
    return numberCell;
  }

  private HTMLNode createFilenameCell(File filename) {
    HTMLNode filenameCell = new HTMLNode("td", ATTR_CLASS, "request-filename");
    if (filename != null) {
      filenameCell.addChild("span", ATTR_CLASS, "filename_is", filename.toString());
    } else {
      filenameCell.addChild("span", ATTR_CLASS, "filename_none", l10n("none"));
    }
    return filenameCell;
  }

  private HTMLNode createPriorityCell(short priorityClass, String[] priorityClasses) {
    HTMLNode priorityCell = new HTMLNode("td", ATTR_CLASS, "request-priority");
    if (priorityClass < 0 || priorityClass >= priorityClasses.length) {
      priorityCell.addChild("span", ATTR_CLASS, "priority_unknown", l10n(UNKNOWN));
    } else {
      priorityCell.addChild("span", ATTR_CLASS, "priority_is", priorityClasses[priorityClass]);
    }
    return priorityCell;
  }

  private HTMLNode createPriorityControl(
      PageMaker pageMaker,
      ToadletContext ctx,
      short priorityClass,
      String[] priorityClasses,
      boolean advancedModeEnabled,
      boolean isUpload,
      String controlSuffix) {
    HTMLNode priorityDiv = new HTMLNode("div", ATTR_CLASS, "request-priority nowrap");
    priorityDiv.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {
          INPUT_TYPE_SUBMIT,
          "change_priority" + controlSuffix,
          NodeL10n.getBase()
              .getString(
                  isUpload
                      ? QUEUE_TOADLET_PREFIX + "changeUploadPriorities"
                      : QUEUE_TOADLET_PREFIX + "changeDownloadPriorities")
        });
    HTMLNode prioritySelect = priorityDiv.addChild("select", ATTR_NAME, PRIORITY + controlSuffix);
    for (int p = 0; p < RequestStarter.NUMBER_OF_PRIORITY_CLASSES; p++) {
      if (p <= RequestStarter.INTERACTIVE_PRIORITY_CLASS && !advancedModeEnabled) continue;
      if (p == priorityClass) {
        prioritySelect.addChild(
            "option",
            new String[] {ATTR_VALUE, "selected"},
            new String[] {String.valueOf(p), "selected"},
            priorityClasses[p]);
      } else {
        prioritySelect.addChild("option", ATTR_VALUE, String.valueOf(p), priorityClasses[p]);
      }
    }
    return priorityDiv;
  }

  private HTMLNode createRecommendControl(PageMaker pageMaker, ToadletContext ctx) {
    HTMLNode recommendDiv = new HTMLNode("div", ATTR_CLASS, "request-recommend");
    recommendDiv.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {INPUT_TYPE_SUBMIT, "recommend_request", l10n("recommendFilesToFriends")});
    return recommendDiv;
  }

  /**
   * Create a delete or restart control at the top of a table. It applies to whichever requests are
   * checked in the table below.
   */
  private HTMLNode createDeleteControl(
      PageMaker pageMaker, ToadletContext ctx, String mimeType, QueueType queueType) {
    HTMLNode deleteDiv = new HTMLNode("div", ATTR_CLASS, "request-delete");
    if (queueType == QueueType.COMPLETED_DOWNLOAD_TO_TEMP) {
      deleteDiv.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {INPUT_TYPE_SUBMIT, DELETE_REQUEST, l10n("deleteFilesFromTemp")});
    } else if (!queueType.isCompleted) {
      deleteDiv.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {INPUT_TYPE_SUBMIT, REMOVE_REQUEST, l10n("cancelSelected")});
    } else {
      deleteDiv.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {INPUT_TYPE_SUBMIT, REMOVE_REQUEST, l10n("removeFilesFromList")});
    }
    if (queueType == QueueType.COMPLETED_DOWNLOAD_TO_DISK) {
      deleteDiv.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {
            INPUT_TYPE_SUBMIT, REMOVE_FINISHED_DOWNLOADS_REQUEST, l10n("removeFinishedDownloads")
          });
    }
    if (queueType == QueueType.COMPLETED_UPLOAD) {
      deleteDiv.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {
            INPUT_TYPE_SUBMIT, REMOVE_FINISHED_UPLOADS_REQUEST, l10n("removeFinishedUploads")
          });
    }
    if (queueType.isFailed) {
      String restartName = NodeL10n.getBase().getString(QUEUE_TOADLET_PREFIX + "restartSelected");
      deleteDiv.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {INPUT_TYPE_SUBMIT, RESTART_REQUEST, restartName});
      if (mimeType != null) {
        deleteDiv.addChild(
            TAG_INPUT,
            new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
            new String[] {INPUT_TYPE_CHECKBOX, DISABLE_FILTER_DATA, DISABLE_FILTER_DATA});
        deleteDiv.addChild("#", l10n("disableFilter", "type", mimeType));
      }
    }
    return deleteDiv;
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

  private HTMLNode createIdentifierCell(FreenetURI uri, String identifier, boolean directory) {
    HTMLNode identifierCell = new HTMLNode("td", ATTR_CLASS, "request-identifier");
    if (uri != null) {
      identifierCell
          .addChild("span", ATTR_CLASS, "identifier_with_uri")
          .addChild("a", "href", "/" + uri + (directory ? "/" : ""), identifier);
    } else {
      identifierCell.addChild("span", ATTR_CLASS, "identifier_without_uri", identifier);
    }
    return identifierCell;
  }

  private HTMLNode createPersistenceCell(boolean persistent, boolean persistentForever) {
    HTMLNode persistenceCell = new HTMLNode("td", ATTR_CLASS, "request-persistence");
    if (persistentForever) {
      persistenceCell.addChild(
          "span", ATTR_CLASS, "persistence_forever", l10n("persistenceForever"));
    } else if (persistent) {
      persistenceCell.addChild("span", ATTR_CLASS, "persistence_reboot", l10n("persistenceReboot"));
    } else {
      persistenceCell.addChild("span", ATTR_CLASS, "persistence_none", l10n("persistenceNone"));
    }
    return persistenceCell;
  }

  private HTMLNode createTypeCell(String type) {
    HTMLNode typeCell = new HTMLNode("td", ATTR_CLASS, "request-type");
    if (type != null) {
      typeCell.addChild("span", ATTR_CLASS, "mimetype_is", type);
    } else {
      typeCell.addChild("span", ATTR_CLASS, "mimetype_unknown", l10n(UNKNOWN));
    }
    return typeCell;
  }

  private HTMLNode createSizeCell(long dataSize, boolean confirmed, boolean advancedModeEnabled) {
    HTMLNode sizeCell = new HTMLNode("td", ATTR_CLASS, "request-size");
    if (dataSize > 0 && (confirmed || advancedModeEnabled)) {
      sizeCell.addChild(
          "span",
          ATTR_CLASS,
          "filesize_is",
          (confirmed ? "" : ">= ") + SizeUtil.formatSize(dataSize) + (confirmed ? "" : " ??"));
    } else {
      sizeCell.addChild("span", ATTR_CLASS, "filesize_unknown", l10n(UNKNOWN));
    }
    return sizeCell;
  }

  private HTMLNode createKeyCell(FreenetURI uri, boolean addSlash) {
    HTMLNode keyCell = new HTMLNode("td", ATTR_CLASS, "request-key");
    if (uri != null) {
      keyCell
          .addChild("span", ATTR_CLASS, "key_is")
          .addChild(
              "a",
              "href",
              '/' + uri.toString() + (addSlash ? "/" : ""),
              uri.toShortString() + (addSlash ? "/" : ""));
    } else {
      keyCell.addChild("span", ATTR_CLASS, "key_unknown", l10n(UNKNOWN));
    }
    return keyCell;
  }

  private HTMLNode createBulkDownloadForm(ToadletContext ctx, PageMaker pageMaker) {
    InfoboxNode infobox = pageMaker.getInfobox(l10n(DOWNLOAD_FILES), GROUPED_DOWNLOADS, true);
    HTMLNode downloadBox = infobox.getOuterNode();
    HTMLNode downloadBoxContent = infobox.getContentNode();
    HTMLNode downloadForm = ctx.addFormChild(downloadBoxContent, path(), "queueDownloadForm");
    downloadForm.addChild("#", l10n("downloadFilesInstructions"));
    downloadForm.addChild("br");
    downloadForm.addChild(
        "textarea",
        new String[] {"id", "name", "cols", "rows"},
        new String[] {BULK_DOWNLOADS, BULK_DOWNLOADS, "120", "8"});
    downloadForm.addChild("br");
    PHYSICAL_THREAT_LEVEL threatLevel = core.getNode().getSecurityLevels().getPhysicalThreatLevel();
    // Force downloading to encrypted space if high/maximum threat level or if the user has disabled
    // downloading to disk.
    if (threatLevel == PHYSICAL_THREAT_LEVEL.HIGH
        || threatLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM
        || FProxyToadlet.isDownloadDisabledOrUnsafe(ctx, core)) {
      downloadForm.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {INPUT_TYPE_HIDDEN, TARGET, RETURN_TYPE_DIRECT});
    } else if (threatLevel == PHYSICAL_THREAT_LEVEL.LOW) {
      downloadForm.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {INPUT_TYPE_HIDDEN, TARGET, "disk"});
      selectLocation(downloadForm);
    } else {
      downloadForm.addChild("br");
      downloadForm
          .addChild(
              TAG_INPUT,
              new String[] {ATTR_TYPE, ATTR_VALUE, ATTR_NAME, "id"},
              new String[] {"radio", "disk", TARGET, BULK_DOWNLOAD_SELECT_OPTION_DISK}
              // Nicer spacing for radio button
              )
          .addChild(
              TAG_LABEL,
              new String[] {"for"},
              new String[] {BULK_DOWNLOAD_SELECT_OPTION_DISK},
              ' ' + l10n(BULK_DOWNLOAD_SELECT_OPTION_DISK) + ' ');
      selectLocation(downloadForm);
      downloadForm.addChild("br");
      downloadForm
          .addChild(
              TAG_INPUT,
              new String[] {ATTR_TYPE, ATTR_VALUE, ATTR_NAME, ATTR_CHECKED, "id"},
              new String[] {
                "radio",
                RETURN_TYPE_DIRECT,
                TARGET,
                ATTR_CHECKED,
                BULK_DOWNLOAD_SELECT_OPTION_DIRECT
              })
          .addChild(
              TAG_LABEL,
              new String[] {"for"},
              new String[] {BULK_DOWNLOAD_SELECT_OPTION_DIRECT},
              ' ' + l10n(BULK_DOWNLOAD_SELECT_OPTION_DIRECT) + ' ');
    }
    HTMLNode filterControl = downloadForm.addChild("div", l10n(FILTER_DATA));
    filterControl.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE, ATTR_CHECKED, "id"},
        new String[] {
          INPUT_TYPE_CHECKBOX, FILTER_DATA, FILTER_DATA, ATTR_CHECKED, FILTER_DATA_MESSAGE
        });
    filterControl.addChild(
        TAG_LABEL,
        new String[] {"for"},
        new String[] {FILTER_DATA_MESSAGE},
        l10n(FILTER_DATA_MESSAGE));
    downloadForm.addChild("br");
    downloadForm.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {INPUT_TYPE_SUBMIT, "insert", l10n("download")});
    return downloadBox;
  }

  private void selectLocation(HTMLNode node) {
    String downloadLocation = core.getDownloadsDir().getAbsolutePath();
    // If the download directory isn't allowed, yet downloading is, at least one directory must
    // have been explicitly defined, so take the first one.
    if (!core.allowDownloadTo(core.getDownloadsDir())) {
      downloadLocation = core.getAllowedDownloadDirs()[0].getAbsolutePath();
    }
    node.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE, "maxlength", "size"},
        new String[] {
          "text",
          "path",
          downloadLocation,
          Integer.toString(MAX_FILENAME_LENGTH),
          String.valueOf(downloadLocation.length())
        });
    node.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {INPUT_TYPE_SUBMIT, "select-location", l10n("browseToChange") + "..."});
  }

  /**
   * Creates a table cell that contains the time of the last activity, as per {@link
   * TimeUtil#formatTime(long)}.
   *
   * @param now The current time (for a unified point of reference for the whole page)
   * @param lastActivity The last activity of the request
   * @return The created table cell HTML node
   */
  private HTMLNode createLastActivityCell(long now, Date lastActivity) {
    HTMLNode lastActivityCell = new HTMLNode("td", ATTR_CLASS, "request-last-activity");
    if (lastActivity == null) {
      // During normal operation, lastActivity will never be null even if there was no
      // activity yet. It will default to the Date when the request was added. (See
      // ClientRequester.getLatestSuccess() for the usability motivation behind that.)
      // lastActivity can however be null if the user had been using a pre-release of
      // purge-db4o which did not store the lastActivity Date to the database yet.
      // Thus, we initialize to "unknown" instead of "never" to stress that there was possibly
      // activity but we cannot know because the Date was not stored yet.
      lastActivityCell.addChild("i", l10n("lastActivity.unknown"));
    } else {
      lastActivityCell.addChild(
          "#", l10n("lastActivity.ago", "time", TimeUtil.formatTime(now - lastActivity.getTime())));
    }
    return lastActivityCell;
  }

  /**
   * @see #createLastActivityCell(long, Date)
   */
  private HTMLNode createLastFailureCell(long now, Date lastFailure) {
    HTMLNode lastFailureCell = new HTMLNode("td", ATTR_CLASS, "request-last-failure");
    if (lastFailure == null) {
      // This is "never" instead of "unknown" because the backend of RequestStatus uses null
      // to signalize that no failure has happened yet.
      lastFailureCell.addChild("i", l10n("lastFailure.never"));
    } else {
      lastFailureCell.addChild(
          "#", l10n("lastFailure.ago", "time", TimeUtil.formatTime(now - lastFailure.getTime())));
    }
    return lastFailureCell;
  }

  private HTMLNode createRequestTable(
      PageMaker pageMaker,
      ToadletContext ctx,
      List<? extends RequestStatus> requests,
      QueueColumn[] columns,
      String[] priorityClasses,
      boolean advancedModeEnabled,
      String id,
      QueueType queueType) {
    return createRequestTable(
        pageMaker,
        ctx,
        requests,
        columns,
        priorityClasses,
        advancedModeEnabled,
        id,
        null,
        queueType);
  }

  private HTMLNode createRequestTable(
      PageMaker pageMaker,
      ToadletContext ctx,
      List<? extends RequestStatus> requests,
      QueueColumn[] columns,
      String[] priorityClasses,
      boolean advancedModeEnabled,
      String id,
      String mimeType,
      QueueType queueType) {
    boolean hasFriends = core.getNode().getDarknetConnections().length > 0;
    long now = System.currentTimeMillis();

    HTMLNode formDiv = new HTMLNode("div", ATTR_CLASS, "request-table-form");
    HTMLNode form = createRequestForm(ctx, id, advancedModeEnabled, formDiv);

    createRequestTableButtons(
        form,
        pageMaker,
        ctx,
        mimeType,
        hasFriends,
        advancedModeEnabled,
        priorityClasses,
        true,
        queueType);

    HTMLNode table = form.addChild(TAG_TABLE, ATTR_CLASS, "requests");
    HTMLNode headerRow = table.addChild("tr", ATTR_CLASS, "table-header");
    headerRow.addChild("th");
    addHeaderCells(headerRow, columns);

    addRequestRows(
        table, requests, columns, priorityClasses, ctx, advancedModeEnabled, now, queueType);

    createRequestTableButtons(
        form,
        pageMaker,
        ctx,
        mimeType,
        hasFriends,
        advancedModeEnabled,
        priorityClasses,
        false,
        queueType);
    return formDiv;
  }

  private HTMLNode createRequestForm(
      ToadletContext ctx, String id, boolean advancedModeEnabled, HTMLNode formDiv) {
    return ctx.addFormChild(
        formDiv,
        path(),
        "request-table-form-" + id + (advancedModeEnabled ? "-advanced" : "-simple"));
  }

  private void addHeaderCells(HTMLNode headerRow, QueueColumn[] columns) {
    for (QueueColumn column : columns) {
      addHeaderCell(headerRow, column);
    }
  }

  private void addHeaderCell(HTMLNode headerRow, QueueColumn column) {
    switch (column) {
      case IDENTIFIER:
        headerRow
            .addChild("th")
            .addChild("a", "href", (isReversed ? "?sortBy=id" : "?sortBy=id&reversed"))
            .addChild("#", l10n("identifier"));
        break;
      case SIZE:
        headerRow
            .addChild("th")
            .addChild("a", "href", (isReversed ? "?sortBy=size" : "?sortBy=size&reversed"))
            .addChild("#", l10n("size"));
        break;
      case MIME_TYPE:
        headerRow.addChild("th", l10n("mimeType"));
        break;
      case PERSISTENCE:
        headerRow.addChild("th", l10n("persistence"));
        break;
      case KEY:
        headerRow.addChild("th", l10n("key"));
        break;
      case FILENAME:
        headerRow.addChild("th", l10n("fileName"));
        break;
      case PRIORITY:
        headerRow.addChild("th", l10n(PRIORITY));
        break;
      case FILES:
        headerRow.addChild("th", l10n("files"));
        break;
      case TOTAL_SIZE:
        headerRow.addChild("th", l10n("totalSize"));
        break;
      case PROGRESS:
        headerRow
            .addChild("th")
            .addChild("a", "href", (isReversed ? "?sortBy=progress" : "?sortBy=progress&reversed"))
            .addChild("#", l10n("progress"));
        break;
      case REASON:
        headerRow.addChild("th", l10n("reason"));
        break;
      case LAST_ACTIVITY:
        headerRow
            .addChild("th")
            .addChild(
                "a",
                "href",
                (isReversed ? "?sortBy=lastActivity" : "?sortBy=lastActivity&reversed"),
                l10n("lastActivity"));
        break;
      case LAST_FAILURE:
        headerRow
            .addChild("th")
            .addChild(
                "a",
                "href",
                (isReversed ? "?sortBy=lastFailure" : "?sortBy=lastFailure&reversed"),
                l10n("lastFailure"));
        break;
      case COMPAT_MODE:
        headerRow.addChild("th", l10n(COMPATIBILITY_MODE_FIELD));
        break;
    }
  }

  private void addRequestRows(
      HTMLNode table,
      List<? extends RequestStatus> requests,
      QueueColumn[] columns,
      String[] priorityClasses,
      ToadletContext ctx,
      boolean advancedModeEnabled,
      long now,
      QueueType queueType) {
    int index = 0;
    for (RequestStatus clientRequest : requests) {
      addRequestRow(
          table,
          columns,
          priorityClasses,
          ctx,
          advancedModeEnabled,
          now,
          queueType,
          index++,
          clientRequest);
    }
  }

  private void addRequestRow(
      HTMLNode table,
      QueueColumn[] columns,
      String[] priorityClasses,
      ToadletContext ctx,
      boolean advancedModeEnabled,
      long now,
      QueueType queueType,
      int index,
      RequestStatus clientRequest) {
    HTMLNode requestRow = table.addChild("tr", ATTR_CLASS, PRIORITY + clientRequest.getPriority());
    requestRow.addChild(createCheckboxCell(clientRequest, index));

    for (QueueColumn column : columns) {
      HTMLNode cell =
          createColumnCell(
              column, clientRequest, ctx, priorityClasses, advancedModeEnabled, now, queueType);
      if (cell != null) {
        requestRow.addChild(cell);
      }
    }
  }

  private HTMLNode createColumnCell(
      QueueColumn column,
      RequestStatus clientRequest,
      ToadletContext ctx,
      String[] priorityClasses,
      boolean advancedModeEnabled,
      long now,
      QueueType queueType) {
    return switch (column) {
      case IDENTIFIER ->
          createIdentifierCell(
              clientRequest.getURI(),
              clientRequest.getIdentifier(),
              clientRequest instanceof UploadDirRequestStatus);
      case SIZE -> createSizeCellForRequest(clientRequest, advancedModeEnabled);
      case MIME_TYPE -> createMimeTypeCell(clientRequest);
      case PERSISTENCE ->
          createPersistenceCell(clientRequest.isPersistent(), clientRequest.isPersistentForever());
      case KEY -> createKeyCellForRequest(clientRequest);
      case FILENAME -> createFilenameCellForRequest(clientRequest);
      case PRIORITY -> createPriorityCell(clientRequest.getPriority(), priorityClasses);
      case FILES -> createNumberCell(((UploadDirRequestStatus) clientRequest).getNumberOfFiles());
      case TOTAL_SIZE ->
          createSizeCell(
              ((UploadDirRequestStatus) clientRequest).getTotalDataSize(),
              true,
              advancedModeEnabled);
      case PROGRESS -> createProgressCellForRequest(ctx, clientRequest, queueType.isUpload);
      case REASON -> createReasonCell(clientRequest.getFailureReason(false));
      case LAST_ACTIVITY -> createLastActivityCell(now, clientRequest.getLastSuccess());
      case LAST_FAILURE -> createLastFailureCell(now, clientRequest.getLastFailure());
      case COMPAT_MODE -> createCompatModeCellForRequest(clientRequest);
    };
  }

  private HTMLNode createSizeCellForRequest(
      RequestStatus clientRequest, boolean advancedModeEnabled) {
    boolean isFinal =
        !(clientRequest instanceof DownloadRequestStatus) || clientRequest.isTotalFinalized();
    return createSizeCell(clientRequest.getDataSize(), isFinal, advancedModeEnabled);
  }

  private HTMLNode createMimeTypeCell(RequestStatus clientRequest) {
    if (clientRequest instanceof DownloadRequestStatus downloadStatus) {
      return createTypeCell(downloadStatus.getMIMEType());
    }
    if (clientRequest instanceof UploadFileRequestStatus uploadStatus) {
      return createTypeCell(uploadStatus.getMIMEType());
    }
    return null;
  }

  private HTMLNode createKeyCellForRequest(RequestStatus clientRequest) {
    if (clientRequest instanceof DownloadRequestStatus) {
      return createKeyCell(clientRequest.getURI(), false);
    }
    if (clientRequest instanceof UploadFileRequestStatus uploadStatus) {
      return createKeyCell(uploadStatus.getFinalURI(), false);
    }
    return createKeyCell(((UploadDirRequestStatus) clientRequest).getFinalURI(), true);
  }

  private HTMLNode createFilenameCellForRequest(RequestStatus clientRequest) {
    if (clientRequest instanceof DownloadRequestStatus downloadStatus) {
      return createFilenameCell(downloadStatus.getDestFilename());
    }
    if (clientRequest instanceof UploadFileRequestStatus uploadStatus) {
      return createFilenameCell(uploadStatus.getOrigFilename());
    }
    return null;
  }

  private HTMLNode createProgressCellForRequest(
      ToadletContext ctx, RequestStatus clientRequest, boolean isUploadQueue) {
    if (clientRequest instanceof UploadFileRequestStatus uploadStatus) {
      return createProgressCell(
          ctx.isAdvancedModeEnabled(),
          clientRequest.isStarted(),
          uploadStatus.isCompressing(),
          clientRequest.getFetchedBlocks(),
          clientRequest.getFailedBlocks(),
          clientRequest.getFatalyFailedBlocks(),
          clientRequest.getMinBlocks(),
          clientRequest.getTotalBlocks(),
          clientRequest.isTotalFinalized() || clientRequest instanceof UploadFileRequestStatus,
          isUploadQueue);
    }
    return createProgressCell(
        ctx.isAdvancedModeEnabled(),
        clientRequest.isStarted(),
        COMPRESS_STATE.WORKING,
        clientRequest.getFetchedBlocks(),
        clientRequest.getFailedBlocks(),
        clientRequest.getFatalyFailedBlocks(),
        clientRequest.getMinBlocks(),
        clientRequest.getTotalBlocks(),
        clientRequest.isTotalFinalized() || clientRequest instanceof UploadFileRequestStatus,
        isUploadQueue);
  }

  private HTMLNode createCompatModeCellForRequest(RequestStatus clientRequest) {
    if (clientRequest instanceof DownloadRequestStatus downloadStatus) {
      return createCompatModeCell(downloadStatus);
    }
    return new HTMLNode("td");
  }

  private boolean queueCannotRecommend(QueueType queueType) {
    return queueType.isUpload && !queueType.isCompleted;
  }

  private void createRequestTableButtons(
      HTMLNode form,
      PageMaker pageMaker,
      ToadletContext ctx,
      String mimeType,
      boolean hasFriends,
      boolean advancedModeEnabled,
      String[] priorityClasses,
      boolean top,
      QueueType queueType) {
    form.addChild(createDeleteControl(pageMaker, ctx, mimeType, queueType));
    if (hasFriends && !queueCannotRecommend(queueType)) {
      form.addChild(createRecommendControl(pageMaker, ctx));
    }
    if (!(queueType.isFailed || queueType.isCompleted)) {
      form.addChild(
          createPriorityControl(
              pageMaker,
              ctx,
              RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS,
              priorityClasses,
              advancedModeEnabled,
              queueType.isUpload,
              top ? "_top" : "_bottom"));
    }
  }

  private HTMLNode createCheckboxCell(RequestStatus clientRequest, int counter) {
    HTMLNode cell = new HTMLNode("td", ATTR_CLASS, "checkbox-cell");
    String identifier = clientRequest.getIdentifier();
    cell.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {INPUT_TYPE_CHECKBOX, IDENTIFIER_PREFIX + counter, identifier});
    FreenetURI uri;
    long size = -1;
    String filename = null;
    if (clientRequest instanceof DownloadRequestStatus) {
      uri = clientRequest.getURI();
      size = clientRequest.getDataSize();
    } else if (clientRequest instanceof UploadRequestStatus status) {
      uri = status.getFinalURI();
      size = clientRequest.getDataSize();
    } else {
      uri = null;
    }
    if (uri != null) {
      cell.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {INPUT_TYPE_HIDDEN, KEY_PREFIX + counter, uri.toASCIIString()});
    }
    filename = clientRequest.getPreferredFilenameSafe();
    if (size != -1)
      cell.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {INPUT_TYPE_HIDDEN, "size-" + counter, Long.toString(size)});
    if (filename != null)
      cell.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {INPUT_TYPE_HIDDEN, FILENAME_PREFIX + counter, filename});
    return cell;
  }

  private HTMLNode createCompatModeCell(DownloadRequestStatus get) {
    HTMLNode compatCell = new HTMLNode("td", ATTR_CLASS, "request-compat-mode");
    InsertContext.CompatibilityMode[] compat = get.getCompatibilityMode();
    if (!(compat[0] == InsertContext.CompatibilityMode.COMPAT_UNKNOWN
        && compat[1] == InsertContext.CompatibilityMode.COMPAT_UNKNOWN)) {
      if (compat[0] == compat[1])
        compatCell.addChild(
            "#",
            NodeL10n.getBase()
                .getString(
                    INSERT_CONTEXT_COMPATIBILITY_MODE_PREFIX + compat[0].name())); // FIXME l10n
      else
        compatCell.addChild(
            "#",
            NodeL10n.getBase()
                    .getString(INSERT_CONTEXT_COMPATIBILITY_MODE_PREFIX + compat[0].name())
                + " - "
                + NodeL10n.getBase()
                    .getString(
                        INSERT_CONTEXT_COMPATIBILITY_MODE_PREFIX + compat[1].name())); // FIXME l10n
      byte[] overrideCryptoKey = get.getOverriddenSplitfileCryptoKey();
      if (overrideCryptoKey != null)
        compatCell.addChild(
            "#",
            " - "
                + l10n("overriddenCryptoKeyInCompatCell")
                + ": "
                + HexUtil.bytesToHex(overrideCryptoKey));
      if (get.detectedDontCompress())
        compatCell.addChild("#", " (" + l10n("dontCompressInCompatCell") + ")");
    }
    return compatCell;
  }

  /** List of completed request identifiers which the user hasn't acknowledged yet. */
  private final HashSet<String> completedRequestIdentifiers = new HashSet<>();

  private final Map<String, GetCompletedEvent> completedGets = new LinkedHashMap<>();
  private final Map<String, PutCompletedEvent> completedPuts = new LinkedHashMap<>();
  private final Map<String, PutDirCompletedEvent> completedPutDirs = new LinkedHashMap<>();

  @Override
  public void notifyFailure(ClientRequest req) {
    // FIXME do something???
  }

  @Override
  public void notifySuccess(ClientRequest req) {
    if (uploads == req instanceof ClientGet) return;
    synchronized (completedRequestIdentifiers) {
      completedRequestIdentifiers.add(req.getIdentifier());
    }
    registerAlert(req); // should be safe here
    saveCompletedIdentifiersOffThread();
  }

  private void saveCompletedIdentifiersOffThread() {
    core.getExecutor().execute(this::saveCompletedIdentifiers, "Save completed identifiers");
  }

  private void loadCompletedIdentifiers() throws PersistenceDisabledException {
    String dl = uploads ? "uploads" : "downloads";
    File completedIdentifiersList = core.getNode().userDir().file(COMPLETED_LIST_PREFIX + dl);
    File completedIdentifiersListNew =
        core.getNode().userDir().file(COMPLETED_LIST_PREFIX + dl + ".bak");
    File oldCompletedIdentifiersList = core.getNode().userDir().file("completed.list");
    boolean migrated = false;
    if (!readCompletedIdentifiers(completedIdentifiersList)) {
      if (!readCompletedIdentifiers(completedIdentifiersListNew)) {
        readCompletedIdentifiers(oldCompletedIdentifiersList);
        migrated = true;
      }
    } else if (!oldCompletedIdentifiersList.delete()) {
      LOG.warn(
          "Failed to delete legacy completed identifiers list {}", oldCompletedIdentifiersList);
    }
    final boolean writeAnyway = migrated;
    core.getClientContext()
        .jobRunner
        .queue(
            new PersistentJob() {

              @Override
              public String toString() {
                return "QueueToadlet LoadCompletedIdentifiers";
              }

              @Override
              public boolean run(ClientContext context) {
                String[] identifiers;
                boolean changed = writeAnyway;
                synchronized (completedRequestIdentifiers) {
                  identifiers = completedRequestIdentifiers.toArray(new String[0]);
                }
                for (String identifier : identifiers) {
                  ClientRequest req = fcp.getGlobalRequest(identifier);
                  if (req == null || req instanceof ClientGet == uploads) {
                    synchronized (completedRequestIdentifiers) {
                      completedRequestIdentifiers.remove(identifier);
                    }
                    changed = true;
                    continue;
                  }
                  registerAlert(req);
                }
                if (changed) saveCompletedIdentifiers();
                return false;
              }
            },
            NativeThread.PriorityLevel.HIGH_PRIORITY.value);
  }

  private boolean readCompletedIdentifiers(File file) {
    try (FileInputStream fis = new FileInputStream(file);
        BufferedInputStream bis = new BufferedInputStream(fis);
        InputStreamReader isr = new InputStreamReader(bis, StandardCharsets.UTF_8);
        BufferedReader br = new BufferedReader(isr)) {
      synchronized (completedRequestIdentifiers) {
        completedRequestIdentifiers.clear();
        while (true) {
          String identifier = br.readLine();
          if (identifier == null) return true;
          completedRequestIdentifiers.add(identifier);
        }
      }
    } catch (EOFException e) {
      // Normal
      return true;
    } catch (FileNotFoundException e) {
      // Normal
      return false;
    } catch (IOException e) {
      LOG.error("Could not read completed identifiers list from {}", file);
      return false;
    }
  }

  private void saveCompletedIdentifiers() {
    String dl = uploads ? "uploads" : "downloads";
    File completedIdentifiersList = core.getNode().userDir().file(COMPLETED_LIST_PREFIX + dl);
    File completedIdentifiersListNew =
        core.getNode().userDir().file(COMPLETED_LIST_PREFIX + dl + ".bak");
    File temp;
    try {
      temp = File.createTempFile("completed.list", ".tmp", core.getNode().getUserDir());
      temp.deleteOnExit();
      try (FileOutputStream fos = new FileOutputStream(temp);
          OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
          BufferedWriter bw = new BufferedWriter(osw)) {
        String[] identifiers;
        synchronized (completedRequestIdentifiers) {
          identifiers = completedRequestIdentifiers.toArray(new String[0]);
        }
        for (String identifier : identifiers) bw.write(identifier + '\n');
      }
    } catch (FileNotFoundException e) {
      LOG.error("Unable to save completed requests list (can't find node directory?!!?): {}", e, e);
      return;
    } catch (IOException e) {
      LOG.error("Unable to save completed requests list: {}", e, e);
      return;
    }
    if (completedIdentifiersListNew.exists() && !completedIdentifiersListNew.delete()) {
      LOG.warn(
          "Unable to delete backup completed identifiers list {}", completedIdentifiersListNew);
    }
    boolean renamedToBackup = temp.renameTo(completedIdentifiersListNew);
    if (!renamedToBackup) {
      LOG.error(
          "Unable to store completed identifiers list because unable to rename {} to {}",
          temp,
          completedIdentifiersListNew);
    }
    if (!completedIdentifiersListNew.renameTo(completedIdentifiersList)) {
      if (completedIdentifiersList.exists() && !completedIdentifiersList.delete()) {
        LOG.warn(
            "Unable to delete existing completed identifiers list {}", completedIdentifiersList);
      }
      if (!completedIdentifiersListNew.renameTo(completedIdentifiersList)) {
        LOG.error(
            "Unable to store completed identifiers list because unable to rename {} to {}",
            completedIdentifiersListNew,
            completedIdentifiersList);
      }
    }
  }

  private void registerAlert(ClientRequest req) {
    final String identifier = req.getIdentifier();
    if (LOG.isDebugEnabled()) LOG.debug("Registering alert for {}", identifier);
    if (!req.hasFinished()) {
      if (LOG.isDebugEnabled()) LOG.debug("Request hasn't finished: {} for {}", req, identifier);
      return;
    }
    if (req instanceof ClientGet get) {
      FreenetURI uri = get.getURI();
      if (uri == null) {
        LOG.error(NO_URI_FOR_FINISHED_REQUEST, req);
        return;
      }
      long size = get.getDataSize();
      GetCompletedEvent event = new GetCompletedEvent(identifier, uri, size);
      synchronized (completedGets) {
        completedGets.put(identifier, event);
      }
      core.getAlerts().register(event);
    } else if (req instanceof ClientPut put) {
      FreenetURI uri = put.getFinalURI();
      if (uri == null) {
        LOG.error(NO_URI_FOR_FINISHED_REQUEST, req);
        return;
      }
      long size = put.getDataSize();
      PutCompletedEvent event = new PutCompletedEvent(identifier, uri, size);
      synchronized (completedPuts) {
        completedPuts.put(identifier, event);
      }
      core.getAlerts().register(event);
    } else if (req instanceof ClientPutDir dir) {
      FreenetURI uri = dir.getFinalURI();
      if (uri == null) {
        LOG.error(NO_URI_FOR_FINISHED_REQUEST, req);
        return;
      }
      long size = dir.getTotalDataSize();
      int files = dir.getNumberOfFiles();
      PutDirCompletedEvent event = new PutDirCompletedEvent(identifier, uri, size, files);
      synchronized (completedPutDirs) {
        completedPutDirs.put(identifier, event);
      }
      core.getAlerts().register(event);
    }
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

  @Override
  public void onRemove(ClientRequest req) {
    String identifier = req.getIdentifier();
    synchronized (completedRequestIdentifiers) {
      completedRequestIdentifiers.remove(identifier);
    }
    if (req instanceof ClientGet)
      synchronized (completedGets) {
        completedGets.remove(identifier);
      }
    else if (req instanceof ClientPut)
      synchronized (completedPuts) {
        completedPuts.remove(identifier);
      }
    else if (req instanceof ClientPutDir)
      synchronized (completedPutDirs) {
        completedPutDirs.remove(identifier);
      }
    saveCompletedIdentifiersOffThread();
  }

  @Override
  public boolean isEnabled(ToadletContext ctx) {
    return (!container.publicGatewayMode()) || ((ctx != null) && ctx.isAllowedFullAccess());
  }

  private static final String DEFAULT_UPLOADS_SEGMENT = "uploads";
  private static final String DEFAULT_DOWNLOADS_SEGMENT = "downloads";

  static final String PATH_UPLOADS =
      normalizePath(System.getProperty("queue.uploads.path", DEFAULT_UPLOADS_SEGMENT));
  static final String PATH_DOWNLOADS =
      normalizePath(System.getProperty("queue.downloads.path", DEFAULT_DOWNLOADS_SEGMENT));

  static final HTMLNode DOWNLOADS_LINK = HTMLNode.link(PATH_DOWNLOADS).setReadOnly();
  static final HTMLNode UPLOADS_LINK = HTMLNode.link(PATH_UPLOADS).setReadOnly();

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

  private class GetCompletedEvent extends StoringUserEvent<GetCompletedEvent> {

    private final String identifier;
    private final FreenetURI uri;
    private final long size;

    public GetCompletedEvent(String identifier, FreenetURI uri, long size) {
      super(
          Type.GET_COMPLETED,
          true,
          null,
          null,
          null,
          null,
          UserAlert.MINOR,
          true,
          NodeL10n.getBase().getString(USER_ALERT_HIDE),
          true,
          completedGets);
      this.identifier = identifier;
      this.uri = uri;
      this.size = size;
    }

    @Override
    public void onDismiss() {
      super.onDismiss();
      saveCompletedIdentifiersOffThread();
    }

    @Override
    public void onEventDismiss() {
      synchronized (completedRequestIdentifiers) {
        completedRequestIdentifiers.remove(identifier);
      }
    }

    @Override
    public HTMLNode getEventHTMLText() {
      HTMLNode text = new HTMLNode("div");
      NodeL10n.getBase()
          .addL10nSubstitution(
              text,
              QUEUE_TOADLET_PREFIX + "downloadSucceeded",
              new String[] {"link", "origlink", FILENAME, "size"},
              new HTMLNode[] {
                HTMLNode.link("/" + uri.toASCIIString() + "?max-size=" + size),
                HTMLNode.link("/" + uri.toASCIIString()),
                HTMLNode.text(uri.getPreferredFilename()),
                HTMLNode.text(SizeUtil.formatSize(size))
              });
      return text;
    }

    @Override
    public String getTitle() {
      String title = null;
      synchronized (events) {
        if (events.size() == 1)
          title = l10n("downloadSucceededTitle", FILENAME, uri.getPreferredFilename());
        else title = l10n("downloadsSucceededTitle", "nr", Integer.toString(events.size()));
      }
      return title;
    }

    @Override
    public String getShortText() {
      return getTitle();
    }

    @Override
    public String getEventText() {
      return l10n("downloadSucceededTitle", FILENAME, uri.getPreferredFilename());
    }
  }

  private class PutCompletedEvent extends StoringUserEvent<PutCompletedEvent> {

    private final String identifier;
    private final FreenetURI uri;
    private final long size;

    public PutCompletedEvent(String identifier, FreenetURI uri, long size) {
      super(
          Type.PUT_COMPLETED,
          true,
          null,
          null,
          null,
          null,
          UserAlert.MINOR,
          true,
          NodeL10n.getBase().getString(USER_ALERT_HIDE),
          true,
          completedPuts);
      this.identifier = identifier;
      this.uri = uri;
      this.size = size;
    }

    @Override
    public void onDismiss() {
      super.onDismiss();
      saveCompletedIdentifiersOffThread();
    }

    @Override
    public void onEventDismiss() {
      synchronized (completedRequestIdentifiers) {
        completedRequestIdentifiers.remove(identifier);
      }
    }

    @Override
    public HTMLNode getEventHTMLText() {
      HTMLNode text = new HTMLNode("div");
      NodeL10n.getBase()
          .addL10nSubstitution(
              text,
              QUEUE_TOADLET_PREFIX + "uploadSucceeded",
              new String[] {"link", FILENAME, "size"},
              new HTMLNode[] {
                HTMLNode.link("/" + uri.toASCIIString()),
                HTMLNode.text(uri.getPreferredFilename()),
                HTMLNode.text(SizeUtil.formatSize(size))
              });
      return text;
    }

    @Override
    public String getTitle() {
      String title = null;
      synchronized (events) {
        if (events.size() == 1)
          title = l10n("uploadSucceededTitle", FILENAME, uri.getPreferredFilename());
        else title = l10n("uploadsSucceededTitle", "nr", Integer.toString(events.size()));
      }
      return title;
    }

    @Override
    public String getShortText() {
      return getTitle();
    }

    @Override
    public String getEventText() {
      return l10n("uploadSucceededTitle", FILENAME, uri.getPreferredFilename());
    }
  }

  private class PutDirCompletedEvent extends StoringUserEvent<PutDirCompletedEvent> {

    private final String identifier;
    private final FreenetURI uri;
    private final long size;
    private final int files;

    public PutDirCompletedEvent(String identifier, FreenetURI uri, long size, int files) {
      super(
          Type.PUT_DIR_COMPLETED,
          true,
          null,
          null,
          null,
          null,
          UserAlert.MINOR,
          true,
          NodeL10n.getBase().getString(USER_ALERT_HIDE),
          true,
          completedPutDirs);
      this.identifier = identifier;
      this.uri = uri;
      this.size = size;
      this.files = files;
    }

    @Override
    public void onDismiss() {
      super.onDismiss();
      saveCompletedIdentifiersOffThread();
    }

    @Override
    public void onEventDismiss() {
      synchronized (completedRequestIdentifiers) {
        completedRequestIdentifiers.remove(identifier);
      }
    }

    @Override
    public HTMLNode getEventHTMLText() {
      String name = uri.getPreferredFilename();
      HTMLNode text = new HTMLNode("div");
      NodeL10n.getBase()
          .addL10nSubstitution(
              text,
              QUEUE_TOADLET_PREFIX + "siteUploadSucceeded",
              new String[] {"link", FILENAME, "size", "files"},
              new HTMLNode[] {
                HTMLNode.link("/" + uri.toASCIIString()),
                HTMLNode.text(name),
                HTMLNode.text(SizeUtil.formatSize(size)),
                HTMLNode.text(files)
              });
      return text;
    }

    @Override
    public String getTitle() {
      String title = null;
      synchronized (events) {
        if (events.size() == 1)
          title = l10n("siteUploadSucceededTitle", FILENAME, uri.getPreferredFilename());
        else title = l10n("sitesUploadSucceededTitle", "nr", Integer.toString(events.size()));
      }
      return title;
    }

    @Override
    public String getShortText() {
      return getTitle();
    }

    @Override
    public String getEventText() {
      return l10n("siteUploadSucceededTitle", FILENAME, uri.getPreferredFilename());
    }
  }
}
