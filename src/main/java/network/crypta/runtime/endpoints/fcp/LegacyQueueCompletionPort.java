package network.crypta.runtime.endpoints.fcp;

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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.PersistentJob;
import network.crypta.clients.fcp.ClientGet;
import network.crypta.clients.fcp.ClientPut;
import network.crypta.clients.fcp.ClientPutDir;
import network.crypta.clients.fcp.ClientRequest;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.RequestCompletionCallback;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.alerts.StoringUserEvent;
import network.crypta.runtime.alerts.UserAlert;
import network.crypta.runtime.alerts.UserEvent;
import network.crypta.runtime.spi.QueueCompletionPort;
import network.crypta.support.HTMLNode;
import network.crypta.support.SizeUtil;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Legacy daemon-backed implementation of the queue-completion runtime SPI.
 *
 * <p>This adapter keeps the remaining queue completion-tracking behavior inside the daemon root
 * module: FCP completion callback registration, completed-request persistence and recovery, and
 * completion user-alert registration. The HTTP layer only asks the adapter to ensure tracking is
 * active for one queue side and no longer depends directly on daemon-owned queue or alert types.
 *
 * <p>Tracking startup is idempotent per side. Repeated calls for downloads or uploads must not
 * register duplicate callbacks or repeat recovery work for that side, but downloads and uploads
 * still keep separate persisted identifier sets and alert collections exactly as before.
 */
public final class LegacyQueueCompletionPort implements QueueCompletionPort {
  private static final Logger LOG = LoggerFactory.getLogger(LegacyQueueCompletionPort.class);

  private static final String COMPLETED_LIST_PREFIX = "completed.list.";
  private static final String LEGACY_COMPLETED_LIST = "completed.list";
  private static final String DOWNLOADS_SEGMENT = "downloads";
  private static final String UPLOADS_SEGMENT = "uploads";
  private static final String QUEUE_TOADLET_PREFIX = "QueueToadlet.";
  private static final String USER_ALERT_HIDE = "UserAlert.hide";
  private static final String FILENAME_L10N_KEY = "filename";

  private final NodeClientCore core;
  private final Object trackingLock = new Object();

  private QueueCompletionTracker downloadTracker;
  private QueueCompletionTracker uploadTracker;

  /**
   * Creates a queue-completion adapter backed by the supplied client core.
   *
   * <p>The adapter resolves the live {@link FCPServer} lazily from the endpoint wiring when
   * tracking is started or replay runs. Construction itself, therefore, does not force early FCP
   * server access during startup.
   *
   * @param core live daemon client core that owns the endpoint registry, alerts, and persistence
   *     infrastructure
   */
  public LegacyQueueCompletionPort(NodeClientCore core) {
    this.core = Objects.requireNonNull(core);
  }

  @Override
  public void ensureTrackingStarted(boolean uploads) {
    synchronized (trackingLock) {
      if (trackerFor(uploads) != null) {
        return;
      }

      QueueCompletionTracker tracker = new QueueCompletionTracker(uploads);
      fcpServer().setCompletionCallback(tracker);
      if (uploads) {
        uploadTracker = tracker;
      } else {
        downloadTracker = tracker;
      }
      try {
        tracker.loadCompletedIdentifiers();
      } catch (PersistenceDisabledException _) {
        // Preserve the legacy tolerance during startup recovery.
      }
    }
  }

  private QueueCompletionTracker trackerFor(boolean uploads) {
    return uploads ? uploadTracker : downloadTracker;
  }

  private FCPServer fcpServer() {
    FCPServer fcpServer = FcpEndpointHandles.serverOrNull(core.getEndpoints().getFcpEndpoint());
    if (fcpServer == null) {
      throw new IllegalStateException("FCP server unavailable");
    }
    return fcpServer;
  }

  private final class QueueCompletionTracker implements RequestCompletionCallback {
    private final boolean uploads;
    private final HashSet<String> completedRequestIdentifiers = new HashSet<>();
    private final Map<String, GetCompletedEvent> completedGets = new LinkedHashMap<>();
    private final Map<String, PutCompletedEvent> completedPuts = new LinkedHashMap<>();
    private final Map<String, PutDirCompletedEvent> completedPutDirs = new LinkedHashMap<>();

    private QueueCompletionTracker(boolean uploads) {
      this.uploads = uploads;
    }

    @Override
    public void notifyFailure(ClientRequest req) {
      LOG.debug(
          "Request {} failed; no further action registered in QueueToadlet", req.getIdentifier());
    }

    @Override
    public void notifySuccess(ClientRequest req) {
      if (uploads == req instanceof ClientGet) {
        return;
      }
      synchronized (completedRequestIdentifiers) {
        completedRequestIdentifiers.add(req.getIdentifier());
      }
      registerAlert(req);
      saveCompletedIdentifiersOffThread();
    }

    @Override
    public void onRemove(ClientRequest req) {
      String identifier = req.getIdentifier();
      synchronized (completedRequestIdentifiers) {
        completedRequestIdentifiers.remove(identifier);
      }
      switch (req) {
        case ClientGet _ -> {
          synchronized (completedGets) {
            completedGets.remove(identifier);
          }
        }
        case ClientPut _ -> {
          synchronized (completedPuts) {
            completedPuts.remove(identifier);
          }
        }
        case ClientPutDir _ -> {
          synchronized (completedPutDirs) {
            completedPutDirs.remove(identifier);
          }
        }
        default -> {
          // Nothing to remove for other request types.
        }
      }
      saveCompletedIdentifiersOffThread();
    }

    private void saveCompletedIdentifiersOffThread() {
      core.getNode()
          .network()
          .executor()
          .execute(this::saveCompletedIdentifiers, "Save completed identifiers");
    }

    private void loadCompletedIdentifiers() throws PersistenceDisabledException {
      File completedIdentifiersList = completedIdentifiersFile();
      File completedIdentifiersListNew = completedIdentifiersBackupFile();
      File oldCompletedIdentifiersList = core.getNode().userDir().file(LEGACY_COMPLETED_LIST);
      boolean migrated = false;
      if (!readCompletedIdentifiers(completedIdentifiersList)) {
        if (!readCompletedIdentifiers(completedIdentifiersListNew)) {
          readCompletedIdentifiers(oldCompletedIdentifiersList);
          migrated = true;
        }
      } else {
        deleteIfExists(
            oldCompletedIdentifiersList,
            "legacy completed identifiers list " + oldCompletedIdentifiersList);
      }
      final boolean writeAnyway = migrated;
      core.getClientContext()
          .jobRunner
          .queue(
              new PersistentJob() {

                @Override
                public String toString() {
                  return "LegacyQueueCompletionPort LoadCompletedIdentifiers";
                }

                @Override
                public boolean run(ClientContext context) {
                  String[] identifiers;
                  boolean changed = writeAnyway;
                  synchronized (completedRequestIdentifiers) {
                    identifiers = completedRequestIdentifiers.toArray(new String[0]);
                  }
                  for (String identifier : identifiers) {
                    ClientRequest req = fcpServer().getGlobalRequest(identifier);
                    if (req == null || req instanceof ClientGet == uploads) {
                      synchronized (completedRequestIdentifiers) {
                        completedRequestIdentifiers.remove(identifier);
                      }
                      changed = true;
                      continue;
                    }
                    registerAlert(req);
                  }
                  if (changed) {
                    saveCompletedIdentifiers();
                  }
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
            if (identifier == null) {
              return true;
            }
            completedRequestIdentifiers.add(identifier);
          }
        }
      } catch (EOFException _) {
        return true;
      } catch (FileNotFoundException _) {
        return false;
      } catch (IOException _) {
        LOG.error("Could not read completed identifiers list from {}", file);
        return false;
      }
    }

    private void saveCompletedIdentifiers() {
      File completedIdentifiersList = completedIdentifiersFile();
      File completedIdentifiersListNew = completedIdentifiersBackupFile();
      File temp = createTemporaryCompletedListFile();
      if (temp == null) {
        return;
      }
      if (!writeCompletedIdentifiers(temp)) {
        return;
      }
      replaceCompletedListFiles(completedIdentifiersList, completedIdentifiersListNew, temp);
    }

    private File completedIdentifiersFile() {
      return core.getNode().userDir().file(COMPLETED_LIST_PREFIX + queueSideSegment());
    }

    private File completedIdentifiersBackupFile() {
      return core.getNode().userDir().file(COMPLETED_LIST_PREFIX + queueSideSegment() + ".bak");
    }

    private String queueSideSegment() {
      return uploads ? UPLOADS_SEGMENT : DOWNLOADS_SEGMENT;
    }

    private File createTemporaryCompletedListFile() {
      try {
        File temp = File.createTempFile(LEGACY_COMPLETED_LIST, ".tmp", core.getNode().getUserDir());
        temp.deleteOnExit();
        return temp;
      } catch (IOException e) {
        LOG.error(
            "Unable to create temporary completed requests list (node dir missing?): {}", e, e);
        return null;
      }
    }

    private boolean writeCompletedIdentifiers(File temp) {
      try (FileOutputStream fos = new FileOutputStream(temp);
          OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
          BufferedWriter bw = new BufferedWriter(osw)) {
        String[] identifiers;
        synchronized (completedRequestIdentifiers) {
          identifiers = completedRequestIdentifiers.toArray(new String[0]);
        }
        for (String identifier : identifiers) {
          bw.write(identifier);
          bw.write('\n');
        }
        return true;
      } catch (FileNotFoundException e) {
        LOG.error(
            "Unable to open completed requests temp list for writing (node dir missing?): {}",
            e,
            e);
        return false;
      } catch (IOException e) {
        LOG.error("Unable to save completed requests list: {}", e, e);
        return false;
      }
    }

    private void replaceCompletedListFiles(
        File completedIdentifiersList, File completedIdentifiersListNew, File temp) {
      deleteIfExists(
          completedIdentifiersListNew,
          "backup completed identifiers list " + completedIdentifiersListNew);
      boolean renamedToBackup = temp.renameTo(completedIdentifiersListNew);
      if (!renamedToBackup) {
        LOG.error(
            "Unable to move completed identifiers list temp {} to backup {}",
            temp,
            completedIdentifiersListNew);
        return;
      }
      if (!completedIdentifiersListNew.renameTo(completedIdentifiersList)) {
        deleteIfExists(
            completedIdentifiersList,
            "existing completed identifiers list " + completedIdentifiersList);
        if (!completedIdentifiersListNew.renameTo(completedIdentifiersList)) {
          LOG.error(
              "Unable to move completed identifiers list backup {} to final {}",
              completedIdentifiersListNew,
              completedIdentifiersList);
        }
      }
    }

    private void deleteIfExists(File file, String description) {
      if (file.exists()) {
        try {
          Files.delete(file.toPath());
        } catch (IOException e) {
          LOG.warn("Unable to delete {}", description, e);
        }
      }
    }

    private void registerAlert(ClientRequest req) {
      String identifier = req.getIdentifier();
      if (LOG.isDebugEnabled()) {
        LOG.debug("Registering alert for {}", identifier);
      }
      if (!req.hasFinished()) {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Request hasn't finished: {} for {}", req, identifier);
        }
        return;
      }
      switch (req) {
        case ClientGet get -> {
          FreenetURI uri = get.getURI();
          if (uri == null) {
            LOG.error("No URI for finished GET request {}", req);
            return;
          }
          long size = get.getDataSize();
          GetCompletedEvent event = new GetCompletedEvent(identifier, uri, size);
          synchronized (completedGets) {
            completedGets.put(identifier, event);
          }
          core.getAlerts().register(event);
        }
        case ClientPut put -> {
          FreenetURI uri = put.getFinalURI();
          if (uri == null) {
            LOG.error("No URI for finished PUT request {}", req);
            return;
          }
          long size = put.getDataSize();
          PutCompletedEvent event = new PutCompletedEvent(identifier, uri, size);
          synchronized (completedPuts) {
            completedPuts.put(identifier, event);
          }
          core.getAlerts().register(event);
        }
        case ClientPutDir dir -> {
          FreenetURI uri = dir.getFinalURI();
          if (uri == null) {
            LOG.error("No URI for finished PUTDIR request {}", req);
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
        default -> {
          // No extra bookkeeping needed for other request types.
        }
      }
    }

    private final class GetCompletedEvent extends StoringUserEvent<GetCompletedEvent> {
      private final String identifier;
      private final FreenetURI uri;
      private final long size;

      private GetCompletedEvent(String identifier, FreenetURI uri, long size) {
        super(
            new UserEventDetails(
                UserEvent.Type.GET_COMPLETED,
                true,
                null,
                Body.of(null, null, null),
                UserAlert.MINOR,
                true,
                new DismissOptions(NodeL10n.getBase().getString(USER_ALERT_HIDE), true)),
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
                new String[] {"link", "origlink", FILENAME_L10N_KEY, "size"},
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
        synchronized (events) {
          if (events.size() == 1) {
            return l10n("downloadSucceededTitle", FILENAME_L10N_KEY, uri.getPreferredFilename());
          }
          return l10n("downloadsSucceededTitle", "nr", Integer.toString(events.size()));
        }
      }

      @Override
      public String getShortText() {
        return getTitle();
      }

      @Override
      public String getEventText() {
        return l10n("downloadSucceededTitle", FILENAME_L10N_KEY, uri.getPreferredFilename());
      }
    }

    private final class PutCompletedEvent extends StoringUserEvent<PutCompletedEvent> {
      private final String identifier;
      private final FreenetURI uri;
      private final long size;

      private PutCompletedEvent(String identifier, FreenetURI uri, long size) {
        super(
            new UserEventDetails(
                UserEvent.Type.PUT_COMPLETED,
                true,
                null,
                Body.of(null, null, null),
                UserAlert.MINOR,
                true,
                new DismissOptions(NodeL10n.getBase().getString(USER_ALERT_HIDE), true)),
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
                new String[] {"link", FILENAME_L10N_KEY, "size"},
                new HTMLNode[] {
                  HTMLNode.link("/" + uri.toASCIIString()),
                  HTMLNode.text(uri.getPreferredFilename()),
                  HTMLNode.text(SizeUtil.formatSize(size))
                });
        return text;
      }

      @Override
      public String getTitle() {
        synchronized (events) {
          if (events.size() == 1) {
            return l10n("uploadSucceededTitle", FILENAME_L10N_KEY, uri.getPreferredFilename());
          }
          return l10n("uploadsSucceededTitle", "nr", Integer.toString(events.size()));
        }
      }

      @Override
      public String getShortText() {
        return getTitle();
      }

      @Override
      public String getEventText() {
        return l10n("uploadSucceededTitle", FILENAME_L10N_KEY, uri.getPreferredFilename());
      }
    }

    private final class PutDirCompletedEvent extends StoringUserEvent<PutDirCompletedEvent> {
      private final String identifier;
      private final FreenetURI uri;
      private final long size;
      private final int files;

      private PutDirCompletedEvent(String identifier, FreenetURI uri, long size, int files) {
        super(
            new UserEventDetails(
                UserEvent.Type.PUT_DIR_COMPLETED,
                true,
                null,
                Body.of(null, null, null),
                UserAlert.MINOR,
                true,
                new DismissOptions(NodeL10n.getBase().getString(USER_ALERT_HIDE), true)),
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
        HTMLNode text = new HTMLNode("div");
        NodeL10n.getBase()
            .addL10nSubstitution(
                text,
                QUEUE_TOADLET_PREFIX + "siteUploadSucceeded",
                new String[] {"link", FILENAME_L10N_KEY, "size", "files"},
                new HTMLNode[] {
                  HTMLNode.link("/" + uri.toASCIIString()),
                  HTMLNode.text(uri.getPreferredFilename()),
                  HTMLNode.text(SizeUtil.formatSize(size)),
                  HTMLNode.text(files)
                });
        return text;
      }

      @Override
      public String getTitle() {
        synchronized (events) {
          if (events.size() == 1) {
            return l10n("siteUploadSucceededTitle", FILENAME_L10N_KEY, uri.getPreferredFilename());
          }
          return l10n("sitesUploadSucceededTitle", "nr", Integer.toString(events.size()));
        }
      }

      @Override
      public String getShortText() {
        return getTitle();
      }

      @Override
      public String getEventText() {
        return l10n("siteUploadSucceededTitle", FILENAME_L10N_KEY, uri.getPreferredFilename());
      }
    }
  }

  private static String l10n(String key, String pattern, String value) {
    return NodeL10n.getBase().getString(QUEUE_TOADLET_PREFIX + key, pattern, value);
  }
}
