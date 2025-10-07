package network.crypta.node.updater;

import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchResult;
import network.crypta.client.async.BinaryBlobWriter;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.USKCallback;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestStarter;
import network.crypta.node.Version;
import network.crypta.support.Ticker;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.FileBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class NodeUpdater implements ClientGetCallback, USKCallback, RequestClient {
  private static final Logger LOG = LoggerFactory.getLogger(NodeUpdater.class);

  private final FetchContext ctx;
  private ClientGetter cg;
  private FreenetURI URI;
  private final Ticker ticker;
  public final NodeClientCore core;
  protected final Node node;
  public final NodeUpdateManager manager;
  private final int currentVersion;
  private int realAvailableVersion;
  private int availableVersion;
  private int fetchingVersion;
  protected int fetchedVersion;
  private int maxDeployVersion;
  private int minDeployVersion;
  private boolean isRunning;
  private boolean isFetching;
  private final String blobFilenamePrefix;
  protected File tempBlobFile;

  /** Human-readable name of the update artifact (for logs/UI). */
  public abstract String artifactName();

  NodeUpdater(
      NodeUpdateManager manager,
      FreenetURI URI,
      int current,
      int min,
      int max,
      String blobFilenamePrefix) {
    // Debug gating derives from LOG.isDebugEnabled() where needed
    this.manager = manager;
    this.node = manager.getNode();
    this.URI = URI.setSuggestedEdition(Version.currentBuildNumber() + 1);
    this.ticker = node.getTicker();
    this.core = node.getClientCore();
    this.currentVersion = current;
    this.availableVersion = -1;
    this.isRunning = true;
    this.cg = null;
    this.isFetching = false;
    this.blobFilenamePrefix = blobFilenamePrefix;
    this.maxDeployVersion = max;
    this.minDeployVersion = min;

    FetchContext tempContext = core.makeClient((short) 0, true, false).getFetchContext();
    tempContext.allowSplitfiles = true;
    tempContext.dontEnterImplicitArchives = false;
    this.ctx = tempContext;
  }

  void start() {
    subscribe(() -> manager.blow("The auto-update URI isn't valid and can't be used", true));
  }

  private void subscribe(Runnable onError) {
    try {
      // because of UoM, this version is actually worth having as well
      USK myUsk = USK.create(URI.setSuggestedEdition(currentVersion));
      core.getUskManager().subscribe(myUsk, this, true, getRequestClient());
    } catch (MalformedURLException e) {
      LOG.error("The auto-update URI isn't valid and can't be used");
      onError.run();
    }
  }

  protected void maybeProcessOldBlob() {
    File oldBlob = getBlobFile(currentVersion);
    if (oldBlob.exists()) {
      File temp;
      try {
        temp =
            File.createTempFile(
                blobFilenamePrefix + availableVersion + "-",
                ".fblob.tmp",
                manager.getNode().getClientCore().getPersistentTempDir());
      } catch (IOException e) {
        LOG.error("Unable to process old blob: " + e, e);
        return;
      }
      if (oldBlob.renameTo(temp)) {
        FreenetURI uri = URI.setSuggestedEdition(currentVersion);
        uri = uri.sskForUSK();
        try {
          manager.getUpdateOverMandatory().processMainJarBlob(temp, null, currentVersion, uri);
        } catch (Throwable t) {
          // Don't disrupt startup.
          LOG.error("Unable to process old blob, caught " + t, t);
        }
        temp.delete();
      } else {
        LOG.error(
            "Unable to rename old blob file " + oldBlob + " to " + temp + " so can't process it.");
      }
    }
  }

  public RequestClient getRequestClient() {
    return this;
  }

  @Override
  public void onFoundEdition(
      long l,
      USK key,
      ClientContext context,
      boolean wasMetadata,
      short codec,
      byte[] data,
      boolean newKnownGood,
      boolean newSlotToo) {
    if (newKnownGood && !newSlotToo) return;
    // Debug gating derives from LOG.isDebugEnabled() where needed
    if (LOG.isDebugEnabled()) LOG.debug("Found edition " + l);
    int found;
    synchronized (this) {
      if (!isRunning) return;
      found = (int) key.suggestedEdition;

      realAvailableVersion = found;
      if (found > maxDeployVersion) {
        System.err.println(
            "Ignoring "
                + artifactName()
                + " update edition "
                + l
                + ": version too new (min "
                + minDeployVersion
                + " max "
                + maxDeployVersion
                + ")");
        found = maxDeployVersion;
      }

      if (found <= availableVersion) return;
      System.err.println("Found " + artifactName() + " update edition " + found);
      LOG.debug(
          "Updating availableVersion from "
              + availableVersion
              + " to "
              + found
              + " and queueing an update");
      this.availableVersion = found;
    }
    finishOnFoundEdition(found);
  }

  private void finishOnFoundEdition(int found) {
    ticker.queueTimedJob(
        () -> maybeUpdate(), SECONDS.toMillis(60)); // leave some time in case we get later editions
    // LOCKING: Always take the NodeUpdater lock *BEFORE* the NodeUpdateManager lock
    if (found <= currentVersion) {
      System.err.println(
          "Cancelling fetch for " + found + ": not newer than current version " + currentVersion);
      return;
    }
    onStartFetching();
    LOG.debug("Fetching " + artifactName() + " update edition " + found);
  }

  protected abstract void onStartFetching();

  public void maybeUpdate() {
    ClientGetter toStart = null;
    if (!manager.isEnabled()) return;
    if (manager.isBlown()) return;
    ClientGetter cancelled = null;
    synchronized (this) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "maybeUpdate: isFetching="
                + isFetching
                + ", isRunning="
                + isRunning
                + ", availableVersion="
                + availableVersion);
      if (!isRunning) return;
      if (isFetching && availableVersion == fetchingVersion) return;
      if (availableVersion <= fetchedVersion) return;
      if (fetchingVersion < minDeployVersion || fetchingVersion == currentVersion) {
        LOG.info("Cancelling previous fetch");
        cancelled = cg;
        cg = null;
      }
      fetchingVersion = availableVersion;

      if (availableVersion > currentVersion) {
        LOG.info("Starting the update process (" + availableVersion + ')');
        System.err.println(
            "Starting the update process: found the update ("
                + availableVersion
                + "), now fetching it.");
      }
      if (LOG.isDebugEnabled()) LOG.debug("Starting the update process (" + availableVersion + ')');
      // We fetch it
      try {
        if ((cg == null) || cg.isCancelled()) {
          if (LOG.isDebugEnabled())
            LOG.debug("Scheduling request for " + URI.setSuggestedEdition(availableVersion));
          if (availableVersion > currentVersion)
            System.err.println("Starting " + artifactName() + " fetch for " + availableVersion);
          tempBlobFile =
              File.createTempFile(
                  blobFilenamePrefix + availableVersion + "-",
                  ".fblob.tmp",
                  manager.getNode().getClientCore().getPersistentTempDir());
          FreenetURI uri = URI.setSuggestedEdition(availableVersion);
          uri = uri.sskForUSK();
          cg =
              new ClientGetter(
                  this,
                  uri,
                  ctx,
                  RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
                  null,
                  new BinaryBlobWriter(new FileBucket(tempBlobFile, false, false, false, false)),
                  null);
          toStart = cg;
        } else {
          System.err.println(
              "Already fetching "
                  + artifactName()
                  + " fetch for "
                  + fetchingVersion
                  + " want "
                  + availableVersion);
        }
        isFetching = true;
      } catch (Exception e) {
        LOG.error("Error while starting the fetching: " + e, e);
        isFetching = false;
      }
    }
    if (toStart != null)
      try {
        node.getClientCore().getClientContext().start(toStart);
      } catch (FetchException e) {
        LOG.error("Error while starting the fetching: " + e, e);
        synchronized (this) {
          isFetching = false;
        }
      } catch (PersistenceDisabledException e) {
        // Impossible
      }
    if (cancelled != null) cancelled.cancel(core.getClientContext());
  }

  final File getBlobFile(int availableVersion) {
    return new File(
        node.getClientCore().getPersistentTempDir(),
        blobFilenamePrefix + availableVersion + ".fblob");
  }

  RandomAccessBucket getBlobBucket(int availableVersion) {
    File f = getBlobFile(availableVersion);
    if (f == null) return null;
    return new FileBucket(f, true, false, false, false);
  }

  @Override
  public void onSuccess(FetchResult result, ClientGetter state) {
    onSuccess(result, state, tempBlobFile, fetchingVersion);
  }

  void onSuccess(FetchResult result, ClientGetter state, File tempBlobFile, int fetchedVersion) {
    // Debug gating derives from LOG.isDebugEnabled() where needed
    File blobFile = null;
    synchronized (this) {
      if (fetchedVersion <= this.fetchedVersion) {
        tempBlobFile.delete();
        if (result != null) {
          Bucket toFree = result.asBucket();
          if (toFree != null) toFree.free();
        }
        return;
      }
      if (result == null || result.asBucket() == null || result.asBucket().size() == 0) {
        tempBlobFile.delete();
        LOG.error("Cannot update: result either null or empty for " + availableVersion);
        System.err.println("Cannot update: result either null or empty for " + availableVersion);
        // Try again
        if (result == null || result.asBucket() == null || availableVersion > fetchedVersion)
          node.getTicker().queueTimedJob(() -> maybeUpdate(), 0);
        return;
      }
      blobFile = getBlobFile(fetchedVersion);
      if (!tempBlobFile.renameTo(blobFile)) {
        blobFile.delete();
        if (!tempBlobFile.renameTo(blobFile))
          if (blobFile.exists()
              && tempBlobFile.exists()
              && blobFile.length() == tempBlobFile.length())
            LOG.debug(
                "Can't rename "
                    + tempBlobFile
                    + " over "
                    + blobFile
                    + " for "
                    + fetchedVersion
                    + " - probably not a big deal though as the files are the same size");
          else {
            LOG.error(
                "Not able to rename binary blob for node updater: "
                    + tempBlobFile
                    + " -> "
                    + blobFile
                    + " - may not be able to tell other peers about this build");
            blobFile = null;
          }
      }
      this.fetchedVersion = fetchedVersion;
      System.out.println("Found " + artifactName() + " version " + fetchedVersion);
      if (fetchedVersion > currentVersion)
        LOG.info(
            "Found version "
                + fetchedVersion
                + ", setting up a new UpdatedVersionAvailableUserAlert");
      maybeParseManifest(result, fetchedVersion);
      this.cg = null;
    }
    processSuccess(fetchedVersion, result, blobFile);
  }

  /** We have fetched the jar! Do something after onSuccess(). Called unlocked. */
  protected abstract void processSuccess(int fetched, FetchResult result, File blobFile);

  /**
   * Called with locks held
   *
   * @param result
   */
  protected abstract void maybeParseManifest(FetchResult result, int build);

  protected void parseManifest(FetchResult result) {
    try (InputStream is = result.asBucket().getInputStream();
        ZipInputStream zis = new ZipInputStream(is)) {
      ZipEntry ze;
      while (true) {
        ze = zis.getNextEntry();
        if (ze == null) break;
        if (ze.isDirectory()) continue;
        String name = ze.getName();

        if (name.equals("META-INF/MANIFEST.MF")) {
          if (LOG.isDebugEnabled()) LOG.debug("Found manifest");
          long size = ze.getSize();
          if (LOG.isDebugEnabled()) LOG.debug("Manifest size: " + size);
          if (size > MAX_MANIFEST_SIZE) {
            LOG.error("Manifest is too big: " + size + " bytes, limit is " + MAX_MANIFEST_SIZE);
            break;
          }
          byte[] buf = new byte[(int) size];
          DataInputStream dis = new DataInputStream(zis);
          dis.readFully(buf);
          ByteArrayInputStream bais = new ByteArrayInputStream(buf);
          InputStreamReader isr = new InputStreamReader(bais, StandardCharsets.UTF_8);
          BufferedReader br = new BufferedReader(isr);
          String line;
          while ((line = br.readLine()) != null) {
            parseManifestLine(line);
          }
        } else {
          zis.closeEntry();
        }
      }
    } catch (IOException e) {
      LOG.error("IOException trying to read manifest on update");
    } catch (Throwable t) {
      LOG.error("Failed to parse update manifest: " + t, t);
    }
  }

  // Legacy dependencies.properties parsing hooks removed.

  protected void parseManifestLine(String line) {
    // Do nothing by default, only some NodeUpdater's will use this, those that don't won't call
    // parseManifest().
  }

  private static final int MAX_MANIFEST_SIZE = 1024 * 1024;

  @Override
  public void onFailure(FetchException e, ClientGetter state) {
    // Debug gating derives from LOG.isDebugEnabled() where needed
    if (!isRunning) return;
    FetchExceptionMode errorCode = e.getMode();
    tempBlobFile.delete();

    if (LOG.isDebugEnabled()) LOG.debug("onFailure(" + e + ',' + state + ')');
    synchronized (this) {
      this.cg = null;
      isFetching = false;
    }
    if (errorCode == FetchExceptionMode.CANCELLED || !e.isFatal()) {
      LOG.info("Rescheduling new request");
      ticker.queueTimedJob(() -> maybeUpdate(), 0);
    } else {
      LOG.error("Canceling fetch : " + e.getMessage());
      System.err.println("Unexpected error fetching update: " + e.getMessage());
      if (e.isFatal()) {
        // Wait for the next version
      } else ticker.queueTimedJob(() -> maybeUpdate(), HOURS.toMillis(1));
    }
  }

  /** Called before kill(). Don't do anything that will involve taking locks. */
  public void preKill() {
    isRunning = false;
  }

  void kill() {
    try {
      ClientGetter c;
      synchronized (this) {
        isRunning = false;
        USK myUsk = USK.create(URI.setSuggestedEdition(currentVersion));
        core.getUskManager().unsubscribe(myUsk, this);
        c = cg;
        cg = null;
      }
      c.cancel(core.getClientContext());
    } catch (Exception e) {
      LOG.debug("Cannot kill NodeUpdater", e);
    }
  }

  public FreenetURI getUpdateKey() {
    return URI;
  }

  public synchronized boolean canUpdateNow() {
    return fetchedVersion > currentVersion;
  }

  /**
   * Called when the fetch URI has changed. No major locks are held by caller.
   *
   * @param uri The new URI.
   */
  public void onChangeURI(FreenetURI uri) {
    String previousDocName;
    synchronized (this) {
      previousDocName = (URI != null) ? URI.getDocName() : null;
    }
    kill(); // unsubscribes from the old uri
    FreenetURI nextUri =
        (previousDocName != null && (uri.getDocName() == null || uri.getDocName().isEmpty()))
            ? uri.setDocName(previousDocName)
            : uri;
    synchronized (this) {
      this.URI = nextUri.setSuggestedEdition(Version.currentBuildNumber() + 1);
      availableVersion = -1;
      realAvailableVersion = -1;
      fetchingVersion = -1;
      fetchedVersion = currentVersion;
      isFetching = false;
      isRunning = true;
    }
    subscribe(() -> {});
    maybeUpdate();
  }

  public int getFetchedVersion() {
    return fetchedVersion;
  }

  public boolean isFetching() {
    return availableVersion > fetchedVersion && availableVersion > currentVersion;
  }

  public int fetchingVersion() {
    // We will not deploy currentVersion...
    if (fetchingVersion <= currentVersion) return availableVersion;
    else return fetchingVersion;
  }

  public long getBlobSize() {
    return getBlobFile(getFetchedVersion()).length();
  }

  public File getBlobFile() {
    return getBlobFile(getFetchedVersion());
  }

  @Override
  public short getPollingPriorityNormal() {
    return RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS;
  }

  @Override
  public short getPollingPriorityProgress() {
    return RequestStarter.INTERACTIVE_PRIORITY_CLASS;
  }

  @Override
  public boolean persistent() {
    return false;
  }

  /**
   * * Called by NodeUpdateManager to re-set the min/max versions for ext when * a new freenet.jar
   * has been downloaded. This is to try to avoid the node * installing incompatible versions of
   * main and ext.
   */
  public void setMinMax(int requiredExt, int recommendedExt) {
    int callFinishedFound = -1;
    synchronized (this) {
      if (recommendedExt > -1) {
        maxDeployVersion = recommendedExt;
      }
      if (requiredExt > -1) {
        minDeployVersion = requiredExt;
        if (realAvailableVersion != availableVersion
            && availableVersion < requiredExt
            && realAvailableVersion >= requiredExt) {
          // We found a revision but didn't fetch it because it wasn't within the range for the old
          // jar.
          // The new one requires it, however.
          System.err.println(
              "Previously out-of-range edition "
                  + realAvailableVersion
                  + " is now needed by the new jar; scheduling fetch.");
          callFinishedFound = availableVersion = realAvailableVersion;
        } else if (availableVersion < requiredExt) {
          // Including if it hasn't been found at all
          // Just try it ...
          callFinishedFound = availableVersion = requiredExt;
          System.err.println(
              "Need minimum edition "
                  + requiredExt
                  + " for new jar, found "
                  + availableVersion
                  + "; scheduling fetch.");
        }
      }
    }
    if (callFinishedFound > -1) finishOnFoundEdition(callFinishedFound);
  }

  @Override
  public boolean realTimeFlag() {
    return false;
  }

  @Override
  public void onResume(ClientContext context) {
    // Do nothing. Not persistent.
  }
}
