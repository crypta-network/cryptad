package network.crypta.node.updater;

import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Map;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.config.Config;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.SubConfig;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.NodeFile;
import network.crypta.node.PeerNode;
import network.crypta.node.ProgramDirectory;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestStarter;
import network.crypta.node.Version;
import network.crypta.node.useralerts.RevocationKeyFoundUserAlert;
import network.crypta.node.useralerts.SimpleUserAlert;
import network.crypta.node.useralerts.UpdatedVersionAvailableUserAlert;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.pluginmanager.OfficialPlugins.OfficialPluginDescription;
import network.crypta.pluginmanager.PluginInfoWrapper;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.StringCallback;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Supervises auto‑update components: core application updates and plugin updates.
 *
 * <p>Historically this class owned a main‑jar self‑updater and coordinated Update‑Over‑Mandatory
 * (UoM) fallback. The core update flow is now package‑based via {@code CoreUpdater} (deb/rpm/dmg/
 * exe/flatpak/snap), and UoM for the main JAR is disabled in that mode (revocation handling stays).
 * Plugin updates continue to use the existing JAR flow.
 *
 * <p>Procedure for updating the update key: Create a new key. Create a new build X, the "transition
 * version". This must be UOM-compatible with the previous transition version. UOM-compatible means
 * UOM should work from the older builds. This in turn means that it should support an overlapping
 * set of connection setup negTypes (@link FNPPacketMangler.supportedNegTypes()). Similarly there
 * may be issues with changes to the UOM messages, or to messages in general. Build X is inserted to
 * both the old key and the new key. Build X's SSK URI (on the old auto-update key) will be
 * hard-coded as the new transition version. Then the next build, X+1, can get rid of some of the
 * back compatibility cruft (especially old connection setup types), and will be inserted only to
 * the new key. Secure backups of the new key are required and are documented elsewhere. FIXME: See
 * bug #6009 for some current UOM compatibility issues.
 */
public class NodeUpdateManager {
  private static final Logger LOG = LoggerFactory.getLogger(NodeUpdateManager.class);

  /**
   * The last build on the previous key with Java 7 support. Older nodes can update to this point
   * via old UOM.
   */
  public static final int TRANSITION_VERSION = 1481;

  /** The URI for post-TRANSITION_VERSION builds' freenet.jar. */
  public static final String UPDATE_URI =
      "USK@uQnFwn0aEFSAZihnSDduEHUd3GUmGg68ATn5R95MKJo,mcNiZqosfZ1F~PkZY8v1TuDKsY6noda-hGRXvu7uUFc,AQACAAE/jar/"
          + Version.currentBuildNumber();

  public static final String REVOCATION_URI =
      "SSK@TAnVLWtrGguuIi3fXkf8OmT5Pmy2Hduai18FUCP0uAU,tMg8t4kLktzmz~uFC6jk~-CUNv1mQ-C573sjLeg0alU,AQACAAE/revoked";
  // These are necessary to prevent DoS.
  public static final long MAX_REVOCATION_KEY_LENGTH = 32 * 1024;
  public static final long MAX_REVOCATION_KEY_TEMP_LENGTH = 64 * 1024;
  public static final long MAX_REVOCATION_KEY_BLOB_LENGTH = 128 * 1024;
  public static final long MAX_MAIN_JAR_LENGTH = 48 * 1024 * 1024; // 48MiB
  public static final long MAX_JAVA_INSTALLER_LENGTH = 300 * 1024 * 1024;
  public static final long MAX_WINDOWS_INSTALLER_LENGTH = 300 * 1024 * 1024;
  public static final long MAX_IP_TO_COUNTRY_LENGTH = 24 * 1024 * 1024;
  public static final long MAX_SEEDNODES_LENGTH = 3 * 1024 * 1024;

  private FreenetURI updateURI;
  private FreenetURI revocationURI;

  // Legacy MainJarUpdater removed; core package updater is used instead.
  // Package-based core updater (Kotlin)
  private CoreUpdater coreUpdater;

  private Map<String, PluginJarUpdater> pluginUpdaters;

  private boolean autoDeployPluginsOnRestart;
  private final boolean wasEnabledOnStartup;

  /** Is auto-update enabled? */
  private volatile boolean isAutoUpdateAllowed;

  /** Has the user given the go-ahead? */
  private volatile boolean armed;

  /**
   * Currently deploying an update? Set when we start to deploy an update. Which means it should not
   * be un-set, except in the case of a severe error causing a valid update to fail. However, it is
   * un-set in this case, so that we can try again with another build.
   */
  private boolean isDeployingUpdate;

  private final Object broadcastUOMAnnouncesSync = new Object();
  private boolean broadcastUOMAnnounces = false;

  /**
   * @deprecated Use {@link #getNode()} instead of accessing this directly.
   */
  @Deprecated
  /* It’s not the field that is deprecated but accessing it directly is. */
  public final Node node;

  /**
   * @deprecated Use {@link #getRevocationChecker()} instead of accessing this directly.
   */
  @Deprecated
  /* It’s not the field that is deprecated but accessing it directly is. */
  final RevocationChecker revocationChecker;

  private String revocationMessage;
  private volatile boolean hasBeenBlown;
  private volatile boolean peersSayBlown;
  private boolean updateSeednodes;
  private boolean updateInstallers;

  /** Is there a new main jar ready to deploy? */
  private volatile boolean hasNewMainJar;

  /** If another main jar is being fetched, when did the fetch start? */
  private long startedFetchingNextMainJar;

  /** Time when we got the jar */
  private long gotJarTime;

  // Revocation alert
  private RevocationKeyFoundUserAlert revocationAlert;
  // Update alert
  private final UpdatedVersionAvailableUserAlert alert;

  /**
   * @deprecated Use {@link #getUpdateOverMandatory()} instead of accessing this directly.
   */
  @Deprecated
  /* It’s not the field that is deprecated but accessing it directly is. */
  public final UpdateOverMandatoryManager uom;

  private boolean disabledThisSession;

  // CoreUpdater manages core updates; legacy main-jar fields are no longer used.

  private static final Object deployLock = new Object();

  static final String TEMP_BLOB_SUFFIX = ".updater.fblob.tmp";
  static final String TEMP_FILE_SUFFIX = ".updater.tmp";

  static {
  }

  public NodeUpdateManager(Node node, Config config) throws InvalidConfigValueException {
    this.node = node;
    this.hasBeenBlown = false;
    this.alert = new UpdatedVersionAvailableUserAlert(this);
    alert.isValid(false);

    SubConfig updaterConfig = config.createSubConfig("node.updater");

    updaterConfig.register(
        "enabled",
        true,
        1,
        false,
        false,
        "NodeUpdateManager.enabled",
        "NodeUpdateManager.enabledLong",
        new UpdaterEnabledCallback());

    wasEnabledOnStartup = updaterConfig.getBoolean("enabled");

    // is the auto-update allowed ?
    updaterConfig.register(
        "autoupdate",
        false,
        2,
        false,
        true,
        "NodeUpdateManager.installNewVersions",
        "NodeUpdateManager.installNewVersionsLong",
        new AutoUpdateAllowedCallback());
    isAutoUpdateAllowed = updaterConfig.getBoolean("autoupdate");

    // Set default update URI for new nodes.
    updaterConfig.register(
        "URI",
        UPDATE_URI,
        3,
        true,
        true,
        "NodeUpdateManager.updateURI",
        "NodeUpdateManager.updateURILong",
        new UpdateURICallback());

    try {
      updateURI = new FreenetURI(updaterConfig.getString("URI"));
    } catch (MalformedURLException e) {
      throw new InvalidConfigValueException(
          l10n("invalidUpdateURI", "error", e.getLocalizedMessage()));
    }

    updateURI = updateURI.setSuggestedEdition(Version.currentBuildNumber());
    if (updateURI.hasMetaStrings()) {
      throw new InvalidConfigValueException(l10n("updateURIMustHaveNoMetaStrings"));
    }
    if (!updateURI.isUSK()) {
      throw new InvalidConfigValueException(l10n("updateURIMustBeAUSK"));
    }

    updaterConfig.register(
        "revocationURI",
        REVOCATION_URI,
        4,
        true,
        false,
        "NodeUpdateManager.revocationURI",
        "NodeUpdateManager.revocationURILong",
        new UpdateRevocationURICallback());

    try {
      revocationURI = new FreenetURI(updaterConfig.getString("revocationURI"));
    } catch (MalformedURLException e) {
      throw new InvalidConfigValueException(
          l10n("invalidRevocationURI", "error", e.getLocalizedMessage()));
    }

    // Deprecated UI option: updateSeednodes (no longer shown on the Auto-update page).
    // Keep internal default as false; accept but ignore legacy config values.
    updaterConfig.registerIgnoredOption("updateSeednodes");

    // Deprecated UI option: updateInstallers (no longer shown on the Auto-update page).
    // Keep internal default as false; accept but ignore legacy config values.
    updaterConfig.registerIgnoredOption("updateInstallers");

    updaterConfig.finishedInitialization();

    this.revocationChecker =
        new RevocationChecker(
            this, new File(node.getClientCore().getPersistentTempDir(), "revocation-key.fblob"));

    this.uom = new UpdateOverMandatoryManager(this);
    this.uom.removeOldTempFiles();
  }

  class SimplePuller implements ClientGetCallback {

    final FreenetURI freenetURI;
    final String filename;
    final ProgramDirectory directory;

    public SimplePuller(FreenetURI freenetURI, NodeFile file) {
      this(freenetURI, file.getFilename(), file.getProgramDirectory(node));
    }

    private SimplePuller(FreenetURI freenetURI, String filename, ProgramDirectory directory) {
      this.freenetURI = freenetURI;
      this.filename = filename;
      this.directory = directory;
    }

    public void start(short priority, long maxSize) {
      HighLevelSimpleClient hlsc = node.getClientCore().makeClient(priority, false, false);
      FetchContext context = hlsc.getFetchContext();
      context.maxNonSplitfileRetries = -1;
      context.maxSplitfileBlockRetries = -1;
      context.maxTempLength = maxSize;
      context.maxOutputLength = maxSize;
      ClientGetter get = new ClientGetter(this, freenetURI, context, priority, null, null, null);
      try {
        node.getClientCore().getClientContext().start(get);
      } catch (PersistenceDisabledException e) {
        // Impossible
      } catch (FetchException e) {
        onFailure(e, null);
      }
    }

    @Override
    public void onFailure(FetchException e, ClientGetter state) {
      System.err.println("Failed to fetch " + filename + " : " + e);
    }

    @Override
    public void onSuccess(FetchResult result, ClientGetter state) {
      File temp;
      try {
        temp = FileUtil.createTempFile(filename, ".tmp", directory.dir());
        temp.deleteOnExit();
        try (FileOutputStream fos = new FileOutputStream(temp)) {
          BucketTools.copyTo(result.asBucket(), fos, -1);
        }
        for (int i = 0; i < 10; i++) {
          // FIXME add a callback in case it's being used on Windows.
          if (FileUtil.moveTo(temp, directory.file(filename))) {
            System.out.println(
                "Successfully fetched "
                    + filename
                    + " for version "
                    + Version.currentBuildNumber());
            break;
          } else {
            System.out.println(
                "Failed to rename " + temp + " to " + filename + " after fetching it from Crypta.");
            try {
              Thread.sleep(
                  SECONDS.toMillis(1)
                      + node.getFastWeakRandom()
                          .nextInt(
                              (int)
                                  SECONDS.toMillis(
                                      (long) Math.min(Math.pow(2, i), MINUTES.toSeconds(15)))));
            } catch (InterruptedException e) {
              // Ignore
            }
          }
        }
        temp.delete();
      } catch (IOException e) {
        System.err.println(
            "Fetched but failed to write out "
                + filename
                + " - please check that the node has permissions to write in "
                + directory.dir()
                + " and particularly the file "
                + filename);
        System.err.println("The error was: " + e);
        e.printStackTrace();
      } finally {
        IOUtils.closeQuietly(result.asBucket());
      }
    }

    @Override
    public void onResume(ClientContext context) {
      // Not persistent.
    }

    @Override
    public RequestClient getRequestClient() {
      return node.getNonPersistentClientBulk();
    }
  }

  public File getInstallerWindows() {
    File f = NodeFile.INSTALLER_WINDOWS.getFile(node);
    if (!(f.exists() && f.canRead() && f.length() > 0)) {
      return null;
    } else {
      return f;
    }
  }

  public File getInstallerNonWindows() {
    File f = NodeFile.INSTALLER_NON_WINDOWS.getFile(node);
    if (!(f.exists() && f.canRead() && f.length() > 0)) {
      return null;
    } else {
      return f;
    }
  }

  public FreenetURI getSeednodesURI() {
    return updateURI.sskForUSK().setDocName("seednodes-" + Version.currentBuildNumber());
  }

  public FreenetURI getInstallerNonWindowsURI() {
    return updateURI.sskForUSK().setDocName("installer-" + Version.currentBuildNumber());
  }

  public FreenetURI getInstallerWindowsURI() {
    return updateURI.sskForUSK().setDocName("wininstaller-" + Version.currentBuildNumber());
  }

  public FreenetURI getIPv4ToCountryURI() {
    return updateURI.sskForUSK().setDocName("iptocountryv4-" + Version.currentBuildNumber());
  }

  public void start() throws InvalidConfigValueException {

    node.getClientCore().getAlerts().register(alert);

    enable(wasEnabledOnStartup);

    // Fetch seednodes to the nodeDir.
    if (updateSeednodes) {

      SimplePuller seedrefsGetter = new SimplePuller(getSeednodesURI(), NodeFile.SEEDNODES);
      seedrefsGetter.start(RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS, MAX_SEEDNODES_LENGTH);
    }

    // Fetch installers and IP-to-country files to the runDir.
    if (updateInstallers) {
      SimplePuller installerGetter =
          new SimplePuller(getInstallerNonWindowsURI(), NodeFile.INSTALLER_NON_WINDOWS);
      SimplePuller wininstallerGetter =
          new SimplePuller(getInstallerWindowsURI(), NodeFile.INSTALLER_WINDOWS);

      installerGetter.start(RequestStarter.UPDATE_PRIORITY_CLASS, MAX_JAVA_INSTALLER_LENGTH);
      wininstallerGetter.start(RequestStarter.UPDATE_PRIORITY_CLASS, MAX_WINDOWS_INSTALLER_LENGTH);
    }

    // FIXME make updateIPToCountry configurable
    SimplePuller ip4Getter = new SimplePuller(getIPv4ToCountryURI(), NodeFile.IPV4_TO_COUNTRY);
    ip4Getter.start(RequestStarter.UPDATE_PRIORITY_CLASS, MAX_IP_TO_COUNTRY_LENGTH);
  }

  void broadcastUOMAnnounces() {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Broadcast UOM announcements");
    }
    long size = canAnnounceUOMNew();
    Message msg;
    if (size <= 0 && !hasBeenBlown) {
      return;
    }
    synchronized (broadcastUOMAnnouncesSync) {
      if (broadcastUOMAnnounces && !hasBeenBlown) {
        return;
      }
      broadcastUOMAnnounces = true;
      msg = getNewUOMAnnouncement(size);
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Broadcasting UOM announcements");
    }
    node.getPeers().localBroadcast(msg, true, true, ctr, TRANSITION_VERSION, Integer.MAX_VALUE);
  }

  /** Return the length of the data fetched for the current version, or -1. */
  private long canAnnounceUOMNew() {
    return -1;
  }

  private Message getNewUOMAnnouncement(long blobSize) {
    int fetchedVersion = blobSize <= 0 ? -1 : Version.currentBuildNumber();
    if (blobSize <= 0) {
      fetchedVersion = -1;
    }
    return new DMT.UOMAnnouncementBuilder()
        .mainKey(updateURI.toString())
        .revocationKey(revocationURI.toString())
        .haveRevocation(revocationChecker.hasBlown())
        .mainJarVersion(fetchedVersion)
        .timeLastTriedRevocationFetch(revocationChecker.lastSucceededDelta())
        .revocationDNFCount(revocationChecker.getRevocationDNFCounter())
        .revocationKeyLength(revocationChecker.getBlobSize())
        .mainJarLength(blobSize)
        .pingTime((int) node.getNodeStats().getNodeAveragePingTime())
        .bwlimitDelayTime((int) node.getNodeStats().getBwlimitDelayTime())
        .build();
  }

  public void maybeSendUOMAnnounce(PeerNode peer) {

    synchronized (broadcastUOMAnnouncesSync) {
      if (!broadcastUOMAnnounces) {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Not sending UOM on connect: Nothing worth announcing yet");
        }
        return; // nothing worth announcing yet
      }
    }
    if (hasBeenBlown && !revocationChecker.hasBlown()) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Not sending UOM (any) on connect: Local problem causing blown key");
      }
      // Local problem, don't broadcast.
      return;
    }
    long size = canAnnounceUOMNew();
    try {
      if (Version.isBuildAtLeast(peer.getNodeName(), peer.getBuildNumber(), TRANSITION_VERSION)) {
        peer.sendAsync(getNewUOMAnnouncement(size), null, ctr);
      }
    } catch (NotConnectedException e) {
      // Sad, but ignore it
    }
  }

  /** Is auto-update enabled? */
  public synchronized boolean isEnabled() {
    return (coreUpdater != null);
  }

  /**
   * Enable or disable auto-update.
   *
   * @param enable Whether auto-update should be enabled.
   * @throws InvalidConfigValueException If enable=true and we are not running under the wrapper.
   */
  void enable(boolean enable) throws InvalidConfigValueException {
    // FIXME 194eb7bb6f295e52d18378d805bd315c95030b24 is doubtful and incomplete.
    // if(!node.isUsingWrapper()){
    // LOG.info(// "Don't try to start the updater as we are not running under the wrapper.");
    // return;
    // }
    Map<String, PluginJarUpdater> oldPluginUpdaters = null;
    CoreUpdater stoppedCoreUpdater = null;
    // We need to run the revocation checker even if auto-update is
    // disabled.
    // Two reasons:
    // 1. For the benefit of other nodes, and because even if auto-update is
    // off, it's something the user should probably know about.
    // 2. When the key is blown, we turn off auto-update!!!!
    revocationChecker.start(false);
    synchronized (this) {
      boolean enabled = (coreUpdater != null);
      if (enabled == enable) {
        return;
      }
      if (!enable) {
        // Kill it
        if (coreUpdater != null) coreUpdater.preKill();
        stoppedCoreUpdater = coreUpdater;
        coreUpdater = null;
        oldPluginUpdaters = pluginUpdaters;
        pluginUpdaters = null;
        disabledNotBlown = false;
      } else {
        // if((!WrapperManager.isControlledByNativeWrapper()) ||
        // (NodeStarter.extBuildNumber == -1)) {
        // LOG.error(// "Cannot update because not running under wrapper");
        // throw new
        // InvalidConfigValueException(l10n("noUpdateWithoutWrapper"));
        // }
        // Start CoreUpdater and plugin updaters
        startCoreUpdater();
        pluginUpdaters = new HashMap<>();
        // Suppress obsolete Update-ASAP form in alert; CoreUpdater renders its own buttons
        armed = true;
      }
    }
    if (!enable) {
      if (stoppedCoreUpdater != null) {
        stoppedCoreUpdater.kill();
      }
      stopPluginUpdaters(oldPluginUpdaters);
    } else {
      if (coreUpdater != null) coreUpdater.start();
      startPluginUpdaters();
    }
  }

  private void startPluginUpdaters() {
    for (OfficialPluginDescription plugin : node.getPluginManager().getOfficialPlugins()) {
      startPluginUpdater(plugin.name);
    }
  }

  /**
   * @param plugName The filename for loading/config purposes for an official plugin. E.g. "Library"
   *     (no .jar)
   */
  public void startPluginUpdater(String plugName) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Starting plugin updater for " + plugName);
    }
    OfficialPluginDescription plugin = node.getPluginManager().getOfficialPlugin(plugName);
    if (plugin != null) {
      startPluginUpdater(plugin);
    } else
    // Most likely not an official plugin
    if (LOG.isDebugEnabled()) {
      LOG.debug("No such plugin " + plugName + " in startPluginUpdater()");
    }
  }

  void startPluginUpdater(OfficialPluginDescription plugin) {
    String name = plugin.name;
    // @see https://emu.freenetproject.org/pipermail/devl/2015-November/038581.html
    long minVer = (plugin.essential ? plugin.minimumVersion : plugin.recommendedVersion);
    // But it might already be past that ...
    PluginInfoWrapper info = node.getPluginManager().findPluginByIdentifier(name);
    if (info == null) {
      if (!(node.getPluginManager().isPluginLoadedOrLoadingOrWantLoad(name))) {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Plugin not loaded");
        }
        return;
      }
    }
    if (info != null) {
      minVer = Math.max(minVer, info.getPluginLongVersion());
    }
    FreenetURI uri = updateURI.setDocName(name).setSuggestedEdition(minVer);
    PluginJarUpdater updater =
        new PluginJarUpdater(
            this,
            uri,
            (int) minVer,
            -1,
            (plugin.essential ? (int) minVer : Integer.MAX_VALUE),
            name + "-",
            name,
            node.getPluginManager(),
            autoDeployPluginsOnRestart);
    synchronized (this) {
      if (pluginUpdaters == null) {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Updating not enabled");
        }
        return; // Not enabled
      }
      if (pluginUpdaters.containsKey(name)) {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Already in updaters list");
        }
        return; // Already started
      }
      pluginUpdaters.put(name, updater);
    }
    updater.start();
    System.out.println("Started plugin update fetcher for " + name);
  }

  public void stopPluginUpdater(String plugName) {
    OfficialPluginDescription plugin = node.getPluginManager().getOfficialPlugin(plugName);
    if (plugin == null) {
      return; // Not an official plugin
    }
    PluginJarUpdater updater = null;
    synchronized (this) {
      if (pluginUpdaters == null) {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Updating not enabled");
        }
        return; // Not enabled
      }
      updater = pluginUpdaters.remove(plugName);
    }
    if (updater != null) {
      updater.kill();
    }
  }

  private void stopPluginUpdaters(Map<String, PluginJarUpdater> oldPluginUpdaters) {
    for (PluginJarUpdater u : oldPluginUpdaters.values()) {
      u.kill();
    }
  }

  /**
   * Create a NodeUpdateManager. Called by node constructor.
   *
   * @param node The node object.
   * @param config The global config object. Options will be added to a subconfig called
   *     node.updater.
   * @return A new NodeUpdateManager
   * @throws InvalidConfigValueException If there is an error in the config.
   */
  public static NodeUpdateManager maybeCreate(Node node, Config config)
      throws InvalidConfigValueException {
    return new NodeUpdateManager(node, config);
  }

  /** Get the URI for freenet.jar. */
  public synchronized FreenetURI getURI() {
    return updateURI;
  }

  /**
   * Update base with docname switched to {@code "info"} (core package info editions). Used by
   * {@link CoreUpdater}.
   */
  public synchronized FreenetURI getCoreInfoURI() {
    return updateURI.setDocName("info");
  }

  /**
   * @return URI for the user-facing changelog.
   */
  public synchronized FreenetURI getChangelogURI() {
    return updateURI.setDocName("changelog");
  }

  public synchronized FreenetURI getDeveloperChangelogURI() {
    return updateURI.setDocName("fullchangelog");
  }

  /**
   * Add links to the changelog for the given version to the given node.
   *
   * <p>Preference order: - Use CHK links provided by {@link CoreUpdater} when available (short +
   * full changelog). - Otherwise, fall back to the legacy SSK links derived from the update USK.
   *
   * <p>This avoids showing duplicate links (old SSK + new CHK) at the same time.
   *
   * @param version USK edition to point to
   * @param node to add links to
   */
  public synchronized void addChangelogLinks(long version, HTMLNode node) {
    boolean addedFromCore = false;
    CoreUpdater cu = coreUpdater;
    if (cu != null) {
      String s = cu.getShortChangelogCHK();
      if (s != null && !s.isEmpty()) {
        node.addChild(
            "a",
            "href",
            '/' + s + "?type=text/plain",
            NodeL10n.getBase().getString("UpdatedVersionAvailableUserAlert.changelog"));
        addedFromCore = true;
      }
      String f = cu.getFullChangelogCHK();
      if (f != null && !f.isEmpty()) {
        if (addedFromCore) node.addChild("br");
        node.addChild(
            "a",
            "href",
            '/' + f + "?type=text/plain",
            NodeL10n.getBase().getString("UpdatedVersionAvailableUserAlert.devchangelog"));
        addedFromCore = true;
      }
    }

    if (!addedFromCore) {
      // Fallback to legacy SSK links only when CHKs are not present.
      String changelogUri =
          getChangelogURI().setSuggestedEdition(version).sskForUSK().toASCIIString();
      String developerDetailsUri =
          getDeveloperChangelogURI().setSuggestedEdition(version).sskForUSK().toASCIIString();
      node.addChild(
          "a",
          "href",
          '/' + changelogUri + "?type=text/plain",
          NodeL10n.getBase().getString("UpdatedVersionAvailableUserAlert.changelog"));
      node.addChild("br");
      node.addChild(
          "a",
          "href",
          '/' + developerDetailsUri + "?type=text/plain",
          NodeL10n.getBase().getString("UpdatedVersionAvailableUserAlert.devchangelog"));
    }
  }

  /**
   * Set the URfrenet.jar should be updated from.
   *
   * @param uri The URI to set.
   */
  public void setURI(FreenetURI uri) {
    // FIXME plugins!!
    NodeUpdater updater;
    Map<String, PluginJarUpdater> oldPluginUpdaters = null;
    synchronized (this) {
      if (updateURI.equals(uri)) {
        return;
      }
      updateURI = uri;
      updateURI = updateURI.setSuggestedEdition(Version.currentBuildNumber());
      updater = coreUpdater;
      oldPluginUpdaters = pluginUpdaters;
      pluginUpdaters = new HashMap<>();
      if (updater == null) {
        return;
      }
    }
    updater.onChangeURI(uri);
    stopPluginUpdaters(oldPluginUpdaters);
    startPluginUpdaters();
  }

  /**
   * @return The revocation URI.
   */
  public synchronized FreenetURI getRevocationURI() {
    return revocationURI;
  }

  /**
   * Set the revocation URI.
   *
   * @param uri The new revocation URI.
   */
  public void setRevocationURI(FreenetURI uri) {
    synchronized (this) {
      if (revocationURI.equals(uri)) {
        return;
      }
      this.revocationURI = uri;
    }
    revocationChecker.onChangeRevocationURI();
  }

  /**
   * @return Is auto-update currently enabled?
   */
  public boolean isAutoUpdateAllowed() {
    return isAutoUpdateAllowed;
  }

  /**
   * Enable or disable auto-update.
   *
   * @param val If true, enable auto-update (and immediately update if an update is ready). If
   *     false, disable it.
   */
  public void setAutoUpdateAllowed(boolean val) {
    synchronized (this) {
      if (val == isAutoUpdateAllowed) {
        return;
      }
      isAutoUpdateAllowed = val;
    }
    // CoreUpdater handles auto-download when enabled; nothing further needed here.
  }

  private static final long WAIT_FOR_SECOND_FETCH_TO_COMPLETE = MINUTES.toMillis(4);
  private static final long RECENT_REVOCATION_INTERVAL = MINUTES.toMillis(2);

  /**
   * After 5 minutes, deploy the update even if we haven't got 3 DNFs on the revocation key yet.
   * Reason: we want to be able to deploy UOM updates on nodes with all TOO NEW or leaf nodes whose
   * peers are overloaded/broken. Note that with UOM, revocation certs are automatically propagated
   * node to node, so this should be *relatively* safe. Any better ideas, tell us.
   */
  private static final long REVOCATION_FETCH_TIMEOUT = MINUTES.toMillis(5);

  /**
   * Does the updater have an update ready to deploy? May be called synchronized(this).
   *
   * @param ignoreRevocation If true, return whether we will deploy when the revocation check
   *     finishes. If false, return whether we can deploy now, and if not, deploy after a delay with
   *     deployOffThread().
   */
  private boolean isReadyToDeployUpdate(boolean ignoreRevocation) {
    return false;
  }

  /** Check whether there is an update to deploy. If there is, do it. */
  private void deployUpdate() {
    /* no-op in package-based updater */
  }

  /**
   * Use this lock when deploying an update of any kind which will require us to restart. If the
   * update succeeds, you should call waitForever() if you don't immediately exit. There could be
   * rather nasty race conditions if we deploy two updates at once.
   *
   * @return A mutex for serialising update deployments.
   */
  static Object deployLock() {
    return deployLock;
  }

  /**
   * Does not return. Should be called, inside the deployLock(), if you are in a situation where
   * you've deployed an update but the exit hasn't actually happened yet.
   */
  static void waitForever() {
    while (true) {
      System.err.println("Waiting for shutdown after deployed update...");
      try {
        Thread.sleep(60 * 1000);
      } catch (InterruptedException e) {
        // Ignore.
      }
    }
  }

  /** Deploy the update. Inner method. Doesn't check anything, just does it. */
  // Legacy deploy methods removed.

  // writeJars removed

  /**
   * Write a jar. Returns true if the caller needs to rewrite the config, false if he doesn't, or
   * throws if it fails.
   *
   * @param mainJar The location of the current jar file.
   * @param newMainJar The location of the new jar file.
   * @param backupMainJar On Windows, we alternate between freenet.jar and freenet.jar.new, so we do
   *     not need to write a backup - the user can rename between these two. On Unix, we copy to
   *     freenet.jar.bak before updating, in case something horrible happens.
   * @param mainUpdater The NodeUpdater for the file in question, so we can ask it to write the
   *     file.
   * @param name The name of the jar for logging.
   * @param tryEasyWay If true, attempt to rename the new file directly over the old one. This
   *     avoids the need to rewrite the wrapper config file.
   * @return True if the caller needs to rewrite the config, false if he doesn't (because easy way
   *     worked).
   * @throws UpdateFailedException If something breaks.
   */
  // writeJar removed

  // writeJarTo removed

  @SuppressWarnings("serial")
  private static class UpdateFailedException extends Exception {

    public UpdateFailedException(String message) {
      super(message);
    }
  }

  // restart removed

  private void failUpdate(String reason) {
    LOG.error("Update failed: " + reason);
    System.err.println("Update failed: " + reason);
    this.killUpdateAlerts();
    node.getClientCore()
        .getAlerts()
        .register(
            new SimpleUserAlert(
                true,
                l10n("updateFailedTitle"),
                l10n("updateFailed", "reason", reason),
                l10n("updateFailedShort", "reason", reason),
                UserAlert.CRITICAL_ERROR));
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString("NodeUpdateManager." + key);
  }

  private String l10n(String key, String pattern, String value) {
    return NodeL10n.getBase().getString("NodeUpdateManager." + key, pattern, value);
  }

  /**
   * Called when a new jar has been downloaded. The caller should process the dependencies *AFTER*
   * this method has completed, and then call onDependenciesReady().
   *
   * @param fetched The build number we have fetched.
   * @param result The actual data.
   */
  void onDownloadedNewJar(Bucket result, int fetched, File savedBlob) {
    /* no-op */
  }

  /** Called when the NodeUpdater starts to fetch a new version of the jar. */
  void onStartFetching() {
    long now = System.currentTimeMillis();
    synchronized (this) {
      startedFetchingNextMainJar = now;
    }
  }

  private boolean disabledNotBlown;

  /**
   * @param msg
   * @param disabledNotBlown If true, the auto-updating system is broken, and should be disabled,
   *     but the problem *could* be local e.g. out of disk space and a node sends us a revocation
   *     certificate.
   */
  public void blow(String msg, boolean disabledNotBlown) {
    CoreUpdater blownCoreUpdater = null;
    synchronized (this) {
      if (hasBeenBlown) {
        if (this.disabledNotBlown && !disabledNotBlown) {
          disabledNotBlown = true;
        }
        LOG.error(
            "The key has ALREADY been marked as blown! Message was "
                + revocationMessage
                + " new message "
                + msg);
        return;
      } else {
        this.revocationMessage = msg;
        this.hasBeenBlown = true;
        this.disabledNotBlown = disabledNotBlown;
        // We must get to the lower part, and show the user the message
        try {
          if (disabledNotBlown) {
            System.err.println("THE AUTO-UPDATING SYSTEM HAS BEEN DISABLED!");
            System.err.println(
                "We do not know whether this is a local problem or the auto-update system has in"
                    + " fact been compromised. What we do know:\n"
                    + revocationMessage);
          } else {
            System.err.println("THE AUTO-UPDATING SYSTEM HAS BEEN COMPROMISED!");
            System.err.println(
                "The auto-updating system revocation key has been inserted. It says: "
                    + revocationMessage);
          }
        } catch (Throwable t) {
          try {
            LOG.error("Caught " + t, t);
          } catch (Throwable t1) {
          }
        }
      }
      if (coreUpdater != null) coreUpdater.preKill();
      blownCoreUpdater = coreUpdater;
      coreUpdater = null;
    }
    if (blownCoreUpdater != null) {
      blownCoreUpdater.kill();
    }
    if (revocationAlert == null) {
      revocationAlert = new RevocationKeyFoundUserAlert(msg, disabledNotBlown);
      node.getClientCore().getAlerts().register(revocationAlert);
      // we don't need to advertize updates : we are not going to do them
      killUpdateAlerts();
    }
    uom.killAlert();
    broadcastUOMAnnounces();
  }

  /** Kill all UserAlerts asking the user whether he wants to update. */
  private void killUpdateAlerts() {
    node.getClientCore().getAlerts().unregister(alert);
  }

  /** Called when the RevocationChecker has got 3 DNFs on the revocation key */
  public void noRevocationFound() {
    deployUpdate(); // May have been waiting for the revocation.
    deployPluginUpdates();
    // If we're still here, we didn't update.
    broadcastUOMAnnounces();
    node.getTicker()
        .queueTimedJob(
            () -> revocationChecker.start(false), node.getRandom().nextInt((int) DAYS.toMillis(1)));
  }

  private void deployPluginUpdates() {
    PluginJarUpdater[] updaters = null;
    synchronized (this) {
      if (this.pluginUpdaters != null) {
        updaters = pluginUpdaters.values().toArray(new PluginJarUpdater[0]);
      }
    }
    boolean restartRevocationFetcher = false;
    if (updaters != null) {
      for (PluginJarUpdater u : updaters) {
        if (u.onNoRevocation()) {
          restartRevocationFetcher = true;
        }
      }
    }
    if (restartRevocationFetcher) {
      revocationChecker.start(true, true);
    }
  }

  /**
   * Mark the update system as “armed”. In package‑based mode this only influences legacy UI text;
   * {@link CoreUpdater} drives actual downloads when auto‑update is allowed or when the user clicks
   * Download.
   */
  public void arm() {
    armed = true;
  }

  void deployOffThread(long delay, final boolean announce) {
    if (announce) maybeBroadcastUOMAnnounces();
  }

  protected void maybeBroadcastUOMAnnounces() {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Maybe broadcast UOM announces");
    }
    synchronized (NodeUpdateManager.this) {
      if (hasBeenBlown) {
        return;
      }
      if (peersSayBlown) {
        return;
      }
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Maybe broadcast UOM announces (2)");
    }
    // If the node has no peers, noRevocationFound will never be called.
    broadcastUOMAnnounces();
  }

  /** Has the private key been revoked? */
  public boolean isBlown() {
    return hasBeenBlown;
  }

  public boolean hasNewMainJar() {
    CoreUpdater cu = coreUpdater;
    return cu != null && cu.canUpdateNow();
  }

  /**
   * What version has been fetched?
   *
   * <p>This includes jar's fetched via UOM, because the UOM code feeds its results through the
   * mainUpdater.
   */
  public int newMainJarVersion() {
    CoreUpdater cu = coreUpdater;
    return (cu != null) ? cu.getFetchedVersion() : -1;
  }

  public boolean fetchingNewMainJar() {
    CoreUpdater cu = coreUpdater;
    return (cu != null && cu.isFetching());
  }

  public int fetchingNewMainJarVersion() {
    CoreUpdater cu = coreUpdater;
    return (cu != null) ? cu.fetchingVersion() : -1;
  }

  public boolean inFinalCheck() {
    return false;
  }

  public int getRevocationDNFCounter() {
    return revocationChecker.getRevocationDNFCounter();
  }

  /** What version is the node currently running? */
  public int getMainVersion() {
    return Version.currentBuildNumber();
  }

  public boolean isArmed() {
    return armed || isAutoUpdateAllowed;
  }

  /** Is the node able to update as soon as the revocation fetch has been completed? */
  public boolean canUpdateNow() {
    CoreUpdater cu = coreUpdater;
    return cu != null && cu.canUpdateNow();
  }

  /**
   * Is the node able to update *immediately*? (i.e. not only is it ready in every other sense, but
   * also a revocation fetch has completed recently enough not to need another one)
   */
  public boolean canUpdateImmediately() {
    return canUpdateNow();
  }

  // Config callbacks

  class UpdaterEnabledCallback extends BooleanCallback {

    @Override
    public Boolean get() {
      if (isEnabled()) {
        return true;
      }
      synchronized (NodeUpdateManager.this) {
        if (disabledNotBlown) {
          return true;
        }
      }
      return false;
    }

    @Override
    public void set(Boolean val) throws InvalidConfigValueException {
      enable(val);
    }
  }

  class AutoUpdateAllowedCallback extends BooleanCallback {

    @Override
    public Boolean get() {
      return isAutoUpdateAllowed();
    }

    @Override
    public void set(Boolean val) throws InvalidConfigValueException {
      setAutoUpdateAllowed(val);
    }
  }

  class UpdateURICallback extends StringCallback {

    @Override
    public String get() {
      return getURI().toString(false, false);
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      FreenetURI uri;
      try {
        uri = new FreenetURI(val);
      } catch (MalformedURLException e) {
        throw new InvalidConfigValueException(
            l10n("invalidUpdateURI", "error", e.getLocalizedMessage()));
      }
      if (uri.hasMetaStrings()) {
        throw new InvalidConfigValueException(l10n("updateURIMustHaveNoMetaStrings"));
      }
      if (!uri.isUSK()) {
        throw new InvalidConfigValueException(l10n("updateURIMustBeAUSK"));
      }
      setURI(uri);
    }
  }

  public class UpdateRevocationURICallback extends StringCallback {

    @Override
    public String get() {
      return getRevocationURI().toString(false, false);
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      FreenetURI uri;
      try {
        uri = new FreenetURI(val);
      } catch (MalformedURLException e) {
        throw new InvalidConfigValueException(
            l10n("invalidRevocationURI", "error", e.getLocalizedMessage()));
      }
      setRevocationURI(uri);
    }
  }

  /**
   * Called when a peer indicates in its UOMAnnounce that it has fetched the revocation key (or
   * failed to do so in a way suggesting that somebody knows the key).
   *
   * @param source The node which is claiming this.
   */
  void peerClaimsKeyBlown() {
    // Note that UpdateOverMandatoryManager manages the list of peers who
    // think this.
    // All we have to do is cancel the update.

    peersSayBlown = true;
  }

  /** Called inside locks, so don't lock anything */
  public void notPeerClaimsKeyBlown() {
    peersSayBlown = false;
    node.getExecutor().execute(() -> {}, "Check for updates");
    node.getTicker().queueTimedJob(() -> maybeBroadcastUOMAnnounces(), REVOCATION_FETCH_TIMEOUT);
  }

  boolean peersSayBlown() {
    return peersSayBlown;
  }

  public File getMainBlob(int version) {
    return null;
  }

  public synchronized long timeRemainingOnCheck() {
    long now = System.currentTimeMillis();
    return Math.max(0, REVOCATION_FETCH_TIMEOUT - (now - gotJarTime));
  }

  /**
   * @deprecated Use {@link #getByteCounter()} instead of accessing this directly.
   */
  @Deprecated
  /* It’s not the field that is deprecated but accessing it directly is. */
  final ByteCounter ctr =
      new ByteCounter() {

        @Override
        public void receivedBytes(int x) {
          // FIXME
        }

        @Override
        public void sentBytes(int x) {
          node.getNodeStats().reportUOMBytesSent(x);
        }

        @Override
        public void sentPayload(int x) {
          // Ignore. It will be reported to sentBytes() as well.
        }
      };

  public void disableThisSession() {
    disabledThisSession = true;
  }

  protected long getStartedFetchingNextMainJarTimestamp() {
    return startedFetchingNextMainJar;
  }

  public void disconnected(PeerNode pn) {
    uom.disconnected(pn);
  }

  public void deployPlugin(String fn) throws IOException {
    PluginJarUpdater updater;
    synchronized (this) {
      if (hasBeenBlown) {
        LOG.error("Not deploying update for " + fn + " because revocation key has been blown!");
        return;
      }
      updater = pluginUpdaters.get(fn);
    }
    updater.writeJar();
  }

  public void deployPluginWhenReady(String fn) throws IOException {
    PluginJarUpdater updater;
    synchronized (this) {
      if (hasBeenBlown) {
        LOG.error("Not deploying update for " + fn + " because revocation key has been blown!");
        return;
      }
      updater = pluginUpdaters.get(fn);
    }
    boolean wasRunning = revocationChecker.start(true, true);
    updater.arm(wasRunning);
  }

  public boolean dontAllowUOM() {
    if (node.isOpennetEnabled() && node.wantAnonAuth(true)) {
      // We are a seednode.
      // Normally this means we won't send UOM.
      // However, if something breaks severely, we need an escape route.
      return node.getUptime() <= MINUTES.toMillis(5)
          || node.getPeers().countCompatibleRealPeers() != 0;
    }
    return false;
  }

  public boolean fetchingFromUOM() {
    return uom.isFetchingMain();
  }

  // onDependenciesReady removed

  /** Show the progress of individual dependencies if possible */
  /**
   * Render core update status/controls into the global Alerts panel. Delegates to {@link
   * CoreUpdater#renderProperties(HTMLNode)}.
   */
  public void renderProgress(HTMLNode alertNode) {
    CoreUpdater cu;
    synchronized (this) {
      cu = coreUpdater;
    }
    if (cu != null) cu.renderProperties(alertNode);
  }

  public boolean brokenDependencies() {
    // No dependency checking in package-based updater
    return false;
  }

  public void onStartFetchingUOM() {
    /* no-op */
  }

  public synchronized File getCurrentVersionBlobFile() {
    // Serving main.jar over UOM is disabled in package-based updater.
    return null;
  }

  // getMainUpdater() removed; jar updates are disabled.

  public Node getNode() {
    return node;
  }

  public RevocationChecker getRevocationChecker() {
    return revocationChecker;
  }

  public UpdateOverMandatoryManager getUpdateOverMandatory() {
    return uom;
  }

  public ByteCounter getByteCounter() {
    return ctr;
  }

  // --- Core updater wiring ---

  /** Create and wire the package‑based {@link CoreUpdater} if not already present. */
  public synchronized void startCoreUpdater() {
    if (coreUpdater != null) return;
    coreUpdater =
        new CoreUpdater(
            this,
            getCoreInfoURI(),
            Version.currentBuildNumber(),
            -1,
            Integer.MAX_VALUE,
            "core-info-");
  }

  /** Current {@link CoreUpdater} instance or null when the core updater is not enabled. */
  public synchronized CoreUpdater getCoreUpdater() {
    return coreUpdater;
  }

  /**
   * Whether legacy main‑jar UoM flows should be handled.
   *
   * <p>In package‑based updater mode this returns {@code false} to avoid serving/fetching the main
   * JAR via UoM. Revocation UoM remains enabled.
   */
  public synchronized boolean supportsJarUOM() {
    return false;
  }
}
