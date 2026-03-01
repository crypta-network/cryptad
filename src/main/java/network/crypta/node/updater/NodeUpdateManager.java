package network.crypta.node.updater;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
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
import network.crypta.config.Option;
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
import network.crypta.node.useralerts.UpdatedVersionAvailableUserAlert;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.IntCallback;
import network.crypta.support.api.StringCallback;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * Supervises auto‑update components for the node.
 *
 * <p>This manager wires the package‑based core updater ({@link CoreUpdater}) and maintains
 * compatibility glue for historical Update‑Over‑Mandatory (UoM) behavior. Today core updates are
 * delivered as OS/arch‑specific packages (deb/rpm/dmg/exe/flatpak/snap). Serving or fetching the
 * main JAR via UoM is intentionally disabled; only revocation handling and announcements remain.
 *
 * <p>Lifecycle and responsibilities:
 *
 * <ul>
 *   <li>Build and hold configuration options under the {@code node.updater} subconfig.
 *   <li>Start/stop the {@link CoreUpdater} when enabled/disabled.
 *   <li>Track and react to revocation state via {@link RevocationChecker}, surfacing alerts.
 *   <li>Render the core update status into the Alerts panel and broadcast UoM announcements.
 * </ul>
 *
 * <p>Threading and state: methods that mutate shared state are generally synchronized on the
 * instance; read‑only getters typically avoid long‑held locks. Callers should treat {@code
 * NodeUpdateManager} as long‑lived and bound to the lifecycle of {@link Node}. Instances are not
 * intended for reuse across nodes. All operations are designed to be idempotent across repeated
 * invocations.
 *
 * <p>Procedure for updating the update key: create a new key and produce a new build X (the
 * “transition version”). Build X must be UoM‑compatible with the previous transition version so
 * older nodes can update. UoM compatibility implies an overlapping set of connection setup
 * negotiation types (see {@code FNPPacketMangler.supportedNegTypes()}) and compatible message
 * formats. Build X is inserted to both the old and the new key; its SSK on the old key is
 * hard‑coded as the transition version. The next build (X+1) can drop legacy compatibility and is
 * inserted only to the new key. Secure key backups are required and documented elsewhere.
 */
public final class NodeUpdateManager {
  private static final Logger LOG = LoggerFactory.getLogger(NodeUpdateManager.class);

  // L10n parameter keys and repeated URL query parts
  private static final String L10N_PARAM_ERROR = "error";
  private static final String QUERY_TEXT_PLAIN = "?type=text/plain";
  private static final String URI_TYPE_SEPARATOR = "@";
  private static final String URI_PATH_SEPARATOR = "/";
  private static final String UPDATE_URI_PREFIX = "USK@";
  private static final String UPDATE_URI_DOC_NAME = "info";
  private static final String LEGACY_UPDATE_URI_DOC_NAME = "jar";
  private static final String REVOCATION_URI_PREFIX = "SSK@";
  private static final String REVOCATION_URI_DOC_NAME = "revoked";
  private static final String LAST_KNOWN_GOOD_FETCHED_EDITION_OPTION =
      "lastKnownGoodFetchedEdition";
  private static final String LAST_KNOWN_GOOD_FETCHED_EDITION_KEY_OPTION =
      "lastKnownGoodFetchedEditionKey";
  private static final String REVOCATION_URI_OPTION = "revocationURI";

  /**
   * The last build on the previous key with Java 7 support. Older nodes can update to this point
   * via old UOM.
   */
  public static final int TRANSITION_VERSION = 1481;

  /** Public key material for post-TRANSITION_VERSION update URIs. */
  public static final String UPDATE_URI =
      "uQnFwn0aEFSAZihnSDduEHUd3GUmGg68ATn5R95MKJo,mcNiZqosfZ1F~PkZY8v1TuDKsY6noda-hGRXvu7uUFc,AQACAAE";

  /** Public key material used to derive the revocation key URI. */
  public static final String REVOCATION_URI =
      "TAnVLWtrGguuIi3fXkf8OmT5Pmy2Hduai18FUCP0uAU,tMg8t4kLktzmz~uFC6jk~-CUNv1mQ-C573sjLeg0alU,AQACAAE";

  // These are necessary to prevent DoS.
  /** Maximum allowed decoded byte length of a revocation document. */
  public static final long MAX_REVOCATION_KEY_LENGTH = 32L * 1024L;

  /** Maximum temporary storage budget in bytes while fetching a revocation document. */
  public static final long MAX_REVOCATION_KEY_TEMP_LENGTH = 64L * 1024L;

  /** Maximum on‑disk blob length in bytes for a persisted revocation document. */
  public static final long MAX_REVOCATION_KEY_BLOB_LENGTH = 128L * 1024L;

  /** Maximum allowed size in bytes for the historical main JAR (legacy paths only). */
  public static final long MAX_MAIN_JAR_LENGTH = 48L * 1024L * 1024L; // 48MiB

  /** Maximum allowed size in bytes for the IPv4‐to‐country database. */
  public static final long MAX_IP_TO_COUNTRY_LENGTH = 24L * 1024L * 1024L;

  /** Whether the updater is in the legacy final-check phase. */
  public static final boolean IN_FINAL_CHECK = false;

  /** Remaining time for a legacy final-check timer. */
  public static final long TIME_REMAINING_ON_CHECK = 0L;

  /** Legacy timestamp for when normal main-jar fetching started. */
  static final long STARTED_FETCHING_NEXT_MAIN_JAR_TIMESTAMP = 0L;

  /** Whether dependency checks are currently considered broken. */
  public static final boolean BROKEN_DEPENDENCIES = false;

  /** Whether legacy main-jar Update-over-Mandatory flows are enabled. */
  public static final boolean SUPPORTS_JAR_UOM = false;

  // Installer/seednodes length caps removed with deprecated auto-fetch paths

  private FreenetURI updateURI;
  private FreenetURI revocationURI;
  private volatile int lastKnownGoodFetchedEdition;
  private volatile String lastKnownGoodFetchedEditionKey;

  // Legacy MainJarUpdater removed; core package updater is used instead.
  // Package-based core updater (Kotlin)
  private CoreUpdater coreUpdater;

  private final boolean wasEnabledOnStartup;

  /** Is auto-update enabled? */
  private volatile boolean isAutoUpdateAllowed;

  /** Has the user given the go-ahead? */
  private volatile boolean armed;

  /**
   * Currently deploying an update? Set when we start to deploy an update. Which means it should not
   * be unsetted, except in the case of a severe error causing a valid update to fail. However, it
   * is unset in this case, so that we can try again with another build.
   */
  // Unused flag removed; deployment happens only via CoreUpdater

  private final Object broadcastUOMAnnouncesSync = new Object();

  private boolean broadcastUOMAnnounces = false;

  /** Owning node; used for configuration, scheduling, and network interactions. */
  public final Node node;

  final RevocationChecker revocationChecker;

  private String revocationMessage;
  private volatile boolean hasBeenBlown;
  private volatile boolean peersSayBlown;

  // Revocation alert
  private RevocationKeyFoundUserAlert revocationAlert;
  // Update alert
  private final UpdatedVersionAvailableUserAlert alert;

  /**
   * Legacy Update‑Over‑Mandatory (UoM) coordinator for announcement/fallback tracking. Serving or
   * fetching the main JAR via UoM is disabled; revocation UoM remains enabled.
   */
  public final UpdateOverMandatoryManager uom;

  // Temp blob suffix removed (legacy path)
  static final String TEMP_FILE_SUFFIX = ".updater.tmp";

  /**
   * Creates a new manager bound to the given {@link Node} and configuration subtree.
   *
   * <p>The constructor wires the {@code node.updater} subconfig, initializes the revocation
   * checker, and prepares the legacy UoM coordinator. It does not start background work; call
   * {@link #enable(boolean)} or {@link #startCoreUpdater()} to begin update processing.
   *
   * @param node the owning node; must remain valid for the lifetime of this manager (non‑null)
   * @param config global configuration; a {@code node.updater} subconfig is created and populated
   * @throws InvalidConfigValueException if provided, URIs are malformed or violate required shapes
   */
  public NodeUpdateManager(Node node, Config config) throws InvalidConfigValueException {
    this.node = node;
    this.hasBeenBlown = false;
    this.alert = new UpdatedVersionAvailableUserAlert(this);
    alert.isValid(false);

    SubConfig updaterConfig = config.createSubConfig("node.updater");

    updaterConfig.register(
        "enabled",
        true,
        new Option.Meta(
            1, false, false, "NodeUpdateManager.enabled", "NodeUpdateManager.enabledLong"),
        new UpdaterEnabledCallback());

    wasEnabledOnStartup = updaterConfig.getBoolean("enabled");

    // is the auto-update allowed?
    updaterConfig.register(
        "autoupdate",
        false,
        new Option.Meta(
            2,
            false,
            true,
            "NodeUpdateManager.installNewVersions",
            "NodeUpdateManager.installNewVersionsLong"),
        new AutoUpdateAllowedCallback());
    isAutoUpdateAllowed = updaterConfig.getBoolean("autoupdate");

    // Set default update URI for new nodes.
    updaterConfig.register(
        "URI",
        UPDATE_URI,
        new Option.Meta(
            3, true, true, "NodeUpdateManager.updateURI", "NodeUpdateManager.updateURILong"),
        new UpdateURICallback());

    String configuredUpdateUriValue = updaterConfig.getString("URI");
    try {
      updateURI = parseConfiguredUpdateURI(configuredUpdateUriValue);
    } catch (MalformedURLException e) {
      throw new InvalidConfigValueException(
          l10n("invalidUpdateURI", L10N_PARAM_ERROR, e.getLocalizedMessage()));
    }
    migrateLegacyUpdateUriValueIfNeeded(updaterConfig, configuredUpdateUriValue);

    if (updateURI.hasMetaStrings()) {
      throw new InvalidConfigValueException(l10n("updateURIMustHaveNoMetaStrings"));
    }
    if (!updateURI.isUSK()) {
      throw new InvalidConfigValueException(l10n("updateURIMustBeAUSK"));
    }

    updaterConfig.register(
        REVOCATION_URI_OPTION,
        REVOCATION_URI,
        new Option.Meta(
            4,
            true,
            false,
            "NodeUpdateManager.revocationURI",
            "NodeUpdateManager.revocationURILong"),
        new UpdateRevocationURICallback());

    String configuredRevocationUriValue = updaterConfig.getString(REVOCATION_URI_OPTION);
    try {
      revocationURI = parseConfiguredRevocationURI(configuredRevocationUriValue);
    } catch (MalformedURLException e) {
      throw new InvalidConfigValueException(
          l10n("invalidRevocationURI", L10N_PARAM_ERROR, e.getLocalizedMessage()));
    }
    migrateLegacyRevocationUriValueIfNeeded(updaterConfig, configuredRevocationUriValue);

    updaterConfig.register(
        LAST_KNOWN_GOOD_FETCHED_EDITION_OPTION,
        -1,
        new Option.Meta(
            5,
            true,
            false,
            "NodeUpdateManager.lastKnownGoodFetchedEdition",
            "NodeUpdateManager.lastKnownGoodFetchedEditionLong"),
        new LastKnownGoodFetchedEditionCallback(),
        false);
    lastKnownGoodFetchedEdition =
        sanitizeFetchedEdition(updaterConfig.getInt(LAST_KNOWN_GOOD_FETCHED_EDITION_OPTION));

    updaterConfig.register(
        LAST_KNOWN_GOOD_FETCHED_EDITION_KEY_OPTION,
        UPDATE_URI,
        new Option.Meta(
            6,
            true,
            false,
            "NodeUpdateManager.lastKnownGoodFetchedEditionKey",
            "NodeUpdateManager.lastKnownGoodFetchedEditionKeyLong"),
        new LastKnownGoodFetchedEditionKeyCallback());
    lastKnownGoodFetchedEditionKey =
        sanitizePublicKeyMaterial(
            updaterConfig.getString(LAST_KNOWN_GOOD_FETCHED_EDITION_KEY_OPTION));
    alignLastKnownGoodFetchedEditionToCurrentUpdateKey();

    // Deprecated UI option: updateSeednodes (no longer shown on the Auto-update page).
    // Keep internal default as false; accept but ignore legacy config values.
    updaterConfig.registerIgnoredOption("updateSeednodes");

    // Deprecated UI option: updateInstallers (no longer shown on the Auto-update page).
    // Keep internal default as false; accept but ignore legacy config values.
    updaterConfig.registerIgnoredOption("updateInstallers");

    updaterConfig.finishedInitialization();

    this.revocationChecker =
        new RevocationChecker(
            this,
            new File(node.services().clientCore().getPersistentTempDir(), "revocation-key.fblob"));

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
      HighLevelSimpleClient hlsc = node.services().clientCore().makeClient(priority, false, false);
      FetchContext context = hlsc.getFetchContext();
      context.setMaxNonSplitfileRetries(-1);
      context.setMaxSplitfileBlockRetries(-1);
      context.setMaxTempLength(maxSize);
      context.setMaxOutputLength(maxSize);
      ClientGetter get = new ClientGetter(this, freenetURI, context, priority, null, null, null);
      try {
        node.services().clientCore().getClientContext().start(get);
      } catch (PersistenceDisabledException _) {
        // Impossible
      } catch (FetchException e) {
        onFailure(e);
      }
    }

    @Override
    public void onFailure(FetchException e) {
      LOG.warn("Failed to fetch {}", filename, e);
    }

    @Override
    public void onSuccess(FetchResult result, ClientGetter state) {
      File temp;
      try {
        temp = FileUtil.createTempFile(filename, ".tmp", directory.dir());
        temp.deleteOnExit();
        writeBucketToFile(temp, result.asBucket());
        for (int i = 0; i < 10; i++) {
          // Consider adding a callback in case it's being used on Windows.
          if (FileUtil.moveTo(temp, directory.file(filename))) {
            LOG.info(
                "Successfully fetched {} for version {}", filename, Version.currentBuildNumber());
            break;
          } else {
            LOG.warn("Failed to rename {} to {} after fetching it from Crypta.", temp, filename);
            sleepWithBackoff(i);
          }
        }
        deleteTempFile(temp);
      } catch (IOException e) {
        LOG.error(
            "Fetched but failed to write out {} - please check that the node has permissions to"
                + " write in {} and particularly the file {}",
            filename,
            directory.dir(),
            filename,
            e);
      } finally {
        IOUtils.closeQuietly(result.asBucket());
      }
    }

    private static void writeBucketToFile(File temp, Bucket bucket) throws IOException {
      try (FileOutputStream fos = new FileOutputStream(temp)) {
        BucketTools.copyTo(bucket, fos, -1);
      }
    }

    private static void deleteTempFile(File temp) {
      try {
        // The temp file may have been moved into place already; quietly ignore when missing.
        Files.deleteIfExists(temp.toPath());
      } catch (IOException ioe) {
        LOG.warn("Failed to delete temp file {}", temp, ioe);
      }
    }

    @SuppressWarnings("java:S1905")
    private void sleepWithBackoff(int i) {
      try {
        Thread.sleep(
            SECONDS.toMillis(1)
                + node.bootstrap()
                    .fastWeakRandom()
                    .nextInt(
                        (int)
                            SECONDS.toMillis(
                                (long) Math.min(Math.pow(2, i), (double) MINUTES.toSeconds(15)))));
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
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

  /**
   * Returns the downloaded installer file for Windows if present and non‑empty.
   *
   * @return an existing readable file for the Windows installer, or {@code null} when absent
   */
  public File getInstallerWindows() {
    File f = NodeFile.INSTALLER_WINDOWS.getFile(node);
    if (!(f.exists() && f.canRead() && f.length() > 0)) {
      return null;
    } else {
      return f;
    }
  }

  /**
   * Returns the downloaded installer file for non‑Windows platforms if present and non‑empty.
   *
   * @return an existing readable file for the Unix/macOS installer, or {@code null} when absent
   */
  public File getInstallerNonWindows() {
    File f = NodeFile.INSTALLER_NON_WINDOWS.getFile(node);
    if (!(f.exists() && f.canRead() && f.length() > 0)) {
      return null;
    } else {
      return f;
    }
  }

  /**
   * Returns the USK‑derived URI for the seednodes list corresponding to the current build.
   *
   * @return a {@link FreenetURI} pointing to {@code seednodes-<build>} under the update key
   */
  @SuppressWarnings("unused")
  public FreenetURI getSeednodesURI() {
    FreenetURI uri = getURI();
    return uri.sskForUSK().setDocName("seednodes-" + Version.currentBuildNumber());
  }

  /**
   * Returns the USK‑derived URI for the non‑Windows installer of the current build.
   *
   * @return a {@link FreenetURI} for {@code installer-<build>} under the update key
   */
  public FreenetURI getInstallerNonWindowsURI() {
    FreenetURI uri = getURI();
    return uri.sskForUSK().setDocName("installer-" + Version.currentBuildNumber());
  }

  /**
   * Returns the USK‑derived URI for the Windows installer of the current build.
   *
   * @return a {@link FreenetURI} for {@code wininstaller-<build>} under the update key
   */
  public FreenetURI getInstallerWindowsURI() {
    FreenetURI uri = getURI();
    return uri.sskForUSK().setDocName("wininstaller-" + Version.currentBuildNumber());
  }

  /**
   * Returns the USK‑derived URI for the IPv4‑to‑country database used by the node.
   *
   * @return a {@link FreenetURI} for {@code iptocountryv4-<build>} under the update key
   */
  public FreenetURI getIPv4ToCountryURI() {
    FreenetURI uri = getURI();
    return uri.sskForUSK().setDocName("iptocountryv4-" + Version.currentBuildNumber());
  }

  /**
   * Starts user‑visible alerting and kicks off background fetchers that do not depend on core
   * update enablement. Auto‑update itself is started or stopped via {@link #enable(boolean)}.
   */
  public void start() {

    node.services().clientCore().getAlerts().register(alert);

    enable(wasEnabledOnStartup);

    // Deprecated: seednodes/installers are no longer auto-fetched here

    // Note: make updateIPToCountry configurable
    SimplePuller ip4Getter = new SimplePuller(getIPv4ToCountryURI(), NodeFile.IPV4_TO_COUNTRY);
    ip4Getter.start(RequestStarter.UPDATE_PRIORITY_CLASS, MAX_IP_TO_COUNTRY_LENGTH);
  }

  /** Broadcasts UoM announcements to local peers when armed and applicable. */
  void broadcastUOMAnnounces() {
    if (LOG.isDebugEnabled()) {
      LOG.debug("UOM announce: begin local broadcast prep");
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
      LOG.debug("UOM announce: dispatching local broadcast");
    }
    node.network()
        .peers()
        .messenger()
        .localBroadcast(msg, true, true, getByteCounter(), TRANSITION_VERSION, Integer.MAX_VALUE);
  }

  /** Return the length of the data fetched for the current version, or {@code -1}. */
  private long canAnnounceUOMNew() {
    return -1;
  }

  private Message getNewUOMAnnouncement(long blobSize) {
    FreenetURI localUpdateURI;
    FreenetURI localRevocationURI;
    synchronized (this) {
      localUpdateURI = updateURI;
      localRevocationURI = revocationURI;
    }
    int fetchedVersion = (blobSize <= 0) ? -1 : Version.currentBuildNumber();
    return new DMT.UOMAnnouncementBuilder()
        .mainKey(localUpdateURI.toString())
        .revocationKey(localRevocationURI.toString())
        .haveRevocation(getRevocationChecker().hasBlown())
        .mainJarVersion(fetchedVersion)
        .timeLastTriedRevocationFetch(getRevocationChecker().lastSucceededDelta())
        .revocationDNFCount(getRevocationChecker().getRevocationDNFCounter())
        .revocationKeyLength(getRevocationChecker().getBlobSize())
        .mainJarLength(blobSize)
        .pingTime((int) node.network().stats().getNodeAveragePingTime())
        .bwlimitDelayTime((int) node.network().stats().getBwlimitDelayTime())
        .build();
  }

  /**
   * Sends a UoM announcement to a newly connected peer when there is information worth broadcasting
   * and the peer is up enough‑to‑date to understand it.
   *
   * @param peer the connected peer to which an announcement may be sent; ignored when announcements
   *     are not yet armed or local revocation state is inconsistent
   */
  public void maybeSendUOMAnnounce(PeerNode peer) {

    synchronized (broadcastUOMAnnouncesSync) {
      if (!broadcastUOMAnnounces) {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Not sending UOM on connect: Nothing worth announcing yet");
        }
        return; // nothing worth announcing yet
      }
    }
    if (hasBeenBlown && !getRevocationChecker().hasBlown()) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Not sending UOM (any) on connect: Local problem causing blown key");
      }
      // Local problem, don't broadcast.
      return;
    }
    long size = canAnnounceUOMNew();
    try {
      if (Version.isBuildAtLeast(peer.getNodeName(), peer.getBuildNumber(), TRANSITION_VERSION)) {
        peer.transport().sendAsync(getNewUOMAnnouncement(size), null, getByteCounter());
      }
    } catch (NotConnectedException _) {
      // Sad, but ignore it
    }
  }

  /**
   * Returns whether the auto‑update system is enabled for the core updater.
   *
   * @return {@code true} when a {@link CoreUpdater} instance is currently wired and active
   */
  public synchronized boolean isEnabled() {
    return (coreUpdater != null);
  }

  /**
   * Enable or disable auto-update.
   *
   * @param enable Whether auto-update should be enabled.
   */
  void enable(boolean enable) {
    // Note: wrapper gating removed in favor of CoreUpdater
    CoreUpdater stoppedCoreUpdater = null;
    CoreUpdater startedCoreUpdater = null;
    // We need to run the revocation checker even if the auto-update is
    // disabled.
    // Two reasons:
    // 1. For the benefit of other nodes, and because even if auto-update is
    // off, it's something the user should probably know about.
    // 2. When the key is blown, we turn off auto-update!!!!
    getRevocationChecker().start(false);
    synchronized (this) {
      boolean enabled = (coreUpdater != null);
      if (enabled == enable) {
        return;
      }
      if (!enable) {
        // Kill it
        coreUpdater.preKill();
        stoppedCoreUpdater = coreUpdater;
        coreUpdater = null;
        disabledNotBlown = false;
      } else {
        // Start CoreUpdater
        startCoreUpdater();
        startedCoreUpdater = coreUpdater;
        // Suppress obsolete an Update-ASAP form in alert; CoreUpdater renders its own buttons
        armed = true;
      }
    }
    if (!enable) {
      // When we reach here with enable=false, coreUpdater was non-null above,
      // so stoppedCoreUpdater is guaranteed to be non-null.
      stoppedCoreUpdater.kill();
    } else {
      if (startedCoreUpdater != null) {
        boolean stillCurrent;
        synchronized (this) {
          stillCurrent = (coreUpdater == startedCoreUpdater);
        }
        if (stillCurrent) {
          startedCoreUpdater.start();
        } else if (LOG.isDebugEnabled()) {
          LOG.debug("Skipping stale CoreUpdater start after concurrent state change");
        }
      }
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

  /**
   * Returns the base USK for core updates, with the current build set as the suggested edition.
   *
   * @return a {@link FreenetURI} representing the update USK, never {@code null}
   */
  public synchronized FreenetURI getURI() {
    return updateURI;
  }

  /**
   * Returns the update base with docname switched to {@code "info"} (core package info editions).
   * Used by {@link CoreUpdater}.
   *
   * @return a {@link FreenetURI} pointing to the {@code info} document under the update USK
   */
  public synchronized FreenetURI getCoreInfoURI() {
    return updateURI.setDocName("info");
  }

  /**
   * Returns the URI for the user‑facing changelog under the update USK.
   *
   * @return a {@link FreenetURI} that resolves to the short changelog document
   */
  public synchronized FreenetURI getChangelogURI() {
    return updateURI.setDocName("changelog");
  }

  /**
   * Returns the URI for the developer‑oriented full changelog under the update USK.
   *
   * @return a {@link FreenetURI} that resolves to the full changelog document
   */
  public synchronized FreenetURI getDeveloperChangelogURI() {
    return updateURI.setDocName("fullchangelog");
  }

  /**
   * Add links to the changelog for the given version to the given node.
   *
   * <p>Preference order: - Use CHK links provided by {@link CoreUpdater} when available (short and
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
            '/' + s + QUERY_TEXT_PLAIN,
            NodeL10n.getBase().getString("UpdatedVersionAvailableUserAlert.changelog"));
        addedFromCore = true;
      }
      String f = cu.getFullChangelogCHK();
      if (f != null && !f.isEmpty()) {
        if (addedFromCore) node.addChild("br");
        node.addChild(
            "a",
            "href",
            '/' + f + QUERY_TEXT_PLAIN,
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
          '/' + changelogUri + QUERY_TEXT_PLAIN,
          NodeL10n.getBase().getString("UpdatedVersionAvailableUserAlert.changelog"));
      node.addChild("br");
      node.addChild(
          "a",
          "href",
          '/' + developerDetailsUri + QUERY_TEXT_PLAIN,
          NodeL10n.getBase().getString("UpdatedVersionAvailableUserAlert.devchangelog"));
    }
  }

  /**
   * Sets the update USK used for core update metadata.
   *
   * <p>The provided {@link FreenetURI} must be a USK without meta-strings. The suggested edition is
   * normalized to the current build. Changing the URI notifies the core updater.
   *
   * @param uri the new USK; must be a valid USK without meta-strings (non‑null)
   */
  public synchronized void setURI(FreenetURI uri) {
    NodeUpdater updater;
    int subscribeEditionSeed;
    synchronized (this) {
      if (updateURI.equals(uri)) {
        return;
      }
      String oldPublicKey = extractPublicKeyMaterial(updateURI);
      updateURI = uri;
      updateURI = updateURI.setSuggestedEdition(Version.currentBuildNumber());
      String newPublicKey = extractPublicKeyMaterial(updateURI);
      if (!newPublicKey.equals(oldPublicKey)) {
        resetLastKnownGoodFetchedEditionLocked(newPublicKey);
      }
      subscribeEditionSeed = computeCoreUpdaterSubscribeEditionSeedLocked(newPublicKey);
      updater = coreUpdater;
      if (updater == null) {
        return;
      }
    }
    updater.onChangeURI(uri, subscribeEditionSeed);
  }

  /**
   * Records a successfully fetched core-info edition for startup seeding.
   *
   * <p>The hint is key-scoped: editions fetched from a stale or different key are ignored.
   */
  void recordSuccessfulCoreInfoFetch(FreenetURI fetchedUri, int fetchedEdition) {
    if (fetchedEdition < 0 || fetchedUri == null) {
      return;
    }
    synchronized (this) {
      String fetchedPublicKey = extractPublicKeyMaterial(fetchedUri);
      String currentPublicKey = extractPublicKeyMaterial(updateURI);
      if (!currentPublicKey.equals(fetchedPublicKey)) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Ignoring fetched edition {} for stale key {}; current key {}",
              fetchedEdition,
              fetchedPublicKey,
              currentPublicKey);
        }
        return;
      }
      if (!currentPublicKey.equals(lastKnownGoodFetchedEditionKey)) {
        lastKnownGoodFetchedEditionKey = currentPublicKey;
        lastKnownGoodFetchedEdition = -1;
      }
      if (fetchedEdition > lastKnownGoodFetchedEdition) {
        lastKnownGoodFetchedEdition = fetchedEdition;
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Recorded last known good fetched edition {} for key {}",
              lastKnownGoodFetchedEdition,
              currentPublicKey);
        }
      }
    }
  }

  /**
   * Returns the configured revocation URI used to publish compromise notices.
   *
   * @return the current revocation {@link FreenetURI}
   */
  public synchronized FreenetURI getRevocationURI() {
    return revocationURI;
  }

  /**
   * Sets the revocation URI used to detect and relay compromise notices.
   *
   * @param uri the new URI to check for revocation messages (non‑null)
   */
  public synchronized void setRevocationURI(FreenetURI uri) {
    synchronized (this) {
      if (revocationURI.equals(uri)) {
        return;
      }
      this.revocationURI = uri;
    }
    getRevocationChecker().onChangeRevocationURI();
  }

  /**
   * Returns whether auto‑update is currently allowed to run in the background.
   *
   * @return {@code true} when background auto‑update is permitted
   */
  public synchronized boolean isAutoUpdateAllowed() {
    return isAutoUpdateAllowed;
  }

  /**
   * Enables or disables auto‑update.
   *
   * <p>When enabled, background download flows are permitted to run and the core updater may fetch
   * new packages. Disabling stops future activity but does not remove already downloaded artifacts.
   *
   * @param val {@code true} to allow background auto‑update, {@code false} to disallow it
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

  /**
   * After 5 minutes, deploy the update even if we haven't got 3 DNFs on the revocation key yet.
   * Reason: we want to be able to deploy UOM updates on nodes with all TOO NEW or leaf nodes whose
   * peers are overloaded/broken. Note that with UOM, revocation certs are automatically propagated
   * node to node, so this should be *relatively* safe. Any better ideas, tell us.
   */
  private static final long REVOCATION_FETCH_TIMEOUT = MINUTES.toMillis(5);

  /** Check whether there is an update to deploy. If there is, do it. */
  private void deployUpdate() {
    /* no-op in package-based updater */
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString("NodeUpdateManager." + key);
  }

  @SuppressWarnings("SameParameterValue")
  private String l10n(String key, String pattern, String value) {
    return NodeL10n.getBase().getString("NodeUpdateManager." + key, pattern, value);
  }

  private boolean disabledNotBlown;

  /**
   * Blows the update key locally and announces the condition to peers. Once blown, auto‑update is
   * considered unsafe and related actions are disabled until the condition is cleared.
   *
   * <p>This method records the message, sets internal flags, raises a user alert, and issues a
   * local broadcast so connected peers can react. It is safe to call repeatedly; later calls will
   * maintain the blown state.
   *
   * @param msg a brief reason or diagnostic to include in user alerts and logs (may be empty)
   * @param disabledNotBlown {@code true} when the updater is disabled for local reasons only (not a
   *     global revocation), {@code false} when the revocation key indicates a global blow
   */
  public void blow(String msg, boolean disabledNotBlown) {
    CoreUpdater blownCoreUpdater;
    synchronized (this) {
      if (hasBeenBlown) {
        LOG.error(
            "The key has ALREADY been marked as blown! Message was {} new message {}",
            revocationMessage,
            msg);
        return;
      }
      this.revocationMessage = msg;
      this.hasBeenBlown = true;
      this.disabledNotBlown = disabledNotBlown;
      if (coreUpdater != null) coreUpdater.preKill();
      blownCoreUpdater = coreUpdater;
      coreUpdater = null;
    }
    printRevocationMessage(disabledNotBlown, msg);
    if (blownCoreUpdater != null) {
      blownCoreUpdater.kill();
    }
    if (revocationAlert == null) {
      revocationAlert = new RevocationKeyFoundUserAlert(msg, disabledNotBlown);
      node.services().clientCore().getAlerts().register(revocationAlert);
      // we don't need to advertise updates: we are not going to do them
      killUpdateAlerts();
    }
    getUpdateOverMandatory().killAlert();
    broadcastUOMAnnounces();
  }

  private void printRevocationMessage(boolean disabledNotBlown, String msg) {
    // We must show the user the message
    try {
      if (disabledNotBlown) {
        LOG.error("THE AUTO-UPDATING SYSTEM HAS BEEN DISABLED!");
        LOG.error(
            "We do not know whether this is a local problem or the auto-update system has in fact"
                + " been compromised. What we do know:{}{}",
            System.lineSeparator(),
            msg);
      } else {
        LOG.error("THE AUTO-UPDATING SYSTEM HAS BEEN COMPROMISED!");
        LOG.error("The auto-updating system revocation key has been inserted. It says: {}", msg);
      }
    } catch (Exception t) {
      try {
        LOG.error("Caught {}", t, t);
      } catch (Exception _) {
        // Ignore secondary logging failures
      }
    }
  }

  /** Kill all UserAlerts asking the user whether he wants to update. */
  private void killUpdateAlerts() {
    node.services().clientCore().getAlerts().unregister(alert);
  }

  /**
   * Clears revocation alert state when a revocation document was expected but not found. The
   * current design does not surface a new alert here; the core updater UI remains the primary
   * status surface.
   */
  public void noRevocationFound() {
    deployUpdate(); // May have been waiting for the revocation.
    // If we're still here, we didn't update.
    broadcastUOMAnnounces();
    node.network()
        .ticker()
        .queueTimedJob(
            () -> getRevocationChecker().start(false),
            node.bootstrap().random().nextInt((int) DAYS.toMillis(1)));
  }

  /** Arms the user‑visible alert for update readiness. */
  public void arm() {
    armed = true;
  }

  /**
   * Schedules or triggers UoM announcements if the node is in a suitable state. Protected to allow
   * controlled invocation from internal timers and connection hooks.
   */
  private void maybeBroadcastUOMAnnounces() {
    if (LOG.isDebugEnabled()) {
      LOG.debug("UOM announce check: begin eligibility scan");
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
      LOG.debug("UOM announce check: passed blow/peer gates");
    }
    // If the node has no peers, noRevocationFound will never be called.
    broadcastUOMAnnounces();
  }

  /**
   * Returns whether the updater has been marked as blown (either locally or via revocation).
   *
   * @return {@code true} when updates are considered unsafe due to a blow condition
   */
  public boolean isBlown() {
    return hasBeenBlown;
  }

  /**
   * Returns whether there is a newer core version available to install.
   *
   * @return {@code true} when a newer version has been fetched and is ready
   */
  public synchronized boolean hasNewMainJar() {
    CoreUpdater cu = coreUpdater;
    return cu != null && cu.canUpdateNow();
  }

  /**
   * Returns the fetched core version when available.
   *
   * @return the fetched version number, or {@code -1} when none is available
   */
  public synchronized int newMainJarVersion() {
    CoreUpdater cu = coreUpdater;
    return (cu != null) ? cu.getFetchedVersion() : -1;
  }

  /**
   * Returns whether the core updater is currently fetching a new version.
   *
   * @return {@code true} when a download is in progress
   */
  public synchronized boolean fetchingNewMainJar() {
    CoreUpdater cu = coreUpdater;
    return (cu != null && cu.isFetching());
  }

  /**
   * Returns the version currently being fetched.
   *
   * @return the in‑flight version number, or {@code -1} when idle
   */
  public synchronized int fetchingNewMainJarVersion() {
    CoreUpdater cu = coreUpdater;
    return (cu != null) ? cu.fetchingVersion() : -1;
  }

  /**
   * Returns the recent count of revocation fetch DNF outcomes, for diagnostics.
   *
   * @return the number of recent DNF results for the revocation fetcher
   */
  public int getRevocationDNFCounter() {
    return getRevocationChecker().getRevocationDNFCounter();
  }

  /**
   * Returns the version number the node is currently running.
   *
   * @return the current build number from {@link Version#currentBuildNumber()}
   */
  public int getMainVersion() {
    return Version.currentBuildNumber();
  }

  /**
   * Returns whether the alert is armed or auto‑update is allowed.
   *
   * @return {@code true} when the alert is armed or auto‑update is allowed
   */
  public boolean isArmed() {
    return armed || isAutoUpdateAllowed;
  }

  /**
   * Returns whether the node could update after a fresh revocation check.
   *
   * @return {@code true} when an update would be possible after revocation verification
   */
  public boolean canUpdateNow() {
    return hasNewMainJar();
  }

  /**
   * Returns whether the node can update immediately without another revocation fetch.
   *
   * @return {@code true} when no additional revocation fetch is needed
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

  class LastKnownGoodFetchedEditionCallback extends IntCallback {

    @Override
    public Integer get() {
      return lastKnownGoodFetchedEdition;
    }

    @Override
    public void set(Integer val) {
      lastKnownGoodFetchedEdition = sanitizeFetchedEdition(val);
    }
  }

  class LastKnownGoodFetchedEditionKeyCallback extends StringCallback {

    @Override
    public String get() {
      return lastKnownGoodFetchedEditionKey;
    }

    @Override
    public void set(String val) {
      lastKnownGoodFetchedEditionKey = sanitizePublicKeyMaterial(val);
    }
  }

  class UpdateURICallback extends StringCallback {

    @Override
    public String get() {
      return extractPublicKeyMaterial(getURI());
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      FreenetURI uri;
      try {
        uri = parseConfiguredUpdateURI(val);
      } catch (MalformedURLException e) {
        throw new InvalidConfigValueException(
            l10n("invalidUpdateURI", L10N_PARAM_ERROR, e.getLocalizedMessage()));
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

  /** Callback adapter that exposes the revocation URI as a mutable string config option. */
  public class UpdateRevocationURICallback extends StringCallback {
    /** Default constructor; creates a callback bound to the outer manager. */
    public UpdateRevocationURICallback() {
      // Intentionally empty: callback holds no additional state and needs no initialization.
    }

    @Override
    public String get() {
      return extractPublicKeyMaterial(getRevocationURI());
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      FreenetURI uri;
      try {
        uri = parseConfiguredRevocationURI(val);
      } catch (MalformedURLException e) {
        throw new InvalidConfigValueException(
            l10n("invalidRevocationURI", L10N_PARAM_ERROR, e.getLocalizedMessage()));
      }
      setRevocationURI(uri);
    }
  }

  private static FreenetURI parseConfiguredUpdateURI(String configuredValue)
      throws MalformedURLException {
    String normalizedLegacyKey = extractLegacyUpdatePublicKeyMaterial(configuredValue);
    if (normalizedLegacyKey != null) {
      FreenetURI parsed = new FreenetURI(expandUpdateUriFromPublicKey(normalizedLegacyKey));
      return parsed.setSuggestedEdition(Version.currentBuildNumber());
    }

    FreenetURI parsed = new FreenetURI(trimConfigValue(configuredValue));
    return parsed.setSuggestedEdition(Version.currentBuildNumber());
  }

  private static FreenetURI parseConfiguredRevocationURI(String configuredValue)
      throws MalformedURLException {
    String normalizedLegacyKey = extractLegacyRevocationPublicKeyMaterial(configuredValue);
    if (normalizedLegacyKey != null) {
      return new FreenetURI(expandRevocationUriFromPublicKey(normalizedLegacyKey));
    }
    return new FreenetURI(trimConfigValue(configuredValue));
  }

  private static String extractLegacyUpdatePublicKeyMaterial(String configuredValue)
      throws MalformedURLException {
    String trimmed = trimConfigValue(configuredValue);
    if (isBarePublicKey(trimmed)) {
      return trimmed;
    }

    FreenetURI parsed = new FreenetURI(trimmed);
    if (!parsed.isUSK() || parsed.hasMetaStrings()) {
      return null;
    }
    String docName = parsed.getDocName();
    if (!UPDATE_URI_DOC_NAME.equals(docName) && !LEGACY_UPDATE_URI_DOC_NAME.equals(docName)) {
      return null;
    }
    return extractPublicKeyMaterial(parsed);
  }

  private static String extractLegacyRevocationPublicKeyMaterial(String configuredValue)
      throws MalformedURLException {
    String trimmed = trimConfigValue(configuredValue);
    if (isBarePublicKey(trimmed)) {
      return trimmed;
    }

    FreenetURI parsed = new FreenetURI(trimmed);
    if (!parsed.isSSK() || parsed.hasMetaStrings()) {
      return null;
    }
    if (!REVOCATION_URI_DOC_NAME.equals(parsed.getDocName())) {
      return null;
    }
    return extractPublicKeyMaterial(parsed);
  }

  private static String expandUpdateUriFromPublicKey(String keyMaterial) {
    return UPDATE_URI_PREFIX
        + keyMaterial
        + URI_PATH_SEPARATOR
        + UPDATE_URI_DOC_NAME
        + URI_PATH_SEPARATOR
        + Version.currentBuildNumber();
  }

  private static String expandRevocationUriFromPublicKey(String keyMaterial) {
    return REVOCATION_URI_PREFIX + keyMaterial + URI_PATH_SEPARATOR + REVOCATION_URI_DOC_NAME;
  }

  private void migrateLegacyUpdateUriValueIfNeeded(SubConfig updaterConfig, String configuredValue)
      throws InvalidConfigValueException {
    migrateLegacyOptionValueIfNeeded(
        updaterConfig,
        "URI",
        configuredValue,
        NodeUpdateManager::extractLegacyUpdatePublicKeyMaterial);
  }

  private void migrateLegacyRevocationUriValueIfNeeded(
      SubConfig updaterConfig, String configuredValue) throws InvalidConfigValueException {
    migrateLegacyOptionValueIfNeeded(
        updaterConfig,
        REVOCATION_URI_OPTION,
        configuredValue,
        NodeUpdateManager::extractLegacyRevocationPublicKeyMaterial);
  }

  private static void migrateLegacyOptionValueIfNeeded(
      SubConfig updaterConfig,
      String optionName,
      String configuredValue,
      LegacyKeyExtractor extractor)
      throws InvalidConfigValueException {
    if (isBarePublicKey(trimConfigValue(configuredValue))) {
      return;
    }

    String extracted;
    try {
      extracted = extractor.extract(configuredValue);
    } catch (MalformedURLException e) {
      throw new InvalidConfigValueException(e.getLocalizedMessage());
    }
    if (extracted == null) {
      return;
    }

    Option<?> option = updaterConfig.getOption(optionName);
    if (option == null) {
      return;
    }
    option.setInitialValue(extracted);
  }

  private static String extractPublicKeyMaterial(FreenetURI uri) {
    String fullUri = uri.toString(false, false);
    if (fullUri == null || fullUri.isEmpty()) {
      return "";
    }
    int typeSeparator = fullUri.indexOf(URI_TYPE_SEPARATOR);
    if (typeSeparator < 0) {
      return fullUri;
    }
    int pathSeparator = fullUri.indexOf(URI_PATH_SEPARATOR, typeSeparator + 1);
    if (pathSeparator < 0) {
      return fullUri.substring(typeSeparator + 1);
    }
    return fullUri.substring(typeSeparator + 1, pathSeparator);
  }

  private static int sanitizeFetchedEdition(Integer edition) {
    if (edition == null) {
      return -1;
    }
    return Math.max(-1, edition);
  }

  private static String sanitizePublicKeyMaterial(String value) {
    String trimmed = trimConfigValue(value);
    if (trimmed == null || trimmed.isEmpty()) {
      return "";
    }
    return isBarePublicKey(trimmed) ? trimmed : "";
  }

  private synchronized void alignLastKnownGoodFetchedEditionToCurrentUpdateKey() {
    String currentUpdatePublicKey = extractPublicKeyMaterial(updateURI);
    if (!currentUpdatePublicKey.equals(lastKnownGoodFetchedEditionKey)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Resetting persisted fetched edition {} due to key mismatch: persisted={}, current={}",
            lastKnownGoodFetchedEdition,
            lastKnownGoodFetchedEditionKey,
            currentUpdatePublicKey);
      }
      resetLastKnownGoodFetchedEditionLocked(currentUpdatePublicKey);
      return;
    }
    lastKnownGoodFetchedEdition = sanitizeFetchedEdition(lastKnownGoodFetchedEdition);
  }

  private int computeCoreUpdaterSubscribeEditionSeedLocked(String currentUpdatePublicKey) {
    if (!currentUpdatePublicKey.equals(lastKnownGoodFetchedEditionKey)) {
      return Version.currentBuildNumber();
    }
    return Math.max(Version.currentBuildNumber(), lastKnownGoodFetchedEdition);
  }

  private void resetLastKnownGoodFetchedEditionLocked(String currentUpdatePublicKey) {
    lastKnownGoodFetchedEdition = -1;
    lastKnownGoodFetchedEditionKey = currentUpdatePublicKey;
  }

  private static boolean isBarePublicKey(String value) {
    if (value == null || value.isEmpty()) {
      return false;
    }
    return !value.contains(URI_TYPE_SEPARATOR) && !value.contains(URI_PATH_SEPARATOR);
  }

  private static String trimConfigValue(String value) {
    return value == null ? null : value.trim();
  }

  @FunctionalInterface
  private interface LegacyKeyExtractor {
    String extract(String configuredValue) throws MalformedURLException;
  }

  /**
   * Called when a peer indicates in its UOMAnnounce that it has fetched the revocation key (or
   * failed to do so in a way suggesting that somebody knows the key).
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
    node.network().executor().execute(() -> {}, "Check for updates");
    node.network()
        .ticker()
        .queueTimedJob(this::maybeBroadcastUOMAnnounces, REVOCATION_FETCH_TIMEOUT);
  }

  boolean peersSayBlown() {
    return peersSayBlown;
  }

  // Legacy blob serving disabled in package-based updater

  final ByteCounter ctr =
      new ByteCounter() {

        @Override
        public void receivedBytes(int x) {
          // No-op
        }

        @Override
        public void sentBytes(int x) {
          node.network().stats().reportUOMBytesSent(x);
        }

        @Override
        public void sentPayload(int x) {
          // Ignore. It will be reported to sentBytes() as well.
        }
      };

  /**
   * Notifies the UoM coordinator that a peer disconnected.
   *
   * @param pn the peer that disconnected
   */
  public void disconnected(PeerNode pn) {
    getUpdateOverMandatory().disconnected(pn);
  }

  /**
   * Returns whether UoM should be suppressed for this node (e.g., seednode or early startup).
   *
   * @return {@code true} when UoM must not be used due to node role or state
   */
  public boolean dontAllowUOM() {
    if (node.network().isOpennetEnabled() && node.network().wantAnonAuth(true)) {
      // We are a seednode.
      // Normally this means we won't send UOM.
      // However, if something breaks severely, we need an escape route.
      return node.network().uptime() <= MINUTES.toMillis(5)
          || node.network().peers().countCompatibleRealPeers() != 0;
    }
    return false;
  }

  /**
   * Returns whether a UoM fetch is currently in progress.
   *
   * @return {@code true} when a legacy UoM fetch is running
   */
  public boolean fetchingFromUOM() {
    return getUpdateOverMandatory().isFetchingMain();
  }

  /**
   * Renders core update status and controls into the Alerts panel.
   *
   * <p>This delegates to {@link CoreUpdater#renderProperties(HTMLNode)} when the core updater is
   * active.
   *
   * @param alertNode the HTML container node to populate with status and action elements
   */
  public void renderProgress(HTMLNode alertNode) {
    CoreUpdater cu;
    synchronized (this) {
      cu = coreUpdater;
    }
    if (cu != null) cu.renderProperties(alertNode);
  }

  /** Callback invoked when beginning a legacy UoM fetch; no‑op in package‑based mode. */
  public void onStartFetchingUOM() {
    /* no-op */
  }

  /**
   * Returns the legacy blob file for the current version.
   *
   * @return always {@code null}; serving the core JAR via UoM is disabled
   */
  public synchronized File getCurrentVersionBlobFile() {
    // Serving the main.jar over UOM is disabled in package-based updater.
    return null;
  }

  // getMainUpdater() removed; jar updates are disabled.

  /**
   * Returns the owning {@link Node}.
   *
   * @return the node instance associated with this manager
   */
  public Node getNode() {
    return node;
  }

  /**
   * Returns the revocation checker responsible for detecting blown keys.
   *
   * @return the revocation checker bound to this manager
   */
  public RevocationChecker getRevocationChecker() {
    return revocationChecker;
  }

  /**
   * Returns the legacy UoM coordinator used for announcements and bookkeeping.
   *
   * @return the UoM coordinator instance
   */
  public UpdateOverMandatoryManager getUpdateOverMandatory() {
    return uom;
  }

  /**
   * Returns the byte counter used to attribute UoM traffic to node statistics.
   *
   * @return the byte counter implementation backed by node stats
   */
  public ByteCounter getByteCounter() {
    return ctr;
  }

  // --- Core updater wiring ---

  /** Create and wire the package‑based {@link CoreUpdater} if not already present. */
  public synchronized void startCoreUpdater() {
    if (coreUpdater != null) return;
    int subscribeEditionSeed =
        computeCoreUpdaterSubscribeEditionSeedLocked(extractPublicKeyMaterial(updateURI));
    NodeUpdaterParams params =
        new NodeUpdaterParams(
            this,
            getCoreInfoURI(),
            Version.currentBuildNumber(),
            -1,
            Integer.MAX_VALUE,
            "core-info-",
            subscribeEditionSeed);
    coreUpdater = new CoreUpdater(params);
  }

  /**
   * Returns the current {@link CoreUpdater} instance, or {@code null} when the core updater is not
   * enabled.
   *
   * @return the current core updater or {@code null}
   */
  public synchronized CoreUpdater getCoreUpdater() {
    return coreUpdater;
  }
}
