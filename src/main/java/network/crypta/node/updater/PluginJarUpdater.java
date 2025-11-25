package network.crypta.node.updater;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import network.crypta.client.FetchResult;
import network.crypta.clients.http.PproxyToadlet;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.RequestClient;
import network.crypta.node.Version;
import network.crypta.node.useralerts.AbstractUserAlert;
import network.crypta.node.useralerts.AbstractUserAlert.Body;
import network.crypta.node.useralerts.AbstractUserAlert.DismissOptions;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.pluginmanager.PluginInfoWrapper;
import network.crypta.pluginmanager.PluginManager;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.BucketTools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates discovery and deployment of updated plugin JARs.
 *
 * <p>This updater is responsible for evaluating fetched update artifacts for a single plugin,
 * presenting a user-facing alert when a newer version is available, and, once permitted, writing
 * the new JAR to disk and restarting the plugin. It builds on {@link NodeUpdater} for retrieval and
 * manifest parsing and integrates with {@link PluginManager} and the alert system to ensure a
 * controlled rollout.
 *
 * <p>Typical usage is indirect via {@link NodeUpdateManager}: when an updated plugin version is
 * detected, an alert is registered. The user can trigger immediate deployment or request that the
 * updater deploy on the next successful revocation check. Writing the JAR is synchronized to avoid
 * concurrent modifications, and deployment proceeds only if the plugin is still wanted and the
 * running node satisfies any minimum version declared in the manifest.
 *
 * <ul>
 *   <li>Manages life cycle: fetch → evaluate → alert → deploy.
 *   <li>Applies a simple gating model around revocation checks before unloading/reloading.
 *   <li>Ensures on-disk JAR content is durable by syncing the file descriptor after writes.
 * </ul>
 *
 * <p>Thread safety: deployment flags and alert state are updated under {@code synchronized} blocks,
 * and JAR writes are guarded by a dedicated monitor to prevent interleaving writes.
 */
public class PluginJarUpdater extends NodeUpdater {
  private static final Logger LOG = LoggerFactory.getLogger(PluginJarUpdater.class);

  private static final String DEPLOYING_PREFIX = "Deploying ";
  private static final String INPUT = "input";
  private static final String VALUE = "value";
  private static final String FAILED_DELETE_TEMP_BLOB = "Failed to delete temp blob {}";
  private static final String L10N_PREFIX = "PluginJarUpdater.";

  final String pluginName;
  final PluginManager pluginManager;
  private UserAlert alert;
  private boolean deployOnNoRevocation;
  private boolean deployOnNextNoRevocation;
  private boolean readyToDeploy;
  private FetchResult result;

  private final Object writeJarSync = new Object();

  /**
   * @return True if the caller should restart the revocation checker.
   */
  boolean onNoRevocation() {
    synchronized (this) {
      if (!readyToDeploy) return false;
      if (deployOnNextNoRevocation) {
        deployOnNoRevocation = true;
        deployOnNextNoRevocation = false;
        LOG.info("{}{} after next revocation check", DEPLOYING_PREFIX, pluginName);
        return true;
      }
      if (!deployOnNoRevocation) return false;
    }
    // Deploy it!
    if (!pluginManager.isPluginLoaded(pluginName)) {
      LOG.error("Plugin is not loaded, so not deploying: {}", pluginName);
      deleteTempBlobQuietly();
      return false;
    }
    LOG.info("Deploying new version of {} : unloading old version...", pluginName);
    // Write the new version of the plugin before shutting down, so if there is a deadlock in
    // terminate, we will still get the new version after a restart.
    try {
      writeJar();
    } catch (IOException e) {
      LOG.error("Cannot deploy", e);
      LOG.error("Cannot deploy new version of {}", pluginName);
      return false; // Not much we can do ...
    }
    pluginManager.killPluginByFilename(pluginName, Integer.MAX_VALUE, true);
    pluginManager.startPluginAuto(pluginName, true);
    UserAlert a;
    synchronized (this) {
      a = alert;
      alert = null;
    }
    if (a != null) node.getClientCore().getAlerts().unregister(a);
    return false;
  }

  PluginJarUpdater(
      NodeUpdateManager manager,
      FreenetURI updateUri,
      int current,
      int min,
      int max,
      String blobFilenamePrefix,
      String pluginName,
      PluginManager pm,
      boolean autoDeployOnRestart) {
    super(manager, updateUri, current, min, max, blobFilenamePrefix);
    this.pluginName = pluginName;
    this.pluginManager = pm;
    if (LOG.isDebugEnabled()) {
      LOG.debug("AutoDeployOnRestart flag present: {}", autoDeployOnRestart);
    }
  }

  /**
   * Return the logical artifact name handled by this updater.
   *
   * <p>The value corresponds to the plugin identifier and is used for log messages, alert
   * summaries, and deriving the on-disk destination via the {@link PluginManager}. Callers should
   * treat the returned string as opaque and stable for the lifetime of the updater instance.
   *
   * @return a non-null plugin identifier representing the artifact being updated
   */
  @Override
  public String artifactName() {
    return pluginName;
  }

  private int requiredNodeVersion;

  private static final String REQUIRED_NODE_VERSION_PREFIX = "Required-Node-Version: ";

  /**
   * Parse and evaluate the manifest of the fetched artifact when available.
   *
   * <p>The implementation prefers parsing from the provided {@code result} so that compatibility
   * checks (such as required node version) run even when the temporary blob cannot yet be renamed
   * into its finalized form on disk. If the result is {@code null} or empty, it falls back to
   * parsing from the finalized blob. Any discovered constraints are recorded for later gating.
   *
   * @param result the fetch result for the current build, or {@code null} when unavailable; a
   *     non-empty result allows in-memory manifest parsing without relying on disk
   * @param build the fetched build number being considered during this update cycle
   */
  @Override
  protected void maybeParseManifest(FetchResult result, int build) {
    requiredNodeVersion = -1;
    // Prefer parsing from the fresh FetchResult so compatibility checks run even when the
    // temporary blob cannot be renamed to the finalized .fblob on disk.
    if (result != null && result.size() > 0) {
      parseManifest(result);
    } else {
      // Fallback to the finalized blob if result is unexpectedly empty.
      parseManifest();
    }
    if (requiredNodeVersion != -1) {
      LOG.info("Required node version for plugin {}: {}", pluginName, requiredNodeVersion);
    }
  }

  /**
   * Handle a single manifest line relevant to plugin compatibility.
   *
   * <p>Currently recognizes lines that begin with {@code "Required-Node-Version: "} and captures
   * the integer value that follows. Unrecognized lines are ignored so that unrelated manifest keys
   * can evolve without impacting updater behavior.
   *
   * @param line a raw manifest line, including key and value; must not be {@code null}
   */
  @Override
  protected void parseManifestLine(String line) {
    if (line.startsWith(REQUIRED_NODE_VERSION_PREFIX)) {
      requiredNodeVersion = Integer.parseInt(line.substring(REQUIRED_NODE_VERSION_PREFIX.length()));
    }
  }

  /**
   * Hook invoked when an update fetch starts for this plugin.
   *
   * <p>Used for diagnostics and progress reporting only. No state transitions are performed here;
   * the method provides a consistent point to record that retrieval has begun.
   */
  @Override
  protected void onStartFetching() {
    LOG.info("Starting to fetch plugin {}", pluginName);
  }

  /**
   * Process a successfully fetched plugin artifact and, when appropriate, raise an update alert.
   *
   * <p>The method enforces compatibility against any {@code Required-Node-Version} constraint in
   * the manifest, releases any previous fetch result, and determines whether the plugin is still
   * desired and actually newer than the loaded version. If and only if a newer version is wanted,
   * it marks the updater ready to deploy and registers a user alert to offer deployment.
   *
   * @param build the fetched build number associated with this result
   * @param result the successful fetch result containing the new plugin content; must not be {@code
   *     null}
   * @param blob the finalized on-disk blob file for the artifact; may be used for fallbacks and
   *     logging and may be {@code null} when not applicable
   */
  @Override
  protected void processSuccess(int build, FetchResult result, File blob) {
    Bucket oldResult = null;
    synchronized (this) {
      if (requiredNodeVersion > Version.currentBuildNumber()) {
        LOG.warn(
            "Found version {} of {} but needs node version {}",
            fetchedVersion,
            pluginName,
            requiredNodeVersion);
        deleteTempBlobQuietly();
        return;
      }
      if (this.result != null) oldResult = this.result.asBucket();
      this.result = result;
    }
    if (oldResult != null) {
      //noinspection EmptyTryBlock
      try (Bucket ignored = oldResult) {
        // release previous result bucket
      }
    }

    PluginInfoWrapper loaded = pluginManager.findPluginByIdentifier(pluginName);

    if (loaded == null && !node.getPluginManager().isPluginLoadedOrLoadingOrWantLoad(pluginName)) {
      LOG.error("Don't want plugin: {}", pluginName);
      deleteTempBlobQuietly();
      return;
    }

    if (loaded != null && loaded.getPluginLongVersion() >= fetchedVersion) {
      deleteTempBlobQuietly();
      return;
    }
    // Create an useralert to ask the user to deploy the new version.
    UserAlert toRegister;
    synchronized (this) {
      readyToDeploy = true;
      if (alert != null) return;
      toRegister = alert = createUpdateAlert();
    }
    node.getClientCore().getAlerts().register(toRegister);
  }

  private void deleteTempBlobQuietly() {
    try {
      if (tempBlobFile != null) Files.deleteIfExists(tempBlobFile.toPath());
    } catch (IOException ex) {
      LOG.warn(FAILED_DELETE_TEMP_BLOB, tempBlobFile, ex);
    }
  }

  private UserAlert createUpdateAlert() {
    return new AbstractUserAlert(
        true,
        l10nName("pluginUpdatedTitle", pluginName),
        Body.of(
            l10nName("pluginUpdatedText", pluginName),
            l10nName("pluginUpdatedShortText", pluginName),
            null),
        UserAlert.ERROR,
        true,
        new DismissOptions(NodeL10n.getBase().getString("UserAlert.hide"), true)) {

      @Override
      public void onDismiss() {
        synchronized (PluginJarUpdater.this) {
          alert = null;
        }
      }

      @Override
      public HTMLNode getHTMLText() {
        HTMLNode div = new HTMLNode("div");
        synchronized (PluginJarUpdater.this) {
          if (deployOnNoRevocation || deployOnNextNoRevocation) {
            div.addChild("#", l10nName("willDeployAfterRevocationCheck", pluginName));
          } else {
            div.addChild("#", l10nPluginUpdatedText(pluginName, fetchedVersion));

            HTMLNode formNode =
                div.addChild(
                    "form",
                    new String[] {"action", "method"},
                    new String[] {PproxyToadlet.PLUGINS_PATH, "post"});
            formNode.addChild(
                INPUT,
                new String[] {"type", "name", VALUE},
                new String[] {"hidden", "formPassword", node.getClientCore().getFormPassword()});
            formNode.addChild(
                INPUT,
                new String[] {"type", "name", VALUE},
                new String[] {"hidden", "update", pluginName});
            formNode.addChild(
                INPUT, new String[] {"type", VALUE}, new String[] {"submit", l10nUpdatePlugin()});
          }
        }
        return div;
      }
    };
  }

  private String l10nUpdatePlugin() {
    return NodeL10n.getBase().getString(L10N_PREFIX + "updatePlugin");
  }

  private String l10nName(String key, String value) {
    return NodeL10n.getBase().getString(L10N_PREFIX + key, "name", value);
  }

  private String l10nPluginUpdatedText(String pluginName, long fetchedVersion) {
    return NodeL10n.getBase()
        .getString(
            L10N_PREFIX + "pluginUpdatedText",
            new String[] {"name", "newVersion"},
            new String[] {pluginName, Long.toString(fetchedVersion)});
  }

  /**
   * Write the fetched plugin artifact to the destination JAR file.
   *
   * <p>The method performs a best-effort deletion of any existing file, then copies the content of
   * {@code result} to {@code fNew}. The write is serialized using an internal monitor and followed
   * by {@code FileDescriptor#sync()} to reduce the chance of partial updates after a crash or power
   * loss. The method does not alter plugin state; callers typically invoke it immediately before
   * unloading and restarting the plugin.
   *
   * @param result the successful fetch result supplying the new plugin bytes; must not be {@code
   *     null} and should remain valid for the duration of the copy operation
   * @param fNew the absolute or relative path of the target JAR file to replace; the parent
   *     directory must exist and be writable by the running process
   * @throws IOException if deleting the existing file, opening the output stream, or copying bytes
   *     fails for any reason, including insufficient permissions or a full filesystem
   */
  public void writeJarTo(FetchResult result, File fNew) throws IOException {
    synchronized (writeJarSync) {
      try {
        boolean deleted = Files.deleteIfExists(fNew.toPath());
        if (!deleted && fNew.exists()) {
          LOG.warn("Can't delete {}!", fNew);
        }
      } catch (IOException ex) {
        LOG.warn("Can't delete {}!", fNew, ex);
      }

      try (FileOutputStream fos = new FileOutputStream(fNew)) {
        BucketTools.copyTo(result.asBucket(), fos, -1);
        fos.getFD().sync();
      }
    }
    if (LOG.isInfoEnabled()) LOG.info("Written {} to {}", artifactName(), fNew);
  }

  void writeJar() throws IOException {
    writeJarTo(result, pluginManager.getPluginFilename(pluginName));
    UserAlert a;
    synchronized (this) {
      a = alert;
      alert = null;
    }
    if (a != null) node.getClientCore().getAlerts().unregister(a);
  }

  @Override
  void kill() {
    super.kill();
    UserAlert a;
    synchronized (this) {
      a = alert;
      alert = null;
    }
    if (a != null) node.getClientCore().getAlerts().unregister(a);
  }

  /**
   * Arm deferred deployment for the next revocation check cycle.
   *
   * <p>When the plugin was already running, deployment is deferred by one additional successful
   * revocation check to minimize churn in busy systems. Otherwise, it is scheduled for the very
   * next successful check. This call only sets intent; the actual write and restart occur later in
   * {@link #onNoRevocation()} when the gate condition is met.
   *
   * @param wasRunning {@code true} when the plugin was running at arm time, in which case the
   *     update deploys after the next but one revocation check; {@code false} schedules deployment
   *     after the next successful check
   */
  public synchronized void arm(boolean wasRunning) {
    if (wasRunning) {
      deployOnNextNoRevocation = true;
      LOG.info("{}{} after next but one revocation check", DEPLOYING_PREFIX, pluginName);
    } else {
      deployOnNoRevocation = true;
      LOG.info("{}{} after next revocation check", DEPLOYING_PREFIX, pluginName);
    }
  }

  /** {@inheritDoc} */
  @Override
  public RequestClient getRequestClient() {
    return pluginManager.getSingleUpdaterRequestClient();
  }
}
