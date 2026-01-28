package network.crypta.pluginmanager;

import static java.util.Collections.unmodifiableCollection;

import java.net.MalformedURLException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import network.crypta.keys.FreenetURI;
import network.crypta.node.updater.NodeUpdater;
import network.crypta.node.updater.PluginJarUpdater;

/**
 * Catalog of Crypta’s official plugins.
 *
 * <p>This class defines the set of "official" plugins that the node knows how to fetch and load.
 * Each plugin entry describes where the plugin JAR is obtained from (typically a CHK), which
 * versions are considered acceptable or recommended, and whether the plugin should be treated as
 * essential or optional.
 *
 * <p>Instances are expected to be constructed during initialization and then used as a read-only
 * lookup table via {@link #get(String)} and {@link #getAll()}. The underlying map is populated
 * during construction; once construction completes, the contents are stable unless modified by code
 * within this class. The class is not designed for concurrent mutation, but concurrent reads after
 * construction are safe.
 *
 * <p><b>Responsibilities</b>
 *
 * <ul>
 *   <li>Define the curated set of official plugin names and groups.
 *   <li>Associate each plugin with a {@link FreenetURI} and version constraints.
 *   <li>Expose a lightweight lookup API for {@link PluginManager} and UI code.
 * </ul>
 *
 * <p>Connectivity-related essential plugins should not have their minimum version raised lightly,
 * because doing so can prevent a node from starting when it can only retrieve an older copy of the
 * plugin.
 *
 * @see <a href="https://bugs.freenetproject.org/view.php?id=6600">bug 6600</a>
 * @author <a href="mailto:bombe@pterodactylus.net">David ‘Bombe’ Roden</a>
 */
public class OfficialPlugins {

  private static final String GROUP_COMMUNICATION = "communication";
  private static final String GROUP_CONNECTIVITY = "connectivity";
  private static final String GROUP_EXAMPLE = "example";
  private static final String GROUP_INDEX = "index";

  private final Map<String, OfficialPluginDescription> pluginDescriptionsByName = new HashMap<>();

  /**
   * Creates and registers the built-in catalog of official plugins.
   *
   * <p>The constructor populates an internal mapping from plugin name to {@link
   * OfficialPluginDescription}. Each entry includes the plugin group, any version recommendations
   * or minimum requirements, and the {@link FreenetURI} used to fetch the plugin. The set of
   * entries is intentionally fixed at runtime; callers should treat the resulting instance as
   * immutable.
   *
   * <p>This constructor performs basic URI parsing and will fail fast if a configured URI is not
   * syntactically valid. No network I/O is performed here; fetching and update behavior is handled
   * elsewhere by {@link PluginManager} and the updater components.
   *
   * @throws IllegalStateException if any configured plugin URI cannot be parsed
   */
  public OfficialPlugins() {
    try {
      addPlugin("Freemail_wot")
          .inGroup(GROUP_COMMUNICATION)
          .recommendedVersion(33)
          .minimumVersion(33)
          .loadedFrom(
              "CHK@tiJ82TPsevVA~nR6hEio0udD8uUWkKekXc6Te1ZXVyE,MAzxlZKewcRLIQNxU4StPLd4FBCr-WqF2ob-JMQTsWk,AAMC--8/plugin-Freemail.jar");
      addPlugin("HelloWorld")
          .inGroup(GROUP_EXAMPLE)
          .loadedFrom(
              "CHK@r3SXUzFR-CjBjck0ZxoZ9mIUzGhSMq6Ap471njwvhAU,V0cQ6eJcCf-~XTwLvtgC2klbUx8CWFZoELM2RmEjSJo,AAMC--8/plugin-HelloWorld.jar")
          .advanced();
      addPlugin("HelloFCP")
          .inGroup(GROUP_EXAMPLE)
          .loadedFrom(
              "CHK@TVN2Pwh38cfeX8Xb7G2mOmZvTcSQpcv~GoxA-bzoi8g,L92mdF-6rHbbTR5B2UQxrWNueS1uhNeUhr719C2qAio,AAMC--8/plugin-HelloFCP.jar")
          .advanced();
      addPlugin("JSTUN")
          .inGroup(GROUP_CONNECTIVITY)
          .advanced()
          .essential()
          .minimumVersion(5)
          .loadedFrom(
              "CHK@9TYUQq88pCfcE9a6BTJEhgu-Kst6jPjSSFlxEUCIUmo,SO5CoHh1TUMcYl7ME9EAVDKFGMV0w~gyAWBg0yZyZ3E,AAMC--8/plugin-JSTUN.jar");
      addPlugin("KeyUtils")
          .inGroup("technical")
          .minimumVersion(5028)
          .loadedFrom(
              "CHK@FswKA4IQRwjn5UMBd6SSfw8h4qeDRyWk~Nr-e4HnpdA,v1YsbEH8NlEzFW98JJoqRYNxyJ1uc9LE~hrPtvRWgfg,AAMC--8/plugin-KeyUtils.jar");
      addPlugin("KeepAlive")
          .inGroup("file-transfer")
          .loadedFrom(
              "CHK@p9qusTcmgT0W6u-GuL8b~BJ846cydrR0MimhOLeFB6o,JCH3UHhAlElmQ0ZaPJ7LYmAJc296XYkBP6vJeUJxqgA,AAMC--8/plugin-KeepAlive.jar");
      addPlugin("MDNSDiscovery")
          .advanced()
          .inGroup(GROUP_CONNECTIVITY)
          .minimumVersion(2)
          .loadedFrom(
              "CHK@11MwFXjQ3dX-Zh2mro7ot4VmmVPTzAxd88Y20C34408,TqWKMDGQora6hAcyD0YaDqcs2jHbqW2~fIPTyTBkIFU,AAMC--8/plugin-MDNSDiscovery.jar");
      addPlugin("SNMP")
          .inGroup(GROUP_CONNECTIVITY)
          .loadedFrom(
              "CHK@-VwuHVl18yqNkg1oBadqBw2faIiVFK1baBr7NIayzqs,DE3RdtpqAURIaR8v40yInbdhhtvsdHwpKUBHqMMxQIo,AAMC--8/plugin-SNMP.jar")
          .advanced();
      addPlugin("TestGallery")
          .inGroup(GROUP_EXAMPLE)
          .minimumVersion(1)
          .loadedFrom(
              "CHK@I5F4pW5rb7oK3Sq6uqM4OJxrl1nCXMv5UO3Q8cSG3EE,m2lXEdTixDCje5-mKHDqIBIl6vOfnx~l4elOd3bq0-Q,AAMC--8/plugin-TestGallery.jar")
          .experimental();
      addPlugin("ThawIndexBrowser")
          .inGroup("file-transfer")
          .advanced()
          .minimumVersion(6)
          .usesXml()
          .loadedFrom(
              "CHK@3Cguz5zFcgzuyu2IN5Rmam-fOb3sJCuAJOv7x8QRBn0,nw0nroxCfLQ94dwtftp-D-LvGKb8JAh4pxMUCqyTV74,AAMC--8/plugin-ThawIndexBrowser.jar");
      addPlugin("UPnP")
          .inGroup(GROUP_CONNECTIVITY)
          .essential()
          .advanced()
          .recommendedVersion(10007)
          .minimumVersion(10007)
          .loadedFrom(
              "CHK@aAcwBVfIl0ZhfXM289LJnipQngeTj05dQoRV6hsqR18,N0dyMHuyffY6xV2i7nO-3OG9jD6zlTgXTf2BuMVJtrQ,AAMC--8/plugin-UPnP.jar");
      addPlugin("UPnP2")
          .inGroup(GROUP_CONNECTIVITY)
          .recommendedVersion(5)
          .minimumVersion(5)
          .loadedFrom(
              "CHK@1AakXeknLKlKC5fEJgjX4NmNInIUdr15slX~T7qWdR0,2Z1VEQvjuv6iqHzfV~T4fvzDIuX-kCIGqiKgT3JUSnk,AAMC--8/plugin-UPnP2.jar");
      addPlugin("Freereader")
          .inGroup(GROUP_INDEX)
          .minimumVersion(6)
          .usesXml()
          .loadedFrom(
              "CHK@y~OUrYyU7lCp1UKqtK~c4ZxHC9zmk~xroxBEfKLlLNk,~NPUN68DS9cqfmNgxXHpEvsPoMC76Lhlhdkd6BrGams,AAMC--8/plugin-Freereader.jar");
      addPlugin("Library")
          .inGroup(GROUP_INDEX)
          .recommendedVersion(37)
          .minimumVersion(37)
          .usesXml()
          .loadedFrom(
              "CHK@MFMLow-EKU3qT4c6dV7YZlJ1db14TXkOxpc3or-LjeM,yJpydVx60ukVzWUBkVOFrN6WZgsVq7ZL5gS0uyRlKP8,AAMC--8/plugin-Library.jar")
          .advanced();
      addPlugin("Spider")
          .inGroup(GROUP_INDEX)
          .minimumVersion(53)
          .loadedFrom(
              "CHK@tiXhymMLqCBpA6t1Y-tPYcXjCc9Y8HQdirH4AAW-upQ,eIJi3yIU7hqF9MOwgGg1zgMSgyCmVPheFV0dWkLz8cA,AAMC--8/plugin-Spider.jar")
          .advanced();
      addPlugin("WebOfTrust")
          .inGroup(GROUP_COMMUNICATION)
          .minimumVersion(20)
          .recommendedVersion(20)
          .usesXml()
          .loadedFrom(
              "CHK@Aw29eDc00olujGi5kwIdsGO-ainGvoI0ao9H40z~cnw,BXYfYGArqO4ShvSUeBsYLyT1EZeUEkGCoZ6~KgIzprs,AAMC--8/plugin-WebOfTrust.jar");
      addPlugin("FlogHelper")
          .inGroup(GROUP_COMMUNICATION)
          .minimumVersion(36)
          .usesXml()
          .loadedFrom(
              "CHK@XThgqfDiUIe6UpepWcDi8M~cFzNjDS-vSrbUc9LbKaA,t1N1tWQcbb9M305be7PUY2UbPKiyz~9Qpdk6PCoObQA,AAMC--8/plugin-FlogHelper.jar");
      addPlugin("Sharesite")
          .inGroup(GROUP_COMMUNICATION)
          .recommendedVersion(7)
          .minimumVersion(7)
          .loadedFrom(
              "CHK@RJg2u4MBeCCzM35eKU8-QrT88z7ys9oN0rx1xuG97uc,n5PHGnEXjh-LryUiA~gEtZ675O797PzTQQkK8d6LbOI,AAMC--8/plugin-sharesite.jar");
    } catch (MalformedURLException mue1) {
      throw new IllegalStateException("Could not create FreenetURI.", mue1);
    }
  }

  private OfficialPluginBuilder addPlugin(String name) {
    return new OfficialPluginBuilder(name);
  }

  /**
   * Looks up the official plugin descriptor for a given plugin name.
   *
   * <p>This is a simple map lookup against the catalog created at construction time. The returned
   * {@link OfficialPluginDescription} instance is the canonical descriptor stored in this catalog
   * and should be treated as immutable.
   *
   * <p>If the requested plugin name is not present, this method returns {@code null}. Callers that
   * require a strict guarantee should handle the {@code null} case explicitly.
   *
   * @param name the plugin's canonical internal name; must match a catalog entry exactly
   * @return the matching descriptor, or {@code null} when the plugin is not in this catalog
   */
  public OfficialPluginDescription get(String name) {
    return pluginDescriptionsByName.get(name);
  }

  /**
   * Returns a read-only view of all official plugin descriptors in this catalog.
   *
   * <p>The returned collection is unmodifiable and is backed by the internal map. As a result, it
   * reflects the catalog contents as of the time of access. Since this class only mutates the map
   * during construction, the returned view is effectively stable for the lifetime of the instance.
   *
   * <p>The iteration order is the map's value-collection order and is not specified as a stable API
   * contract; callers should not rely on a particular ordering.
   *
   * @return an unmodifiable view of all {@link OfficialPluginDescription} values
   */
  public Collection<OfficialPluginDescription> getAll() {
    return unmodifiableCollection(pluginDescriptionsByName.values());
  }

  private class OfficialPluginBuilder {

    private final String name;
    private String group;
    private boolean essential;
    private long minimumVersion = -1;
    private long recommendedVersion = -1;

    /**
     * @see OfficialPluginDescription#alwaysFetchLatestVersion
     */
    private boolean alwaysFetchLatestVersion;

    private boolean usesXml;

    /**
     * @see OfficialPluginDescription#uri
     */
    private FreenetURI uri;

    private boolean deprecated;
    private boolean experimental;
    private boolean advanced;
    private boolean unsupported;

    private OfficialPluginBuilder(String name) {
      this.name = name;
      addCurrentPluginDescription();
    }

    public OfficialPluginBuilder inGroup(String group) {
      this.group = group;
      addCurrentPluginDescription();
      return this;
    }

    public OfficialPluginBuilder essential() {
      essential = true;
      addCurrentPluginDescription();
      return this;
    }

    public OfficialPluginBuilder minimumVersion(int minimumVersion) {
      this.minimumVersion = minimumVersion;
      addCurrentPluginDescription();
      return this;
    }

    public OfficialPluginBuilder recommendedVersion(int recommendedVersion) {
      this.recommendedVersion = recommendedVersion;
      addCurrentPluginDescription();
      return this;
    }

    /**
     * Configures the plugin to re-fetch its JAR at startup even when cached locally.
     *
     * <p>This is intended for USK-based plugin distribution where the plugin is not updated via the
     * main update mechanism. See {@link OfficialPluginDescription#alwaysFetchLatestVersion} for the
     * behavioral details and trade-offs.
     *
     * @see OfficialPluginDescription#alwaysFetchLatestVersion
     */
    @SuppressWarnings("unused")
    public OfficialPluginBuilder alwaysFetchLatestVersion() {
      this.alwaysFetchLatestVersion = true;
      addCurrentPluginDescription();
      return this;
    }

    public OfficialPluginBuilder usesXml() {
      usesXml = true;
      addCurrentPluginDescription();
      return this;
    }

    /**
     * Sets the source URI for the plugin JAR.
     *
     * <p>Please read {@link OfficialPluginDescription#uri} before deciding whether to use a USK or
     * CHK, as it affects update behavior and how quickly new versions are observed.
     *
     * @param uri the Freenet URI string identifying the plugin content to fetch
     * @return this builder for fluent configuration calls
     * @throws MalformedURLException if the provided URI string is not valid
     */
    public OfficialPluginBuilder loadedFrom(String uri) throws MalformedURLException {
      this.uri = new FreenetURI(uri);
      addCurrentPluginDescription();
      return this;
    }

    @SuppressWarnings("unused")
    public OfficialPluginBuilder deprecated() {
      deprecated = true;
      addCurrentPluginDescription();
      return this;
    }

    @SuppressWarnings("UnusedReturnValue")
    public OfficialPluginBuilder experimental() {
      experimental = true;
      addCurrentPluginDescription();
      return this;
    }

    public OfficialPluginBuilder advanced() {
      advanced = true;
      addCurrentPluginDescription();
      return this;
    }

    @SuppressWarnings("unused")
    public OfficialPluginBuilder unsupported() {
      unsupported = true;
      addCurrentPluginDescription();
      return this;
    }

    private void addCurrentPluginDescription() {
      if (recommendedVersion == 0 && minimumVersion > 0) recommendedVersion = minimumVersion;
      if (minimumVersion == 0 && recommendedVersion > 0) minimumVersion = recommendedVersion;
      pluginDescriptionsByName.put(name, createOfficialPluginDescription());
    }

    private OfficialPluginDescription createOfficialPluginDescription() {
      return new OfficialPluginDescription(
          new OfficialPluginDefinition(name, group, uri),
          new OfficialPluginVersionPolicy(
              minimumVersion, recommendedVersion, alwaysFetchLatestVersion),
          new OfficialPluginFlags(
              essential, usesXml, deprecated, experimental, advanced, unsupported));
    }
  }

  public record OfficialPluginDefinition(String name, String group, FreenetURI uri) {}

  public record OfficialPluginVersionPolicy(
      long minimumVersion, long recommendedVersion, boolean alwaysFetchLatestVersion) {}

  public record OfficialPluginFlags(
      boolean essential,
      boolean usesXml,
      boolean deprecated,
      boolean experimental,
      boolean advanced,
      boolean unsupported) {}

  /**
   * Descriptor for an official plugin known to the node.
   *
   * <p>This type captures the metadata that {@link PluginManager} uses to decide how and when to
   * fetch a plugin JAR, whether loading is allowed based on version constraints, and how the entry
   * should be presented to users. The descriptor is a simple data holder: fields are {@code public}
   * and {@code final}, and callers should treat instances as immutable.
   *
   * <p>Version fields refer to the plugin-reported version (often exposed as a "real version" in
   * plugin metadata). A minimum version is a hard requirement that prevents loading older copies. A
   * recommended version is used to trigger background update behavior. When {@link
   * #alwaysFetchLatestVersion} is enabled and {@link #uri} points to a USK, the constructor forces
   * a "latest edition" fetch by setting a negative suggested edition.
   *
   * <p><b>Notable behaviors</b>
   *
   * <ul>
   *   <li>Entries may be essential, which can cause startup-time fetching when missing.
   *   <li>Update behavior depends on whether the plugin is tracked by the main update USK.
   *   <li>Visibility can be gated by flags such as {@link #advanced} and {@link #unsupported}.
   * </ul>
   *
   * @see PluginJarUpdater
   * @see PluginManager
   */
  public static class OfficialPluginDescription {

    /**
     * The canonical internal name of the plugin.
     *
     * <p>This value is used as the lookup key in {@link OfficialPlugins} and is also used for
     * localization keys (for example, {@code pluginDesc.<name>}). It should be treated as a stable
     * identifier rather than display text.
     */
    public final String name;

    /**
     * The technical group identifier for the plugin.
     *
     * <p>This value is not intended to be shown directly. It is a stable key that can be translated
     * or mapped to UI categories by {@link PluginManager} and related presentation code.
     */
    public final String group;

    /**
     * Whether this plugin is considered essential for core node functionality.
     *
     * <p>When {@code true}, the node may attempt to fetch the plugin during startup when it is not
     * already available locally (subject to configuration that may forbid HTTP). When {@code
     * false}, fetching can be deferred until after startup and performed asynchronously.
     */
    public final boolean essential;

    /**
     * Minimum accepted plugin-reported version.
     *
     * <p>If the plugin is older than this value, loading is rejected. The catalog may use a
     * negative value to indicate that no explicit minimum was configured.
     */
    public final long minimumVersion;

    /**
     * Recommended plugin-reported version.
     *
     * <p>If the currently available plugin is older than this value, the node may download a newer
     * version in the background. Applying the updated JAR typically happens on restart or by
     * offering the user an explicit reload action. This behavior is conceptually similar to a
     * USK-based update, but the specific update trigger depends on the plugin's distribution path.
     */
    public final long recommendedVersion;

    /**
     * Whether startup should ignore any cached local JAR and re-fetch the plugin.
     *
     * <p>When this flag is {@code true} and a cached plugin JAR already exists on disk, {@link
     * PluginManager} will ignore the cached file during startup and download the plugin again. This
     * is primarily intended for plugins that are fetched from a USK {@link #uri} but are not
     * included in the main update USK monitored by {@link PluginJarUpdater}.
     *
     * <p>For plugins distributed via the main update USK, setting this is usually unnecessary
     * because {@link PluginJarUpdater} will observe and apply updates. For plugins, which are not
     * tracked by the main update, USK re-fetching at startup can be the only automatic opportunity
     * to observe a newly inserted USK edition.
     */
    public final boolean alwaysFetchLatestVersion;

    /**
     * Whether the plugin uses XML processing.
     *
     * <p>Consumers can use this flag to apply additional safety checks or policy decisions before
     * loading plugins that rely on XML functionality.
     */
    public final boolean usesXML;

    /**
     * Location to fetch the plugin JAR from, typically a CHK.
     *
     * <p>Official plugin updates are normally deployed via the main update USK used by {@link
     * NodeUpdater} and monitored by {@link PluginJarUpdater}. For that workflow, this URI usually
     * points at a content-hash key (CHK) for the current version.
     *
     * <p>To allow updates without granting write access to the main update USK, this URI can be a
     * USK. When using a USK, updates are only discovered at certain points in time:
     *
     * <ul>
     *   <li>When the plugin is manually unloaded and loaded again.
     *   <li>At restart when {@link #alwaysFetchLatestVersion} is {@code true}; if it is {@code
     *       false}, a cached local JAR can prevent observing new editions.
     * </ul>
     *
     * <p>Because USK-based updates can be less timely than the main update mechanism, CHKs are
     * generally preferred for official distribution. A typical reason to still use a USK here is to
     * allow individual plugin developers to publish testing versions without giving them
     * write-access to the main update USK.
     */
    public final FreenetURI uri;

    /**
     * Whether this plugin is marked as deprecated in the catalog.
     *
     * <p>A deprecated plugin is considered obsolete and may be hidden or discouraged from normal
     * use, depending on UI and policy decisions in {@link PluginManager}.
     */
    public final boolean deprecated;

    /**
     * Whether this plugin is marked as experimental in the catalog.
     *
     * <p>Experimental plugins may be exposed only in appropriate UI modes and may be treated as
     * less stable than non-experimental entries.
     */
    public final boolean experimental;

    /**
     * Whether this plugin should be shown only in "advanced" views.
     *
     * <p>Advanced plugins are not deprecated and not necessarily experimental, but they are
     * intended for experienced users and may be hidden in simplified UI modes.
     */
    public final boolean advanced;

    /**
     * Whether this plugin is no longer supported as part of the official set.
     *
     * <p>Unsupported plugins are treated as removed from the official catalog. They are expected to
     * be hidden from normal UI flows, including advanced views.
     */
    public final boolean unsupported;

    OfficialPluginDescription(
        OfficialPluginDefinition definition,
        OfficialPluginVersionPolicy versionPolicy,
        OfficialPluginFlags flags) {

      this.name = definition.name();
      this.group = definition.group();
      this.essential = flags.essential();
      this.minimumVersion = versionPolicy.minimumVersion();
      this.recommendedVersion = versionPolicy.recommendedVersion();
      this.alwaysFetchLatestVersion = versionPolicy.alwaysFetchLatestVersion();
      this.usesXML = flags.usesXml();
      this.deprecated = flags.deprecated();
      this.experimental = flags.experimental();
      this.advanced = flags.advanced();
      this.unsupported = flags.unsupported();

      FreenetURI resolvedUri = definition.uri();
      if (this.alwaysFetchLatestVersion && resolvedUri != null) {
        assert resolvedUri.isUSK() : "Non-USK URIs do not support updates!";

        // Force fetching the latest edition by setting a negative USK edition.
        long edition = resolvedUri.getSuggestedEdition();
        if (edition >= 0) {
          edition = Math.min(-1, -edition);
        }
        resolvedUri = resolvedUri.setSuggestedEdition(edition);
      }

      this.uri = resolvedUri;
    }

    /**
     * Returns the localized display name for this plugin.
     *
     * <p>The returned text is resolved via {@link PluginManager}'s localization mechanisms. The
     * specific language and fallback behavior depend on the node's localization configuration and
     * the available translation resources.
     *
     * <p>This method performs no I/O and does not cache: it delegates directly to {@link
     * PluginManager} each time it is called.
     *
     * @return the localized display name for this plugin entry
     */
    public String getLocalisedPluginName() {
      return PluginManager.getOfficialPluginLocalisedName(name);
    }

    /**
     * Returns the localized description for this plugin.
     *
     * <p>The returned text is resolved via {@link PluginManager}'s localization mechanisms using a
     * key of the form {@code pluginDesc.<name>}. The specific language and fallback behavior depend
     * on the node's localization configuration and the available translation resources.
     *
     * <p>This method performs no I/O and does not cache: it delegates directly to {@link
     * PluginManager} each time it is called.
     *
     * @return the localized description text for this plugin entry
     */
    public String getLocalisedPluginDescription() {
      return PluginManager.l10n("pluginDesc." + name);
    }
  }
}
