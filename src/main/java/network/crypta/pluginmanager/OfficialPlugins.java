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
 * Container for Freenet’s official plugins.
 *
 * <p>FIXME: Connectivity essential plugins shouldn't have their minimum version increased!
 *
 * @see https://bugs.freenetproject.org/view.php?id=6600
 * @author <a href="mailto:bombe@pterodactylus.net">David ‘Bombe’ Roden</a>
 */
public class OfficialPlugins {

  private final Map<String, OfficialPluginDescription> officialPlugins = new HashMap<>();

  public OfficialPlugins() {
    try {
      addPlugin("Freemail_wot")
          .inGroup("communication")
          .recommendedVersion(33)
          .minimumVersion(33)
          .loadedFrom(
              "CHK@tiJ82TPsevVA~nR6hEio0udD8uUWkKekXc6Te1ZXVyE,MAzxlZKewcRLIQNxU4StPLd4FBCr-WqF2ob-JMQTsWk,AAMC--8/plugin-Freemail.jar");
      addPlugin("HelloWorld")
          .inGroup("example")
          .loadedFrom(
              "CHK@r3SXUzFR-CjBjck0ZxoZ9mIUzGhSMq6Ap471njwvhAU,V0cQ6eJcCf-~XTwLvtgC2klbUx8CWFZoELM2RmEjSJo,AAMC--8/plugin-HelloWorld.jar")
          .advanced();
      addPlugin("HelloFCP")
          .inGroup("example")
          .loadedFrom(
              "CHK@TVN2Pwh38cfeX8Xb7G2mOmZvTcSQpcv~GoxA-bzoi8g,L92mdF-6rHbbTR5B2UQxrWNueS1uhNeUhr719C2qAio,AAMC--8/plugin-HelloFCP.jar")
          .advanced();
      addPlugin("JSTUN")
          .inGroup("connectivity")
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
          .inGroup("connectivity")
          .minimumVersion(2)
          .loadedFrom(
              "CHK@11MwFXjQ3dX-Zh2mro7ot4VmmVPTzAxd88Y20C34408,TqWKMDGQora6hAcyD0YaDqcs2jHbqW2~fIPTyTBkIFU,AAMC--8/plugin-MDNSDiscovery.jar");
      addPlugin("SNMP")
          .inGroup("connectivity")
          .loadedFrom(
              "CHK@-VwuHVl18yqNkg1oBadqBw2faIiVFK1baBr7NIayzqs,DE3RdtpqAURIaR8v40yInbdhhtvsdHwpKUBHqMMxQIo,AAMC--8/plugin-SNMP.jar")
          .advanced();
      addPlugin("TestGallery")
          .inGroup("example")
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
          .inGroup("connectivity")
          .essential()
          .advanced()
          .recommendedVersion(10007)
          .minimumVersion(10007)
          .loadedFrom(
              "CHK@aAcwBVfIl0ZhfXM289LJnipQngeTj05dQoRV6hsqR18,N0dyMHuyffY6xV2i7nO-3OG9jD6zlTgXTf2BuMVJtrQ,AAMC--8/plugin-UPnP.jar");
      addPlugin("UPnP2")
          .inGroup("connectivity")
          .recommendedVersion(5)
          .minimumVersion(5)
          .loadedFrom(
              "CHK@1AakXeknLKlKC5fEJgjX4NmNInIUdr15slX~T7qWdR0,2Z1VEQvjuv6iqHzfV~T4fvzDIuX-kCIGqiKgT3JUSnk,AAMC--8/plugin-UPnP2.jar");
      addPlugin("Freereader")
          .inGroup("index")
          .minimumVersion(6)
          .usesXml()
          .loadedFrom(
              "CHK@y~OUrYyU7lCp1UKqtK~c4ZxHC9zmk~xroxBEfKLlLNk,~NPUN68DS9cqfmNgxXHpEvsPoMC76Lhlhdkd6BrGams,AAMC--8/plugin-Freereader.jar");
      addPlugin("Library")
          .inGroup("index")
          .recommendedVersion(37)
          .minimumVersion(37)
          .usesXml()
          .loadedFrom(
              "CHK@MFMLow-EKU3qT4c6dV7YZlJ1db14TXkOxpc3or-LjeM,yJpydVx60ukVzWUBkVOFrN6WZgsVq7ZL5gS0uyRlKP8,AAMC--8/plugin-Library.jar")
          .advanced();
      addPlugin("Spider")
          .inGroup("index")
          .minimumVersion(53)
          .loadedFrom(
              "CHK@tiXhymMLqCBpA6t1Y-tPYcXjCc9Y8HQdirH4AAW-upQ,eIJi3yIU7hqF9MOwgGg1zgMSgyCmVPheFV0dWkLz8cA,AAMC--8/plugin-Spider.jar")
          .advanced();
      addPlugin("WebOfTrust")
          .inGroup("communication")
          .minimumVersion(20)
          .recommendedVersion(20)
          .usesXml()
          .loadedFrom(
              "CHK@Aw29eDc00olujGi5kwIdsGO-ainGvoI0ao9H40z~cnw,BXYfYGArqO4ShvSUeBsYLyT1EZeUEkGCoZ6~KgIzprs,AAMC--8/plugin-WebOfTrust.jar");
      addPlugin("FlogHelper")
          .inGroup("communication")
          .minimumVersion(36)
          .usesXml()
          .loadedFrom(
              "CHK@XThgqfDiUIe6UpepWcDi8M~cFzNjDS-vSrbUc9LbKaA,t1N1tWQcbb9M305be7PUY2UbPKiyz~9Qpdk6PCoObQA,AAMC--8/plugin-FlogHelper.jar");
      addPlugin("Sharesite")
          .inGroup("communication")
          .recommendedVersion(7)
          .minimumVersion(7)
          .loadedFrom(
              "CHK@RJg2u4MBeCCzM35eKU8-QrT88z7ys9oN0rx1xuG97uc,n5PHGnEXjh-LryUiA~gEtZ675O797PzTQQkK8d6LbOI,AAMC--8/plugin-sharesite.jar");
    } catch (MalformedURLException mue1) {
      throw new RuntimeException("Could not create FreenetURI.", mue1);
    }
  }

  private OfficialPluginBuilder addPlugin(String name) {
    return new OfficialPluginBuilder(name);
  }

  public OfficialPluginDescription get(String name) {
    return officialPlugins.get(name);
  }

  public Collection<OfficialPluginDescription> getAll() {
    return unmodifiableCollection(officialPlugins.values());
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
     * @see OfficialPluginDescription#alwaysFetchLatestVersion
     */
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
     * ATTENTION: Please read {@link OfficialPluginDescription#uri} before deciding whether to use
     * USK or CHK!
     */
    public OfficialPluginBuilder loadedFrom(String uri) throws MalformedURLException {
      this.uri = new FreenetURI(uri);
      addCurrentPluginDescription();
      return this;
    }

    public OfficialPluginBuilder deprecated() {
      deprecated = true;
      addCurrentPluginDescription();
      return this;
    }

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

    public OfficialPluginBuilder unsupported() {
      unsupported = true;
      addCurrentPluginDescription();
      return this;
    }

    private void addCurrentPluginDescription() {
      if (recommendedVersion == 0 && minimumVersion > 0) recommendedVersion = minimumVersion;
      if (minimumVersion == 0 && recommendedVersion > 0) minimumVersion = recommendedVersion;
      officialPlugins.put(name, createOfficialPluginDescription());
    }

    private OfficialPluginDescription createOfficialPluginDescription() {
      return new OfficialPluginDescription(
          name,
          group,
          essential,
          minimumVersion,
          recommendedVersion,
          alwaysFetchLatestVersion,
          usesXml,
          uri,
          deprecated,
          experimental,
          advanced,
          unsupported);
    }
  }

  public static class OfficialPluginDescription {

    /** The name of the plugin */
    public final String name;

    /**
     * The group of the plugin. The group is a technical name that needs to be translated before it
     * is shown to the user.
     */
    public final String group;

    /**
     * If true, we will download it, blocking, over HTTP, during startup (unless explicitly
     * forbidden to use HTTP). If not, we will download it on a separate thread after startup. Both
     * are assuming we don't have it in a file.
     */
    public final boolean essential;

    /** Minimum getRealVersion(). If the plugin is older than this, we will fail the load. */
    public final long minimumVersion;

    /**
     * Recommended getRealVersion(). If the plugin is older than this, we will download the new
     * version in the background, and either use it on restart, or offer the user the option to
     * reload it. This is in fact identical to what happens on a USK-based update...
     */
    public final long recommendedVersion;

    /**
     * If true, if during startup we already have a copy of the plugin JAR on disk, the {@link
     * PluginManager} will ignore it and redownload the JAR instead so the user gets a recent
     * version if there is one.<br>
     * <br>
     * This is for being used together with plugins which are fetched from a USK {@link #uri}, and
     * which are not included in the official main Freenet update USK which {@link PluginJarUpdater}
     * watches.<br>
     * For plugins which are in the main Freenet update USK, setting this to true is usually not
     * necessary: The {@link PluginJarUpdater} will update the plugin if there is a new version.<br>
     * <br>
     * In other words: Plugins which are NOT in the official USK but have their own USK will not
     * have the {@link PluginJarUpdater} monitor their USK, it only monitors the main USK. Thus, the
     * only chance to update them is during startup by ignoring the JAR and causing a re-download of
     * it.
     */
    public final boolean alwaysFetchLatestVersion;

    /** Does it use XML? If so, if the JVM is vulnerable, then don't load it */
    public final boolean usesXML;

    /**
     * FreenetURI to get the latest version from.<br>
     * Typically a CHK, not USK, since updates are deployed using the main Freenet USK of {@link
     * NodeUpdater}'s subclass {@link PluginJarUpdater}.<br>
     * <br>
     * To allow people to insert plugin updates without giving them write access to the main USK,
     * this *can* be an USK, but updating when a new version is inserted to the USK will only happen
     * at certain points in time:<br>
     * - if the plugin is manually unloaded and loaded again.<br>
     * - at restart of Freenet if {@link #alwaysFetchLatestVersion} is true. If it is false, the
     * cached local JAR file on disk will prevent updating!<br>
     * So to make updating work using USK, set {@link #alwaysFetchLatestVersion} so we check for
     * updates when the node is restarted.<br>
     * <br>
     * NOTICE the conclusion of the above: It is NOT RECOMMENDED to use USKs here: Updates will only
     * be delivered at restarts of the node, while the main Freenet USK supports live updates; and
     * also there is no revocation mechanism for the USKs. Instead of using USKs here, a CHK should
     * be preferred, and new plugin versions then should be inserted at the main Freenet update USK
     * of the the {@link NodeUpdater}. A typical usecase for nevertheless using an USK here is to
     * allow individual plugin developers to push testing versions of their plugin on their own
     * without giving them write-access to the main Freenet update USK.
     */
    public final FreenetURI uri;

    /** If true, the plugin is obsolete. */
    public final boolean deprecated;

    /** If true, the plugin is experimental. */
    public final boolean experimental;

    /**
     * If true, the plugin is geeky - it should not be shown except in advanced mode even though
     * it's not deprecated nor is it experimental.
     */
    public final boolean advanced;

    /**
     * If true, the plugin used to be official, but is no longer supported. These are not shown even
     * in advanced mode.
     */
    public final boolean unsupported;

    OfficialPluginDescription(
        String name,
        String group,
        boolean essential,
        long minVer,
        long recVer,
        boolean alwaysFetchLatestVersion,
        boolean usesXML,
        FreenetURI uri,
        boolean deprecated,
        boolean experimental,
        boolean advanced,
        boolean unsupported) {

      this.name = name;
      this.group = group;
      this.essential = essential;
      this.minimumVersion = minVer;
      this.recommendedVersion = recVer;
      this.alwaysFetchLatestVersion = alwaysFetchLatestVersion;
      this.usesXML = usesXML;
      this.deprecated = deprecated;
      this.experimental = experimental;
      this.advanced = advanced;
      this.unsupported = unsupported;

      if (alwaysFetchLatestVersion && uri != null) {
        assert (uri.isUSK()) : "Non-USK URIs do not support updates!";

        // Force fetching the latest edition by setting a negative USK edition.
        long edition = uri.getSuggestedEdition();
        if (edition >= 0) {
          edition = Math.min(-1, -edition);
        }
        uri = uri.setSuggestedEdition(edition);
      }

      this.uri = uri;
    }

    public String getLocalisedPluginName() {
      return PluginManager.getOfficialPluginLocalisedName(name);
    }

    public String getLocalisedPluginDescription() {
      return PluginManager.l10n("pluginDesc." + name);
    }
  }
}
