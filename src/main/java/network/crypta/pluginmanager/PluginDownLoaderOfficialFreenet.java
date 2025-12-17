package network.crypta.pluginmanager;

import network.crypta.client.HighLevelSimpleClient;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.pluginmanager.OfficialPlugins.OfficialPluginDescription;

/**
 * Downloads plugins that are listed in Crypta's built-in "official plugins" catalog.
 *
 * <p>This downloader is intended for the common case where a user supplies a plugin identifier
 * (typically a short plugin name) and expects the node to resolve that name to a stable,
 * authenticated {@link FreenetURI}. Resolution is performed against {@link OfficialPlugins} via the
 * node's {@code PluginManager}. If the catalog entry already includes a concrete URI, that URI is
 * used directly. Otherwise, the downloader derives a USK-based URI rooted at the node updater's
 * base URI, applying the plugin name as the document name and the catalog's recommended version as
 * the suggested edition.
 *
 * <p>Instances are lightweight and carry no mutable state beyond the references inherited from
 * {@link PluginDownLoaderFreenet}. Thread-safety therefore follows the thread-safety of the
 * provided {@link Node} and {@link HighLevelSimpleClient}: callers should treat this downloader as
 * not intrinsically synchronized and avoid sharing it across threads unless the surrounding plugin
 * download flow is already safe to share.
 *
 * <ul>
 *   <li><b>Responsibility:</b> Validate that the requested plugin is in the official list and
 *       compute its source URI.
 *   <li><b>Failure mode:</b> Reject unknown names early with {@link PluginNotFoundException}.
 *   <li><b>Retry behavior:</b> Provides a retry downloader that forces the "desperate" mode.
 * </ul>
 *
 * @see PluginDownLoaderFreenet
 * @see OfficialPlugins
 */
public class PluginDownLoaderOfficialFreenet extends PluginDownLoaderFreenet {

  /**
   * Creates an official-plugin downloader bound to a specific node and client.
   *
   * <p>This constructor is typically called by the plugin manager when it needs to resolve and
   * fetch an official plugin. The {@code desperate} flag is forwarded to {@link
   * PluginDownLoaderFreenet} and is used as a policy input for how aggressively the download flow
   * should retry or relax constraints. Construction itself performs no network I/O and does not
   * validate the {@code client} or {@code node} beyond storing references.
   *
   * @param client high-level client used for fetching plugin content; must not be {@code null}
   * @param node node instance used to access the plugin catalog and updater URIs; must not be
   *     {@code null}
   * @param desperate whether to enable more aggressive retry behavior in the superclass policy
   */
  public PluginDownLoaderOfficialFreenet(
      HighLevelSimpleClient client, Node node, boolean desperate) {
    super(client, node, desperate);
  }

  /**
   * Resolves an official plugin name to a concrete source {@link FreenetURI}.
   *
   * <p>The input is interpreted as a plugin identifier understood by the official plugin list. If
   * the plugin is not present in that list, this method fails fast and does not attempt any
   * fallback name resolution. For catalog entries that provide an explicit URI, the URI is returned
   * unchanged. Otherwise, the URI is derived from the node updater's base URI by setting the
   * document name to {@code source}, applying the catalog's recommended version as the suggested
   * edition, and converting the resulting USK to the corresponding SSK.
   *
   * @param source plugin identifier to resolve via the official plugins list; must not be {@code
   *     null}
   * @return resolved URI for the official plugin source, suitable for subsequent download steps
   * @throws PluginNotFoundException if {@code source} is not present in the official plugins list
   */
  @Override
  public FreenetURI checkSource(String source) throws PluginNotFoundException {
    OfficialPluginDescription desc = node.getPluginManager().getOfficialPlugin(source);
    if (desc == null)
      throw new PluginNotFoundException("Not in the official plugins list: " + source);
    if (desc.uri != null) return desc.uri;
    else {
      return node.getNodeUpdater()
          .getURI()
          .setDocName(source)
          .setSuggestedEdition(desc.recommendedVersion)
          .sskForUSK();
    }
  }

  @Override
  String getPluginName(String source) {
    return source + ".jar";
  }

  /**
   * Indicates that this downloader is restricted to "official plugin" sources.
   *
   * <p>This flag allows higher-level code to distinguish between downloaders that accept arbitrary
   * user-supplied URIs and downloaders that only resolve names through the curated official plugin
   * catalog. Callers may use this information to tailor UI messaging, apply stricter safety checks,
   * or decide whether a missing plugin should be treated as a configuration error versus a
   * retriable network failure.
   *
   * @return {@code true}, as this downloader only targets the official plugins list
   */
  @Override
  public boolean isOfficialPluginLoader() {
    return true;
  }

  /**
   * Creates a new downloader instance to be used after a failed attempt.
   *
   * <p>The retry downloader shares the same {@link HighLevelSimpleClient} and {@link Node}
   * references as this instance, but forces {@code desperate=true}. This provides a simple,
   * explicit policy escalation mechanism while keeping each downloader instance immutable from the
   * perspective of callers.
   *
   * @return a new downloader configured for retry behavior using the same node and client
   */
  @Override
  public PluginDownLoader<FreenetURI> getRetryDownloader() {
    return new PluginDownLoaderOfficialFreenet(hlsc, node, true);
  }
}
