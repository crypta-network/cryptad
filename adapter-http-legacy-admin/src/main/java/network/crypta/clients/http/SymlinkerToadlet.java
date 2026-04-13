package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.l10n.NodeL10n;
import network.crypta.runtime.spi.ToadletSymlinkEntry;
import network.crypta.runtime.spi.ToadletSymlinkPort;
import network.crypta.support.api.HTTPRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Toadlet that resolves short alias paths to other toadlet URLs via HTTP redirects.
 *
 * <p>This toadlet keeps a synchronized in-memory map of aliases and redirects any request whose
 * path starts with a known alias to the mapped target. It bootstraps from persisted configuration
 * and can persist later edits on demand. Synchronization on the internal {@link Map} keeps link
 * updates and lookups thread-safe. Callers typically create one instance per node, let it load its
 * persisted aliases through the runtime SPI, and rely on {@link #handleMethodGET(URI, HTTPRequest,
 * ToadletContext)} to perform the resolution work.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Maintaining alias-to-target mappings loaded from persisted configuration values.
 *   <li>Adding and removing aliases while optionally persisting the updated map.
 *   <li>Resolving incoming requests and issuing redirects or localized 404 responses.
 * </ul>
 *
 * <p>Instances are not immutable: callers should avoid external iteration over the alias map and
 * rely on this class to coordinate updates. Redirect semantics preserve the original query string
 * and fragment while replacing only the matched path prefix.
 */
public class SymlinkerToadlet extends Toadlet {
  private static final Logger LOG = LoggerFactory.getLogger(SymlinkerToadlet.class);

  private final HashMap<String, String> linkMap = new HashMap<>();
  private final ToadletSymlinkPort symlinkPort;

  /**
   * Creates a new symlinker toadlet backed by detached symlink persistence.
   *
   * <p>The constructor loads the current configured alias mappings through the provided runtime
   * port and populates the in-memory map. Construction is not thread-safe, but further alias access
   * is synchronized on the internal map.
   *
   * @param symlinkPort runtime port supplying a configuration-backed alias load and persistence.
   */
  public SymlinkerToadlet(ToadletSymlinkPort symlinkPort) {
    super();
    this.symlinkPort = Objects.requireNonNull(symlinkPort, "symlinkPort");
    for (ToadletSymlinkEntry entry : symlinkPort.loadConfiguredSymlinks()) {
      addLink(entry.alias(), entry.target(), false);
    }
  }

  /**
   * Inserts or updates an alias mapping in memory and optionally persists it to disk.
   *
   * <p>The method acquires a monitor on the alias map, updates the mapping for {@code alias} to the
   * provided {@code target}, and logs the operation. When {@code store} is {@code true}, the full
   * current alias list is persisted through the runtime port before releasing the map monitor so
   * persisted state follows the same mutation order as the in-memory alias map. No validation or
   * normalization of path components is performed; callers should pass canonical prefixes,
   * including trailing slashes, to avoid ambiguous matches. The boolean return indicates whether
   * the previous mapping value was identical to the alias string before replacement.
   *
   * @param alias request path prefix to match; typically starts and ends with a slash.
   * @param target destination prefix that replaces the alias in constructed redirect paths.
   * @param store whether to trigger immediate persistence of the modified alias map.
   * @return {@code true} if the prior mapping value equaled the alias before being overwritten.
   */
  public boolean addLink(String alias, String target, boolean store) {
    boolean ret;
    synchronized (linkMap) {
      ret = alias.equals(linkMap.put(alias, target));
      LOG.info("Adding link: {} => {}", alias, target);
      if (store) {
        symlinkPort.persistConfiguredSymlinks(snapshotEntries());
      }
    }
    return ret;
  }

  /**
   * Removes an existing alias mapping and optionally persists the change.
   *
   * <p>The method synchronizes on the alias map, deletes the mapping for {@code alias} when
   * present, and logs the removal together with the previous target. No validation is performed on
   * the alias format, and requesting persistence stores the remaining full alias list through the
   * runtime port before releasing the map monitor so the persisted state follows in-memory mutation
   * order. Calls are idempotent with respect to non-existent aliases and return a boolean to signal
   * whether removal occurred.
   *
   * @param alias path prefix identifying the mapping to delete from the symlinker.
   * @param store whether to trigger configuration persistence after the removal attempt.
   * @return {@code true} when a mapping existed and was removed; {@code false} otherwise.
   */
  public boolean removeLink(String alias, boolean store) {
    boolean ret;
    synchronized (linkMap) {
      Object o;
      ret = (o = linkMap.remove(alias)) != null;

      LOG.info("Removing link: {} => {}", alias, o);
      if (store) {
        symlinkPort.persistConfiguredSymlinks(snapshotEntries());
      }
    }
    return ret;
  }

  private List<ToadletSymlinkEntry> snapshotEntries() {
    List<ToadletSymlinkEntry> entries = new ArrayList<>(linkMap.size());
    for (Map.Entry<String, String> entry : linkMap.entrySet()) {
      entries.add(new ToadletSymlinkEntry(entry.getKey(), entry.getValue()));
    }
    return List.copyOf(entries);
  }

  /**
   * Handles GET requests by resolving configured aliases and issuing redirects or 404 responses.
   *
   * <p>The handler scans all registered aliases for a prefix match against the request path,
   * choosing the last encountered match when multiple aliases overlap. When a mapping is found, it
   * rewrites the path by replacing the alias with its target while preserving the original query
   * string and fragment, then throws a {@link RedirectException} to redirect the client. If the
   * path does not match any alias, the method writes a localized 404 response. URI syntax errors
   * during redirect construction are logged and returned to the caller as an HTML body.
   *
   * @param uri incoming request URI whose path is inspected for alias prefixes.
   * @param request HTTP request wrapper; currently unused but provided for interface compatibility.
   * @param ctx toadlet context used for writing replies or signaling redirect responses.
   * @throws ToadletContextClosedException when the context is already closed before replying.
   * @throws IOException if writing a response fails due to I/O problems in the context.
   * @throws RedirectException when a matching alias is found and the client should be redirected.
   */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    String path = uri.getPath();
    String foundtarget = null;
    String foundkey = null;
    synchronized (linkMap) {
      for (Map.Entry<String, String> entry : linkMap.entrySet()) {
        String key = entry.getKey();
        if (path.startsWith(key)) {
          foundkey = key;
          foundtarget = entry.getValue();
        }
      }
    }

    if (foundtarget == null) {
      writeTextReply(
          ctx, 404, "Not found", NodeL10n.getBase().getString("StaticToadlet.pathNotFound"));
      return;
    }

    path = foundtarget + path.substring(foundkey.length());
    URI outuri;
    try {
      outuri = new URI(null, null, path, uri.getQuery(), uri.getFragment());
    } catch (URISyntaxException e) {
      LOG.warn("Failed to create redirect URI for path {}", path, e);
      writeHTMLReply(ctx, 200, "OK", e.getMessage());
      return;
    }

    throw new RedirectException(outuri);
  }

  /**
   * Returns the base path under which this toadlet serves alias resolution requests.
   *
   * <p>The path is a fixed string {@code "/sl/"}; callers typically mount this toadlet at that
   * location so that child paths such as {@code /sl/search/} can be redirected. The value is stable
   * across process restarts and does not depend on configuration, making it suitable for wiring in
   * the node's HTTP toadlet registry or in tests that assert routing behavior.
   *
   * @return constant base path string {@code "/sl/"} used to register the toadlet.
   */
  @Override
  public String path() {
    return "/sl/";
  }
}
