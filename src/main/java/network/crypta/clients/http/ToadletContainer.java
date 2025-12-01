package network.crypta.clients.http;

import java.io.File;
import java.net.InetAddress;
import java.net.URI;
import network.crypta.clients.http.FProxyFetchInProgress.REFILTER_POLICY;
import network.crypta.clients.http.PageMaker.THEME;
import network.crypta.pluginmanager.FredPluginL10n;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.BucketFactory;

/**
 * Central contract for components that own and expose HTTP toadlets.
 *
 * <p>Implementations map incoming HTTP paths to {@link Toadlet} instances, inject shared UI
 * services such as theme and page maker support, and surface policy toggles that affect request
 * handling. A container typically sits directly behind the HTTP listener: it receives requests,
 * resolves the target toadlet via {@link #findToadlet(URI)}, and provides helpers for rendering
 * forms, enforcing authentication, and reporting node capabilities to callers.
 *
 * <p>Usage patterns usually involve registering toadlets at startup, optionally wiring them into a
 * navigation menu, and then invoking the various getters from request-processing threads. State is
 * expected to be long-lived and stable for the lifetime of the node; implementors should document
 * whether registration or mode changes are thread-safe and whether they can occur after the HTTP
 * server starts.
 *
 * <ul>
 *   <li>Registration: associates path prefixes with handlers and optional menu entries.
 *   <li>Presentation: exposes theme selection, page builder access, and generated form helpers.
 *   <li>Policy: reports gateway/public access settings, caching behavior, and other feature flags.
 * </ul>
 *
 * <p>See also {@link PageMaker} for templating support and {@link ToadletContext} for per-request
 * execution context.
 */
public interface ToadletContainer {

  /**
   * Register a {@link Toadlet} without adding a navigation link.
   *
   * <p>All incoming requests whose path begins with {@code urlPrefix} are routed to the supplied
   * toadlet. The registration order controls precedence when prefixes overlap; placing a toadlet at
   * the front allows it to shadow earlier registrations with the same prefix. This overload is
   * useful for programmatic endpoints or internal hooks that do not need menu exposure but still
   * need to be reachable through the HTTP surface.
   *
   * @param t the toadlet to register; must remain valid for the lifetime of the container
   * @param menu menu category key that scopes navigation; ignored when no menu entry is created
   * @param urlPrefix leading path segment (e.g., {@code /foo/bar}) used for handler resolution
   * @param atFront whether this toadlet should win over earlier matching prefixes when resolving
   * @param fullAccessOnly whether the link is hidden for reduced-permission clients; does not gate
   *     dispatching, so handlers should still validate access before serving sensitive content
   */
  void register(Toadlet t, String menu, String urlPrefix, boolean atFront, boolean fullAccessOnly);

  /**
   * Register a {@link Toadlet} and, when possible, expose it in the navigation menu.
   *
   * <p>This overload allows callers to provide localized menu metadata and a callback that
   * dynamically governs link visibility. Menu and name values may be {@code null} to suppress menu
   * creation while still routing traffic. The registration process does not duplicate toadlets or
   * mutate them; ownership and lifecycle stay with the caller. Overlapping prefixes follow the same
   * precedence rules as the simpler overload.
   *
   * @param t the toadlet to register; must safely handle concurrent requests once exposed
   * @param menu menu grouping key; {@code null} skips menu creation even when other metadata exists
   * @param urlPrefix leading path segment (e.g., {@code /foo/bar}) used for request routing
   * @param atFront whether this toadlet should be prioritized over earlier registrations
   * @param name localization key that renders the menu label when a link is created
   * @param title localization key that renders the tooltip for the link when present
   * @param fullOnly whether the menu link is visible only to clients with full access permissions
   * @param cb optional callback that can enable or hide the link based on runtime state
   */
  void register(
      Toadlet t,
      String menu,
      String urlPrefix,
      boolean atFront,
      String name,
      String title,
      boolean fullOnly,
      LinkEnabledCallback cb);

  /**
   * Register a {@link Toadlet} with menu metadata and localization support.
   *
   * <p>This variant mirrors {@link #register(Toadlet, String, String, boolean, String, String,
   * boolean, LinkEnabledCallback)} while allowing localized strings to be resolved by the caller
   * through a provided {@link FredPluginL10n}. Passing {@code null} for menu or name suppresses
   * link creation and ignores presentation arguments. Implementations may cache translations or
   * consult the callback for each render, so inputs should remain valid after registration.
   *
   * @param t the toadlet to register for the given prefix
   * @param menu menu grouping key; {@code null} disables link creation regardless of other values
   * @param urlPrefix leading path segment (e.g., {@code /foo/bar}) that this toadlet serves
   * @param atFront whether this toadlet should override earlier registrations with matching
   *     prefixes
   * @param name localization key used for the visible link text when a menu entry is shown
   * @param title localization key that supplies the link tooltip text where supported
   * @param fullOnly whether the link is shown only to users with full access permissions enabled
   * @param cb optional visibility callback consulted to decide whether the link is currently shown
   * @param l10n optional localization provider used to resolve {@code name} and {@code title}
   */
  void register(
      Toadlet t,
      String menu,
      String urlPrefix,
      boolean atFront,
      String name,
      String title,
      boolean fullOnly,
      LinkEnabledCallback cb,
      FredPluginL10n l10n);

  /**
   * Remove a previously registered toadlet and any associated navigation link metadata.
   *
   * <p>After deregistration, new requests under the toadlet's prefix will no longer be dispatched
   * to it. Implementations should be resilient when the toadlet was not registered and should avoid
   * interrupting in-flight requests that are already being served.
   *
   * @param t the toadlet to unregister; ignored when the container does not track it
   */
  void unregister(Toadlet t);

  /**
   * Find a Toadlet by URI.
   *
   * <p>Resolvers should match the longest registered prefix and may return {@code null} when no
   * toadlet is available. Implementations may perform redirects for canonicalization, and callers
   * should be prepared to reissue requests when a permanent redirect is signaled.
   *
   * @param uri absolute or server-relative URI used to locate the target toadlet
   * @return the registered toadlet for the given URI, or {@code null} when no mapping exists
   * @throws PermanentRedirectException when the URI should be replaced by a different canonical
   *     endpoint before retrying
   */
  Toadlet findToadlet(URI uri) throws PermanentRedirectException;

  /**
   * Get the theme configured for all toadlets.
   *
   * <p>The theme guides page rendering choices such as colors and typography. Callers typically
   * feed this value into {@link PageMaker} before building responses to ensure consistent
   * presentation across the UI.
   *
   * @return the configured {@link THEME} for current responses
   */
  THEME getTheme();

  /**
   * Obtain the form password that protects sensitive POST submissions.
   *
   * <p>This value is commonly embedded into hidden fields by {@link #addFormChild(HTMLNode, String,
   * String)} to mitigate cross-site or automated attacks. Implementations should return a stable
   * token for the duration of a session or node lifetime.
   *
   * @return a non-empty password string that callers must echo with privileged form submissions
   */
  String getFormPassword();

  /**
   * Determine whether the given remote address has full access rights.
   *
   * <p>Full access controls the visibility of administrative pages and queue views. Containers may
   * evaluate static ACLs, authentication state, or connection-level properties. The check is purely
   * advisory; toadlets should still verify permissions before serving sensitive resources.
   *
   * @param remoteAddr client address being evaluated; {@code null} is treated as unauthorized
   * @return {@code true} when the address is considered fully trusted, {@code false} otherwise
   */
  boolean isAllowedFullAccess(InetAddress remoteAddr);

  /**
   * Report whether the node should ask web crawlers not to index pages.
   *
   * <p>When {@code true}, toadlets can emit appropriate {@code robots} headers or meta tags to
   * discourage indexing of private or ephemeral content.
   *
   * @return {@code true} when crawler directives should block indexing
   */
  boolean doRobots();

  /**
   * Append a toadlet-aware form node to the supplied parent.
   *
   * <p>The helper constructs a form targeting the given path, injects the container's form
   * password, and returns the newly created {@link HTMLNode}. Callers can then populate inputs or
   * controls before rendering the document. Parent nodes are modified in place.
   *
   * @param parentNode HTML node that receives the new form as a child; must not be {@code null}
   * @param target path that the form submits to, relative to the toadlet container
   * @param name optional name attribute to set on the form for identification
   * @return the created {@link HTMLNode} representing the form element
   */
  HTMLNode addFormChild(HTMLNode parentNode, String target, String name);

  /**
   * Indicate whether persistent HTTP connections are allowed for served toadlets.
   *
   * <p>Persistent connections reduce handshake overhead for multiple requests but may be disabled
   * when resource usage needs to be constrained or intermediaries misbehave. Callers that stream
   * large responses or issue many small requests can check this flag to decide whether to advertise
   * keep-alive semantics or to close sockets aggressively after each exchange.
   *
   * @return {@code true} when keep-alive connections may be used
   */
  boolean enablePersistentConnections();

  /**
   * State whether inline prefetch of linked resources is permitted.
   *
   * <p>When enabled, toadlets may optimistically fetch resources referenced in a page to reduce
   * perceived latency. Callers should honor this flag before initiating speculative fetches and may
   * also throttle the number of speculative requests to avoid overwhelming constrained nodes.
   *
   * @return {@code true} when inline prefetching is enabled
   */
  boolean enableInlinePrefetch();

  /**
   * State whether extended HTTP method handling is active.
   *
   * <p>Extended handling may include support for additional verbs or relaxed parsing. Toadlets that
   * rely on non-GET/POST methods should consult this flag before advertising such capabilities and
   * may need to degrade gracefully to safer subsets when the feature is disabled.
   *
   * @return {@code true} when extended method handling is enabled
   */
  boolean enableExtendedMethodHandling();

  /**
   * State whether caching is allowed for CHK and SSK key responses.
   *
   * <p>Enabling caching lets callers reuse fetched content keyed by content hashes or signed keys.
   * Disabled caching forces fresh retrieval to reduce stale data risk. Toadlets that expose cache
   * headers or maintain local caches should synchronize their behavior with this policy flag.
   *
   * @return {@code true} when caching of CHK/SSK responses is permitted
   */
  boolean enableCachingForChkAndSskKeys();

  /**
   * Access the shared {@link BucketFactory} for creating temporary or persistent buckets.
   *
   * <p>Callers typically use the factory to stream request or response bodies without manually
   * managing files. The returned factory should be thread-safe or otherwise safe for concurrent
   * use.
   *
   * @return the bucket factory associated with this container
   */
  BucketFactory getBucketFactory();

  /**
   * Indicate whether POST requests are accepted.
   *
   * <p>Some deployments may temporarily disable POST handling during bootstrap or maintenance.
   * Callers should avoid generating POST forms when this returns {@code false} and may want to
   * redirect users toward read-only flows or explanatory status pages until POST support returns.
   *
   * @return {@code true} when POST handling is enabled
   */
  boolean allowPosts();

  /**
   * Was public-gateway mode enabled on startup? (Changing it won't take effect until restart
   * because of bookmark-related issues). If so, users with full access will still be able to
   * configure the node etc., but everyone else will not have access to the download queue or
   * anything else that might conceivably result in a DoS.
   *
   * @return {@code true} when public gateway restrictions are active for unauthenticated users
   */
  boolean publicGatewayMode();

  /**
   * State whether activelinks rendering support is enabled for outgoing pages.
   *
   * <p>When enabled, link rendering may include richer metadata or interactive behaviors. Toadlets
   * that emit HTML should respect this flag when choosing link styles, tooltips, or progressive
   * enhancements so the UI remains usable when the feature is disabled.
   *
   * @return {@code true} when activelinks support is enabled
   */
  @SuppressWarnings("BooleanMethodIsAlwaysInverted")
  boolean enableActivelinks();

  /**
   * State whether all themes are sent to the client instead of only the active one.
   *
   * <p>Sending all themes can simplify client-side theme switching at the cost of additional
   * bandwidth. Static clients may prefer to receive only the active theme, while theme pickers can
   * preload assets when this flag is {@code true} to deliver instant switches.
   *
   * @return {@code true} when all theme assets are provided to clients
   */
  boolean sendAllThemes();

  /**
   * Determine whether FProxy JavaScript helpers are enabled in generated pages.
   *
   * <p>Disabling scripts can harden pages for highly restricted environments but may remove
   * progressive enhancements or live status updates. Toadlets that rely on client-side behavior
   * should degrade gracefully or emit compatibility warnings when scripts are disabled.
   *
   * @return {@code true} when JavaScript support is allowed in FProxy pages
   */
  boolean isFProxyJavascriptEnabled();

  /**
   * Determine whether FProxy server push or WebSocket-style features are enabled.
   *
   * <p>When disabled, pages should fall back to polling or static updates to avoid relying on push
   * channels. Implementations can also use this signal to avoid allocating long-lived connections
   * when the operator prefers strictly request/response traffic.
   *
   * @return {@code true} when push-style updates are permitted
   */
  boolean isFProxyWebPushingEnabled();

  /**
   * Indicate whether progress pages are disabled for downloads or other long-running operations.
   *
   * <p>Containers may suppress progress pages in kiosk or embedded modes where minimal output is
   * desired. Toadlets that would normally stream progress should check this flag and emit succinct
   * completion messages or status codes instead of interactive progress dashboards.
   *
   * @return {@code true} when progress pages are suppressed
   */
  boolean disableProgressPage();

  /**
   * Obtain the page maker used to build HTML responses.
   *
   * <p>Callers can reuse the returned {@link PageMaker} to assemble pages consistent with the
   * container's theme, localization, and layout conventions. The page maker may also embed common
   * headers, navigation scaffolding, and security tokens so downstream code can focus on content.
   *
   * @return the shared {@link PageMaker} instance
   */
  PageMaker getPageMaker();

  /**
   * Report whether advanced mode is currently enabled.
   *
   * <p>Advanced mode typically unlocks expert options or verbose diagnostics intended for trusted
   * users. UI components can read this flag to conditionally render advanced controls and to avoid
   * surprising novice users with experimental features when the mode is off.
   *
   * @return {@code true} when advanced mode features should be shown
   */
  boolean isAdvancedModeEnabled();

  /**
   * Enable or disable advanced mode.
   *
   * <p>Implementations should persist the chosen state and notify interested components as needed.
   * Callers are expected to gate privileged UI elements on this value rather than direct authority
   * checks. Changing this flag may have immediate UI effects, so consumers should re-render any
   * cached views after toggling.
   *
   * @param enabled {@code true} to expose advanced mode features; {@code false} to hide them
   */
  void setAdvancedMode(boolean enabled);

  /**
   * Report whether the FProxy setup wizard has been completed.
   *
   * <p>Toadlets may use this to decide whether to reroute users to onboarding flows or to surface
   * reminders about incomplete configuration. The result should remain stable across requests until
   * the wizard runs to completion.
   *
   * @return {@code true} when the initial wizard has already run to completion
   */
  boolean fproxyHasCompletedWizard();

  /**
   * What to do when we find cached data on the global queue, but it's already been filtered, and we
   * want a filtered copy.
   *
   * @return the refilter policy governing how cached filtered content is handled
   */
  REFILTER_POLICY getReFilterPolicy();

  /**
   * Retrieve a file that overrides defaults for this container.
   *
   * <p>Implementations may use this file to supply custom configuration or branding assets. The
   * file may be absent when default settings are in effect, so callers should handle {@code null}
   * defensively.
   *
   * @return override file path, or {@code null} when no override is configured
   */
  File getOverrideFile();

  /**
   * Get the base URL that external clients should use to reach this container.
   *
   * <p>The URL typically includes protocol and host information and may reflect current SSL
   * settings or public gateway mode. This value is suitable for constructing absolute links in
   * email notifications or redirects.
   *
   * @return a canonical URL string for the container
   */
  String getURL();

  /**
   * Get a base URL using an explicit host instead of the auto-detected one.
   *
   * <p>This is useful when constructing links for virtual hosting scenarios or behind proxies where
   * the externally visible host differs from the local listener. Implementations should preserve
   * the container's current scheme and port when composing the URL.
   *
   * @param host hostname to embed in the returned URL; must be a valid host token
   * @return a URL string that points to this container using the supplied host
   */
  String getURL(String host);

  /**
   * Determine whether the container is serving content over HTTPS.
   *
   * <p>Toadlets can use this information to decide whether to emit secure-only links or additional
   * transport guidance.
   *
   * @return {@code true} when HTTPS is active for this container
   */
  boolean isSSL();

  /**
   * Create a container-scoped unique identifier suitable for {@link ToadletContext} instances.
   *
   * <p>IDs should be unique for the lifetime of the container and may be used for correlation or
   * logging. Implementations should avoid expensive generation paths because this method may be
   * called for every incoming request.
   *
   * @return a monotonically unique identifier for contextual correlation
   */
  long generateUniqueID();
}
