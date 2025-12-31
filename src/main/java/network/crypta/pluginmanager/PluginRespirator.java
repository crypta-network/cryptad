package network.crypta.pluginmanager;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.UUID;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.filter.FilterCallback;
import network.crypta.client.filter.GenericReadFilterCallback;
import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.clients.fcp.FCPPluginConnection;
import network.crypta.clients.fcp.FCPPluginMessage;
import network.crypta.clients.http.PageMaker;
import network.crypta.clients.http.SessionManager;
import network.crypta.clients.http.ToadletContainer;
import network.crypta.config.SubConfig;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestStarter;
import network.crypta.support.HTMLNode;
import network.crypta.support.URIPreEncoder;
import network.crypta.support.plugins.helpers1.WebInterfaceToadlet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides a plugin-facing façade for common node services.
 *
 * <p>A {@code PluginRespirator} is handed to plugins by the plugin manager so they can interact
 * with the running node without reaching directly into internal wiring. It bundles access to
 * higher-level client operations (fetch/insert via {@link HighLevelSimpleClient}), HTTP/UI helpers
 * (toadlets, pages, and sessions), plugin-to-plugin messaging via FCP, and persistence facilities
 * via {@link PluginStore}.
 *
 * <p>The instance is tied to a specific node and plugin. Most accessors return shared services
 * owned by the node; they do not imply ownership transfer and must not be closed by the plugin.
 * Methods that touch persistence or shared registries are synchronized to keep state consistent
 * when called concurrently from different plugin threads.
 *
 * <ul>
 *   <li><b>Client helpers</b>: exposes a preconfigured {@link HighLevelSimpleClient} for typical
 *       interactive operations.
 *   <li><b>Web integration</b>: provides access to the node HTTP container and helpers to build
 *       authenticated forms.
 *   <li><b>Inter-plugin FCP</b>: establishes and looks up intra-node FCP connections for message
 *       exchange.
 * </ul>
 *
 * @see PluginManager
 * @see NodeClientCore
 * @see HighLevelSimpleClient
 */
public class PluginRespirator {
  private static final Logger LOG = LoggerFactory.getLogger(PluginRespirator.class);
  private static final ArrayList<SessionManager> sessionManagers = new ArrayList<>(4);

  /**
   * For accessing Freenet: simple fetches and inserts, and the data you need (FetchContext etc.) to
   * start more complex ones.
   */
  private final HighLevelSimpleClient hlsc;

  /** For accessing the node. */
  private final Node node;

  private final FredPlugin plugin;
  private final PluginInfoWrapper pi;
  private final PluginStores stores;

  private PluginStore store;

  /**
   * Creates a respirator bound to the given node and plugin wrapper.
   *
   * <p>The created instance exposes stable access points into the node for the plugin represented
   * by {@code pi}. The {@link HighLevelSimpleClient} returned by {@link #getHLSimpleClient()} is
   * created with interactive priority to match typical UI-triggered operations. The respirator also
   * wires access to shared plugin stores through the node client core.
   *
   * @param node the running node providing services; must not be {@code null}.
   * @param pi the plugin wrapper that owns configuration and metadata; must not be {@code null}.
   */
  public PluginRespirator(Node node, PluginInfoWrapper pi) {
    this.node = node;
    this.hlsc =
        node.getClientCore().makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, false, false);
    this.plugin = pi.getPlugin();
    this.pi = pi;
    stores = node.getClientCore().getPluginStores();
  }

  /**
   * Returns a preconfigured high-level client for common fetch/insert operations.
   *
   * <p>The returned client is owned by the node and is intended for typical plugin use cases such
   * as simple fetches, simple inserts, and obtaining the supporting contexts for more complex
   * operations. It is configured for interactive priority and is safe to keep for the lifetime of
   * the plugin.
   *
   * @return a non-null {@link HighLevelSimpleClient} instance owned by the node.
   */
  public HighLevelSimpleClient getHLSimpleClient() {
    return hlsc;
  }

  /**
   * Returns the underlying node instance.
   *
   * <p>This accessor is intended for advanced plugins that need lower-level access beyond the
   * convenience methods provided by this class, such as reading node configuration or interacting
   * with subsystems not directly exposed here. Callers must treat the returned object as shared,
   * node-owned state.
   *
   * @return the node associated with this respirator; never {@code null}.
   */
  public Node getNode() {
    return node;
  }

  /**
   * Create a GenericReadFilterCallback, which will filter URLs in exactly the same way as the node
   * does when filtering a page.
   *
   * <p>The callback is created with the same filter configuration used by the node HTTP layer. The
   * base URI is URI-encoded before it is passed into the filter subsystem. If the URI cannot be
   * encoded, this method fails fast with an {@link AssertionError} because callers typically pass
   * stable, internally constructed paths.
   *
   * @param path the base URI for the page being filtered; not necessarily a Freenet URI string.
   * @return a new {@link FilterCallback} configured like the node's page filtering.
   * @throws AssertionError if {@code path} cannot be URI-encoded for use by the filter subsystem.
   */
  public FilterCallback makeFilterCallback(String path) {
    try {
      ToadletContainer container = getToadletContainer();
      LinkFilterExceptionProvider provider =
          container instanceof LinkFilterExceptionProvider linkProvider ? linkProvider : null;
      return new GenericReadFilterCallback(URIPreEncoder.encodeURI(path), null, null, provider);
    } catch (URISyntaxException e) {
      throw new AssertionError("Invalid filter callback path: " + path, e);
    }
  }

  /**
   * Returns the {@link PageMaker} used by the node HTTP UI, if available.
   *
   * <p>This is a convenience wrapper around {@link #getToadletContainer()}: if the node does not
   * have an HTTP container (for example due to configuration or startup state), this method returns
   * {@code null}. Callers should handle a {@code null} result by disabling UI integration or
   * deferring registration until HTTP is available.
   *
   * @return the node {@link PageMaker}, or {@code null} if HTTP is not available.
   */
  public PageMaker getPageMaker() {
    ToadletContainer container = getToadletContainer();
    if (container == null) return null;
    return container.getPageMaker();
  }

  /**
   * Add a valid form including the {@link NodeClientCore#getFormPassword() formPassword}. See the
   * Javadoc there for an explanation of the purpose of this mechanism.
   *
   * <p><b>ATTENTION</b>: It is critically important to validate the form password when processing
   * requests which "change the server state". Other words for this would be requests which change
   * your database or "write" requests. Requests which only read values from the server don't have
   * to validate the form password.
   *
   * <p>To validate that the right password was received, use {@code
   * WebInterfaceToadlet.isFormPassword(HTTPRequest)} from within a {@link WebInterfaceToadlet}
   * subclass.
   *
   * @param parentNode the parent {@link HTMLNode} to which the form element is appended.
   * @param target the form action URL/target to post to, as expected by the node HTTP layer.
   * @param name the form id/name attribute used to identify the form in the DOM.
   * @return the newly created form {@link HTMLNode}, including the form password field.
   */
  public HTMLNode addFormChild(HTMLNode parentNode, String target, String name) {
    HTMLNode formNode =
        parentNode.addChild(
            "form",
            new String[] {"action", "method", "enctype", "id", "name", "accept-charset"},
            new String[] {target, "post", "multipart/form-data", name, name, "utf-8"});
    formNode.addChild(
        "input",
        new String[] {"type", "name", "value"},
        new String[] {"hidden", "formPassword", node.getClientCore().getFormPassword()});

    return formNode;
  }

  /**
   * Creates an intra-node FCP client connection to another plugin.
   *
   * <p><i>NOTICE: This API is a rewrite of the whole code for plugin communication. It was added
   * 2015-03, and for some time after that may change in ways which break backward compatibility.
   * Thus, any suggestions or pull requests for improvement of all involved interfaces and classes
   * are welcome!<br>
   * </i><br>
   *
   * <p>Creates an FCP client connection with another plugin which is an FCP server (= which
   * implements interface {@link FredPluginFCPMessageHandler.ServerSideFCPMessageHandler}).<br>
   * Currently, the remote plugin must run in the same node, but the fact that FCP is used lays
   * foundation for a future implementation to allow you to connect to other plugins by network, no
   * matter where they are running.
   *
   * <h4>Disconnecting properly</h4>
   *
   * <p>The formally correct mechanism of disconnecting the returned {@link FCPPluginConnection} is
   * to null out the strong reference to it. The node internally keeps a {@link
   * java.lang.ref.ReferenceQueue} which allows it to detect the strong reference being nulled,
   * which in turn makes the node clean up its internal structures.<br>
   * Thus, you are encouraged to keep the returned {@link FCPPluginConnection} in memory and use it
   * for as long as you need it. Notice that keeping it in memory won't block unloading of the
   * server plugin. If the server plugin is unloaded, the send-functions will fail. To get
   * reconnected once the server plugin is loaded again, you must obtain a fresh client connection
   * from this function: Once an existing client connection is indicated as closed by a single call
   * to a send function throwing {@link IOException}, it <b>must be</b> considered as dead forever,
   * reconnecting is not possible.<br>
   * While this does seem like you do not have to take care about disconnection at all, you
   * <b>must</b> make sure to not keep an excessive amount of {@link FCPPluginConnection} objects
   * strongly referenced to ensure that this mechanism works. Especially notice that a {@link
   * FCPPluginConnection} is safe and intended to be used for multiple messages, you should
   * <b>not</b> obtain a fresh one for every message you send.<br>
   * Also, you <b>should</b> make sure to periodically try to send a message over the {@link
   * FCPPluginConnection} and check whether you receive a reply to check whether the connection
   * still is alive: There is no other mechanism of indicating a closed connection to you than not
   * getting back any reply to messages you send. So if your plugin does send messages very
   * infrequently, and thus might keep a reference to a dead FCPPluginConnection for a long time, it
   * might be indicated to create a "keepalive-loop" which sends "ping" messages periodically and
   * reconnects if no "pong" message is received within a sane timeout. Whether a server plugin
   * supports a special "ping" message or requires you to use another type of message as ping is
   * left up to the implementation of the server plugin.
   *
   * <h4>Performance</h4>
   *
   * <br>
   * While you are formally connecting via FCP, there is no actual network connection being created.
   * The FCP messages are passed-through directly as Java objects. Therefore, this mechanism should
   * be somewhat efficient.<br>
   * Thus, plugins should communicate via FCP instead of passing objects of their own Java classes
   * even if they are running within the same node because this encourages implementation of FCP
   * servers, which in turn allows people to write alternative user interfaces for plugins. <br>
   * Also, this will allow future changes to the node to make it able to run each plugin within its
   * own node and only connect them via real networked FCP connections. This could be used for load
   * balancing of plugins across multiple machines, CPU usage monitoring, sandboxing and other nice
   * stuff.
   *
   * @param pluginName The name of the main class of the plugin - that is the class which implements
   *     {@link FredPlugin}. See {@link PluginManager#getPluginInfoByClassName(String)}.
   * @param messageHandler An object of your plugin which implements the {@link
   *     FredPluginFCPMessageHandler.ClientSideFCPMessageHandler} interface. Its purpose is to
   *     handle FCP messages which the remote plugin sends back to your plugin.
   * @return A {@link FCPPluginConnection} representing the client connection.<br>
   *     Please do read the whole Javadoc of this function to know how to use it properly.
   * @throws PluginNotFoundException if no loaded plugin matches {@code pluginName}.
   */
  public FCPPluginConnection connectToOtherPlugin(
      String pluginName, FredPluginFCPMessageHandler.ClientSideFCPMessageHandler messageHandler)
      throws PluginNotFoundException {

    if (messageHandler == null) throw new NullPointerException("messageHandler must not be null");

    // pluginName being null will be handled by createFCPPluginConnectionForIntraNodeFCP().

    return node.getClientCore()
        .getEndpoints()
        .getFCPServer()
        .createFCPPluginConnectionForIntraNodeFCP(pluginName, messageHandler);
  }

  /**
   * Allows FCP server plugins, that is plugins which implement {@link
   * FredPluginFCPMessageHandler.ServerSideFCPMessageHandler}, to obtain an existing client {@link
   * FCPPluginConnection} by its {@link UUID} - if the client is still connected.<br>
   * <br>
   * May be used by servers which cannot store objects in memory, for example because they are using
   * a database: An {@link UUID} can be serialized to disk, serialization would not be possible for
   * a {@link FCPPluginConnection}.<br>
   * Servers are however free to instead keep the {@link FCPPluginConnection} in memory, usage of
   * this function is not mandatory.<br>
   * <br>
   * <b>Must not</b> be used by client plugins: They shall instead keep a hard reference to the
   * {@link FCPPluginConnection} in memory after they have received it from {@link
   * #connectToOtherPlugin(String, FredPluginFCPMessageHandler.ClientSideFCPMessageHandler)}. If
   * they did not keep a hard reference and only stored the ID, the {@link FCPPluginConnection}
   * would be garbage collected and thus considered as disconnected.<br>
   * <br>
   * Before you use this function, you <b>should definitely</b> also read the Javadoc of {@link
   * FredPluginFCPMessageHandler.ServerSideFCPMessageHandler#handlePluginFCPMessage(
   * FCPPluginConnection, FCPPluginMessage)} for full instructions on how to handle the lifecycle of
   * client connections and their disconnection.
   *
   * @see FredPluginFCPMessageHandler.ServerSideFCPMessageHandler#handlePluginFCPMessage(
   *     FCPPluginConnection, FCPPluginMessage) The message handler at
   *     FredPluginFCPMessageHandler.ServerSideFCPMessageHandler provides an explanation of when to
   *     use this.
   * @param connectionID The connection's {@link UUID} as obtained by {@link
   *     FCPPluginConnection#getID()}.
   * @return The client connection if it is still connected.
   * @throws IOException If there has been no client connection with the given ID or if the client
   *     has disconnected already.<br>
   *     If this happens, you should consider the connection {@link UUID} as invalid forever and
   *     discard it.
   */
  public FCPPluginConnection getPluginConnectionByID(UUID connectionID) throws IOException {
    return node.getClientCore().getEndpoints().getFCPServer().getPluginConnectionByID(connectionID);
  }

  /**
   * Returns the {@link ToadletContainer} used by the node HTTP subsystem.
   *
   * <p>Plugins can use the returned container to register toadlets and integrate into the node web
   * interface. Compared to {@code FredPluginHTTP}, toadlets allow more flexible routing and
   * rendering while still participating in the node's UI conventions (navigation, theming, access
   * control, and form-password validation).
   *
   * <p>The container is owned by the node. Plugins should not attempt to stop or replace it. If
   * HTTP is unavailable, this method returns {@code null} and callers should avoid registering
   * toadlets or building HTTP-only UI elements.
   *
   * @return the node {@link ToadletContainer}, or {@code null} if HTTP is not available.
   */
  public ToadletContainer getToadletContainer() {
    return node.getClientCore().getEndpoints().getToadletContainer();
  }

  /**
   * Get a PluginStore that can be used by the plugin to put data in a database. The database used
   * is the node's database, so all the encrypt/decrypt part is already automatically handled
   * according to the physical security level.
   *
   * <p>The store is loaded lazily and cached in this respirator instance. If no persisted store
   * exists yet, a new empty {@link PluginStore} is created. The store is keyed by the canonical
   * name of the plugin main class, so a plugin typically sees the same store across restarts as
   * long as its class name remains stable.
   *
   * <p>Access is synchronized so plugins may call this method from multiple threads without racing
   * the lazy initialization.
   *
   * @return a non-null {@link PluginStore} instance associated with this plugin.
   */
  public PluginStore getStore() {
    synchronized (this) {
      if (store != null) return store;
      store = stores.loadPluginStore(this.plugin.getClass().getCanonicalName());
      if (store == null) store = new PluginStore();
      return store;
    }
  }

  /**
   * This should be called by the plugin to store its PluginStore in the node's database.
   *
   * <p>The store is written under the canonical name of the plugin class. Write failures are logged
   * and are not rethrown so that plugins can continue operating with an in-memory store.
   *
   * @param store the store instance to persist; may be {@code null} if the plugin has no state.
   */
  public void putStore(final PluginStore store) {
    String name = this.plugin.getClass().getCanonicalName();
    try {
      stores.writePluginStore(name, store);
    } catch (IOException e) {
      LOG.warn("Unable to write plugin data for {}", name, e);
    }
  }

  /**
   * Get a new session manager for use with the global "/" cookie path and the given cookie
   * namespace. See {@link SessionManager} for a detailed explanation of what cookie namespaces are.
   *
   * <p>This method maintains a process-wide list of session managers and returns an existing
   * instance when one has already been created for the same namespace. This is important for
   * consistent cookie handling: if multiple parts of a plugin (or multiple plugins) used separate
   * session managers with the same namespace, login/session state could become inconsistent.
   *
   * <p>This function is synchronized on the session manager list and is safe to call concurrently.
   *
   * @param cookieNamespace the cookie namespace used to avoid collisions between applications.
   * @return a {@link SessionManager} for {@code cookieNamespace}, creating it if necessary.
   */
  public SessionManager getSessionManager(String cookieNamespace) {
    synchronized (sessionManagers) {
      for (SessionManager m : sessionManagers) {
        if (m.getCookieNamespace().equals(cookieNamespace)) return m;
      }

      final SessionManager m = new SessionManager(cookieNamespace);
      sessionManagers.add(m);
      return m;
    }
  }

  /**
   * Returns the plugin's {@link SubConfig}, if the plugin is configurable.
   *
   * <p>The returned sub-configuration represents the plugin-specific configuration subtree managed
   * by the node. Plugins can read and update values on this object, and then call {@link
   * #storeConfig()} to request persistence. If the plugin does not implement {@code
   * FredPluginConfigurable}, no sub-config exists and this method returns {@code null}.
   *
   * @return the plugin {@link SubConfig}, or {@code null} if the plugin is not configurable.
   */
  public SubConfig getSubConfig() {
    return pi.getSubConfig();
  }

  /**
   * Requests persistence of the plugin configuration to disk.
   *
   * <p>This method delegates to the plugin wrapper's configuration storage mechanism. It is
   * typically used after mutating values obtained from {@link #getSubConfig()} so that changes are
   * durably recorded. If the plugin is not configurable, this call is effectively a no-op from the
   * plugin perspective and callers should not rely on it to create configuration state.
   */
  public void storeConfig() {
    pi.getConfig().store();
  }
}
