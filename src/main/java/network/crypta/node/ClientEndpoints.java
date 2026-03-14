package network.crypta.node;

import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.async.ClientContext;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.http.FProxyToadlet;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.io.TempBucketFactory;

/**
 * Bundles client-facing endpoints (FCP, TMCI, and HTTP toadlet container) and their lifecycle.
 *
 * <p>This type centralizes the node's externally visible interfaces so callers can wire them
 * consistently during startup and expose simple accessors during runtime. It holds the FCP server,
 * the optional text-mode interface, and the HTTP toadlet container, and it exposes a small set of
 * methods that delegate to those collaborators. Typical usage is to build an instance during node
 * initialization, register any startup alerts, and then start the endpoints once the core is ready.
 *
 * <p>Thread-safety is limited to safe publication of a small set of references via atomic holders;
 * the underlying endpoint implementations define their own concurrency guarantees. Callers should
 * avoid mutating endpoint state concurrently unless the respective component documents that it is
 * safe to do so.
 *
 * <ul>
 *   <li>Holds the endpoint instances and exposes read-only accessors.
 *   <li>Coordinates simple lifecycle steps such as load and start.
 *   <li>Registers and unregisters a startup alert during initialization.
 * </ul>
 *
 * @see FCPServer
 * @see SimpleToadletServer
 * @see TextModeClientInterfaceServer
 */
public final class ClientEndpoints {
  private final FCPServer fcpServer;
  private final TextModeClientInterfaceServer tmci;
  private final SimpleToadletServer toadletContainer;
  private final AtomicReference<TextModeClientInterface> directTMCI = new AtomicReference<>();
  private final AtomicReference<FProxyToadlet> fproxy = new AtomicReference<>();
  private UserAlert startingUpAlert;

  /**
   * Result wrapper for {@link #create(Node, NodeClientCore, RuntimePorts, NodeClientCoreInit,
   * NodeClientPersistence, ClientContext)}.
   *
   * <p>The returned direct TMCI is created but not started. Callers must publish it via {@link
   * #setDirectTMCI(TextModeClientInterface)} and schedule it on the node executor only after the
   * {@link NodeClientCore} has completed endpoint assignment.
   *
   * @param endpoints fully constructed client endpoints bundle.
   * @param directTMCI direct text-mode interface instance, or {@code null} when disabled.
   */
  public record InitResult(ClientEndpoints endpoints, TextModeClientInterface directTMCI) {}

  /**
   * Creates a new bundle from the provided endpoint instances.
   *
   * <p>The constructor stores the references without validation or defensive copying, so the caller
   * must supply fully initialized instances that remain valid for the lifetime of this bundle. The
   * text-mode interface may be {@code null} when that endpoint is disabled; all other parameters
   * are expected to be non-null in normal operation. Construction has no side effects beyond
   * storing the references, and it does not perform any lifecycle work such as starting servers or
   * registering alerts.
   *
   * @param fcpServer FCP server instance to expose and manage for the node.
   * @param tmci text-mode client interface server, or {@code null} when disabled.
   * @param toadletContainer HTTP toadlet container used for browser-facing endpoints.
   */
  public ClientEndpoints(
      FCPServer fcpServer,
      TextModeClientInterfaceServer tmci,
      SimpleToadletServer toadletContainer) {
    this.fcpServer = fcpServer;
    this.tmci = tmci;
    this.toadletContainer = toadletContainer;
  }

  /**
   * Returns the FCP server associated with this bundle.
   *
   * <p>The returned reference is the same instance supplied at construction time and is not wrapped
   * or proxied. The call is inexpensive and side-effect free, and it does not guarantee that the
   * server has been started or loaded. Use it when wiring other components that already manage the
   * server lifecycle.
   *
   * @return the FCP server instance owned by this bundle.
   */
  public FCPServer getFCPServer() {
    return fcpServer;
  }

  /**
   * Returns the currently configured FProxy toadlet, if any.
   *
   * <p>This value may be {@code null} when no FProxy has been installed or before configuration
   * occurs. The reference is stored in an atomic holder for safe publication across threads, but it
   * does not imply that the toadlet implementation itself is thread-safe. The returned reference is
   * the direct instance currently published by this bundle.
   *
   * @return the current FProxy toadlet, or {@code null} when not set.
   */
  public FProxyToadlet getFProxy() {
    return fproxy.get();
  }

  /**
   * Sets the FProxy toadlet reference to expose via {@link #getFProxy()}.
   *
   * <p>The provided reference is stored as-is and can be {@code null} to clear a previous value. No
   * additional registration or lifecycle actions are performed by this method, so callers must
   * ensure the toadlet is registered with the container elsewhere if required. The update becomes
   * visible to other threads via the atomic reference.
   *
   * @param fproxy FProxy toadlet instance to publish, or {@code null} to clear.
   */
  public void setFProxy(FProxyToadlet fproxy) {
    this.fproxy.set(fproxy);
  }

  /**
   * Returns the HTTP toadlet container used by this bundle.
   *
   * <p>The container is expected to be non-null and shared with other components that register
   * toadlets. This method simply returns the stored reference without modification and does not
   * guarantee any specific initialization state of the container. Callers should consult the
   * container itself for lifecycle details and concurrency guarantees.
   *
   * @return the toadlet container instance for HTTP endpoints and requests.
   */
  public SimpleToadletServer getToadletContainer() {
    return toadletContainer;
  }

  /**
   * Returns the text-mode client interface server, if one was created.
   *
   * <p>The text-mode interface is optional and may be {@code null} when disabled by configuration.
   * Callers must handle the absence of this endpoint and should not attempt to start it directly
   * without checking for {@code null}. The returned instance is the same object provided to the
   * constructor.
   *
   * @return the text-mode client interface server, or {@code null} when unavailable.
   */
  public TextModeClientInterfaceServer getTextModeClientInterface() {
    return tmci;
  }

  /**
   * Returns the directly configured text-mode client interface, if any.
   *
   * <p>This reference is separate from the server returned by {@link #getTextModeClientInterface()}
   * and is published atomically. It may be {@code null} until configured. The method only returns
   * the stored reference and does not create or start a client interface. Callers must handle a
   * {@code null} result.
   *
   * @return the direct text-mode client interface, or {@code null} when not set.
   */
  public TextModeClientInterface getDirectTMCI() {
    return directTMCI.get();
  }

  /**
   * Sets the direct text-mode client interface reference.
   *
   * <p>The reference is stored as-is for later access and may be {@code null} to clear a previous
   * value. No network listeners are started or stopped by this call, and the method does not alter
   * any configuration associated with the interface. It is purely a setter.
   *
   * @param tmci direct text-mode client interface to publish, or {@code null} to clear.
   */
  public void setDirectTMCI(TextModeClientInterface tmci) {
    directTMCI.set(tmci);
  }

  /**
   * Loads persistent requests through the FCP server.
   *
   * <p>This method delegates directly to {@link FCPServer#load()} without checking any additional
   * conditions. It is up to the caller to decide whether loading is required for the current node
   * state, such as skipping it when a database has been intentionally reset. The method itself does
   * not cache or record whether loading has been performed.
   */
  public void loadPersistentRequestsIfNeeded() {
    fcpServer.load();
  }

  /**
   * Starts the client-facing endpoints when appropriate.
   *
   * <p>The FCP server is asked to start via {@link FCPServer#maybeStart()}, and the text-mode
   * interface server is started only if it is present. This method does not create new endpoints
   * and performs no retries; it simply forwards to the underlying components. It is safe to call
   * multiple times if the underlying components implement idempotent start logic.
   */
  public void maybeStart() {
    fcpServer.maybeStart();
    if (tmci != null) {
      tmci.start();
    }
  }

  /**
   * Configures the bucket factory used by the HTTP toadlet container.
   *
   * <p>The provided factory is passed directly to {@link SimpleToadletServer#setBucketFactory} and
   * becomes the source of temporary buckets for future requests. The method does not validate the
   * factory beyond the container's own checks, and it does not create any buckets immediately.
   * Configuration applies to subsequent requests only.
   *
   * @param tempBucketFactory bucket factory to install for temporary storage.
   */
  public void configureBucketFactory(TempBucketFactory tempBucketFactory) {
    toadletContainer.setBucketFactory(tempBucketFactory);
  }

  /**
   * Creates and registers the startup alert shown while the node is initializing.
   *
   * <p>The alert is created via {@link NodeClientCoreSupport#createStartingUpAlert} and registered
   * with the alert manager using {@link NodeClientCoreSupport#registerFProxyAlerts}. The newly
   * created alert reference is stored so {@link #unregisterStartupAlert(UserAlertManager)} can
   * remove it later. If this method is called multiple times, the stored reference is overwritten
   * without automatically unregistering the previous alert, so callers should explicitly unregister
   * when replacing an existing startup alert.
   *
   * @param alerts alert manager used to register the startup alert instance.
   * @param core node client core associated with the alert registration.
   * @param title alert title text to display to the user.
   * @param longText long-form alert description shown in detailed views.
   * @param shortText short-form alert description shown in compact views.
   */
  public void registerStartupAlerts(
      UserAlertManager alerts,
      NodeClientCore core,
      String title,
      String longText,
      String shortText) {
    UserAlert alert = NodeClientCoreSupport.createStartingUpAlert(title, longText, shortText);
    NodeClientCoreSupport.registerFProxyAlerts(alerts, core, alert);
    startingUpAlert = alert;
  }

  /**
   * Unregisters the previously registered startup alert, if present.
   *
   * <p>If no startup alert has been registered, this method performs no action. The stored alert
   * reference is not cleared here; the caller should avoid reusing stale references or should clear
   * its own tracking when appropriate. No other alerts are affected.
   *
   * @param alerts alert manager used to unregister the stored startup alert.
   */
  public void unregisterStartupAlert(UserAlertManager alerts) {
    if (startingUpAlert != null) {
      alerts.unregister(startingUpAlert);
    }
  }

  /**
   * Returns whether the toadlet container is in advanced mode.
   *
   * <p>This is a simple delegation to {@link SimpleToadletServer#isAdvancedModeEnabled()} and has
   * no side effects. The returned value reflects the container's current configuration and may
   * change if that configuration is updated elsewhere. It does not imply any access control
   * changes. It is read-only.
   *
   * @return {@code true} when advanced mode is enabled, otherwise {@code false}.
   */
  public boolean isAdvancedModeEnabled() {
    return toadletContainer.isAdvancedModeEnabled();
  }

  /**
   * Returns whether FProxy JavaScript support is enabled.
   *
   * <p>This is a direct delegation to {@link SimpleToadletServer#isFProxyJavascriptEnabled()} and
   * does not alter the container state. The return value is a snapshot of the container's current
   * configuration at the time of the call. It does not enable or disable scripts. It is
   * informational only.
   *
   * @return {@code true} when FProxy JavaScript is enabled, otherwise {@code false}.
   */
  public boolean isFProxyJavascriptEnabled() {
    return toadletContainer.isFProxyJavascriptEnabled();
  }

  /**
   * Builds a fully wired {@link ClientEndpoints} instance from core node components.
   *
   * <p>The method conditionally creates the text-mode interface server, creates an FCP server via
   * the persistence layer, and registers that server as the download cache in the client context.
   * If the node has not killed its database, it loads persistent requests immediately. No endpoints
   * are started by this method; callers typically invoke {@link #maybeStart()} once the node is
   * ready. When direct TMCI is enabled, it is created but not started; callers must register it on
   * the endpoints bundle and schedule it after {@link NodeClientCore#getEndpoints()} is assigned.
   * The returned instance captures the created references and does not perform any additional
   * initialization beyond the steps described above.
   *
   * <pre>{@code
   * ClientEndpoints.InitResult initResult =
   *     ClientEndpoints.create(node, core, runtimePorts, init, persistence, clientContext);
   * initResult.endpoints().maybeStart();
   * }</pre>
   *
   * @param node node instance used for endpoint creation and configuration.
   * @param core client core used by endpoint factories and alert registration.
   * @param runtimePorts runtime SPI bridge passed to the FCP infrastructure.
   * @param init initializer providing configuration and toadlet container access.
   * @param persistence persistence layer responsible for creating the FCP server.
   * @param clientContext client context updated with the FCP download cache.
   * @return an {@link InitResult} containing the endpoints bundle and optional direct TMCI
   *     instance.
   */
  public static InitResult create(
      Node node,
      NodeClientCore core,
      RuntimePorts runtimePorts,
      NodeClientCoreInit init,
      NodeClientPersistence persistence,
      ClientContext clientContext) {
    TextModeClientInterfaceServer.InitResult tmciInit =
        TextModeClientInterfaceServer.maybeCreate(node, core, init.config());
    TextModeClientInterfaceServer tmci = tmciInit.server();
    FCPServer fcpServer = persistence.createFcpServer(node, core, runtimePorts);
    clientContext.setDownloadCache(fcpServer);
    if (!core.killedDatabase()) {
      fcpServer.load();
    }
    return new InitResult(
        new ClientEndpoints(fcpServer, tmci, init.toadlets()), tmciInit.directTMCI());
  }
}
