package network.crypta.clients.http;

import java.io.File;
import network.crypta.config.Config;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.appvault.AppVaultService;
import network.crypta.runtime.alerts.UserAlertSurface;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.Ticker;

/**
 * Defines the daemon-backed services that the HTTP shell still needs at runtime.
 *
 * <p>This interface is public only so runtime-owned HTTP bootstrap adapters can implement it from
 * outside {@code network.crypta.clients.http}. It is not a new platform API. The seam narrows the
 * remaining surface that {@link SimpleToadletServer} uses while the larger daemon bootstrap still
 * starts from the legacy node core. Implementations may expose old HTTP-local concepts such as
 * alerts, ticker access, and legacy bootstrap work, but the seam is not a new cross-module platform
 * abstraction. Its purpose is to keep shell behavior explicit, locally testable, and detached from
 * direct legacy node-core field access inside the server itself.
 */
public interface HttpShellRuntimeSupport {

  /**
   * Returns the runtime ports used by the shell for low-level services such as randomness.
   *
   * <p>The returned ports stay owned by the surrounding daemon runtime. Callers treat them as
   * shared infrastructure and should not assume exclusive access or independent lifecycle control.
   *
   * @return runtime ports that expose shell-relevant low-level services
   */
  RuntimePorts runtimePorts();

  /**
   * Returns the live node configuration visible to the HTTP shell.
   *
   * <p>Shell callbacks use this configuration to read and persist settings that still live in the
   * daemon config tree. The returned object remains mutable and reflects the daemon's current
   * runtime state.
   *
   * @return live configuration object used by HTTP shell callbacks and startup checks
   */
  Config config();

  /**
   * Returns the long-lived AppHost instance used by the platform control plane.
   *
   * <p>The returned host is shared across the current node lifecycle. Callers should treat it as a
   * managed runtime service rather than constructing new AppHost instances per request.
   *
   * @return shared AppHost instance used by Platform API app-management routes
   */
  AppHost appHost();

  /**
   * Returns the long-lived signed app-catalog manager used by the platform control plane.
   *
   * <p>A {@code null} value means the current embedding exposes AppHost lifecycle routes but has
   * not configured catalog source management. The Platform API router treats that state as the
   * catalog endpoint family being unavailable rather than constructing a per-request manager.
   *
   * @return shared app-catalog manager, or {@code null} when catalog support is unavailable
   */
  AppCatalogManager appCatalogManager();

  /**
   * Returns the long-lived app vault used by Platform API vault routes.
   *
   * <p>The vault is shared across app lifecycle, app-facing vault routes, and operator-facing
   * identity-grant management. It owns local at-rest envelope storage and must not be recreated per
   * request.
   *
   * @return shared app-vault service, or {@code null} when vault support is unavailable
   */
  AppVaultService appVaultService();

  /**
   * Creates the legacy push-data manager used by the shell's interval push flow.
   *
   * <p>The returned handle stays owned by the runtime bridge. Shared-shell code uses this seam so
   * the concrete browse-owned implementation can live outside the shared admin shell.
   *
   * @param ticker scheduler used by the push manager for cleanup and timed work
   * @return shared-shell push-data manager handle
   */
  PushDataManagerHandle createPushDataManagerHandle(Ticker ticker);

  /**
   * Returns the ticker used for shell tasks that rely on the daemon scheduler.
   *
   * <p>The ticker remains owned by the daemon network services. The HTTP shell uses it for
   * time-based tasks rather than creating its own independent scheduler.
   *
   * @return shared daemon ticker used by shell-level timed work
   */
  Ticker ticker();

  /**
   * Returns the detached alert surface surfaced through HTTP status and warning pages.
   *
   * <p>The surface is shared with the rest of the daemon. Shell code should treat it as a live
   * runtime service whose contents may change as the node state changes.
   *
   * @return shared user-alert surface visible to HTTP toadlets
   */
  UserAlertSurface userAlerts();

  /**
   * Returns the current hidden form password inserted into shell-generated forms.
   *
   * <p>The shell uses this token when it renders actions that must be protected against unwanted
   * submission. Callers should treat the returned value as a sensitive process-local state.
   *
   * @return current form password for hidden HTTP form fields
   */
  String formPassword();

  /**
   * Checks whether the current runtime policy allows uploads from a local file.
   *
   * <p>This preserves the existing daemon-side permission check instead of duplicating policy in
   * the HTTP shell. The decision may depend on current security settings and operator choices.
   *
   * @param filename local file the user wants to upload through the HTTP shell
   * @return {@code true} when uploads from the supplied file are currently permitted
   */
  boolean allowUploadFrom(File filename);

  /**
   * Persists the current configuration after shell code changes a stored setting.
   *
   * <p>Implementations are responsible for forwarding the save request to the daemon-side config
   * storage layer used by the existing node runtime.
   */
  void storeConfig();

  /**
   * Indicates whether the shell may still redirect requests to the first-time setup wizard.
   *
   * <p>This allows tests or future adapters to suppress wizard redirects without reproducing the
   * full daemon bootstrap state. Production core-backed wiring currently allows the redirect check.
   *
   * @return {@code true} when wizard redirect decisions should remain active
   */
  boolean canRedirectToWizard();

  /**
   * Returns the detached insert compatibility modes used by legacy HTTP forms.
   *
   * <p>The returned value object keeps the admin shell independent of the runtime-node insert enum
   * while preserving the current ordering, labels, and default selection used by the legacy upload
   * forms.
   *
   * @return HTTP-local compatibility-mode names and their default selection
   */
  InsertCompatibilityModes insertCompatibilityModes();

  /**
   * Registers a listener for network threat-level changes using HTTP-local enum values.
   *
   * <p>The callback receives detached values so {@link SimpleToadletServer} does not have to depend
   * on daemon threat-level enums directly. Listener invocation timing remains controlled by the
   * underlying runtime implementation.
   *
   * @param listener callback notified when the runtime network threat level changes
   */
  void addNetworkThreatLevelListener(ThreatLevelListener<NetworkThreatLevel> listener);

  /**
   * Registers a listener for physical threat-level changes using HTTP-local enum values.
   *
   * <p>The callback receives detached values, so shell code can react to local security changes
   * without importing daemon threat-level types directly.
   *
   * @param listener callback notified when the runtime physical threat level changes
   */
  void addPhysicalThreatLevelListener(ThreatLevelListener<PhysicalThreatLevel> listener);

  /**
   * Creates the browse-neutral collaborators required before the shell registers child toadlets.
   *
   * <p>Implementations assemble the daemon-backed collaborators required for legacy browse startup,
   * then hand the shell a browse-neutral bundle. Callers should treat the result as a one-time
   * bootstrap snapshot for the current shell instance.
   *
   * @param publicGatewayMode whether the shell should bootstrap public-gateway bookmark behavior
   * @return bootstrap bundle containing the bookmark manager and browse-owned startup collaborators
   */
  HttpShellBrowseBootstrap createBrowseBootstrap(boolean publicGatewayMode);

  /**
   * Receives detached threat-level change notifications from the runtime support implementation.
   *
   * @param <T> HTTP-local threat-level enum type delivered to the listener
   */
  @FunctionalInterface
  interface ThreatLevelListener<T> {
    /**
     * Handles a threat-level transition.
     *
     * <p>The callback receives the previous and new level using the detached enum type chosen by
     * the surrounding listener registration.
     *
     * @param oldLevel previous detached threat level before the change
     * @param newLevel new detached threat level after the change
     */
    void onChange(T oldLevel, T newLevel);
  }

  /** Represents the lowest network threat posture exposed to the HTTP shell. */
  enum NetworkThreatLevel {
    /** Indicates low network-side threat assumptions. */
    LOW,
    /** Indicates the default network threat posture used during normal operation. */
    NORMAL,
    /** Indicates elevated network-side threat assumptions. */
    HIGH,
    /** Indicates the most restrictive network threat posture available to the shell. */
    MAXIMUM
  }

  /** Represents the local physical threat posture exposed to the HTTP shell. */
  enum PhysicalThreatLevel {
    /** Indicates low physical compromise risk for the local node environment. */
    LOW,
    /** Indicates the default physical threat posture used during normal operation. */
    NORMAL,
    /** Indicates elevated concern about local physical compromise. */
    HIGH,
    /** Indicates the most restrictive physical threat posture available to the shell. */
    MAXIMUM
  }
}
