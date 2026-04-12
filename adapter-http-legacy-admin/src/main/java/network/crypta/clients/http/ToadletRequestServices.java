package network.crypta.clients.http;

import network.crypta.runtime.alerts.UserAlertManager;

/**
 * Shared services needed to build per-request {@link ToadletContextImpl} instances.
 *
 * <p>This record groups the long-lived collaborators that are passed together whenever a new
 * request context is created. It keeps request handling signatures compact while preserving the
 * existing wiring between the HTTP listener and the toadlet container.
 *
 * @param container the owning toadlet container that enforces request policies
 * @param pageMaker shared page renderer used by UI toadlets
 * @param userAlertManager manager used to surface user-facing alerts
 * @param bookmarkManager bookmark subsystem handle for request handlers
 */
public record ToadletRequestServices(
    ToadletContainer container,
    PageMaker pageMaker,
    UserAlertManager userAlertManager,
    BookmarkManagerHandle bookmarkManager) {}
