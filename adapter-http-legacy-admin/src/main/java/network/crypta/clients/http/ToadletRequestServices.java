package network.crypta.clients.http;

import network.crypta.runtime.alerts.UserAlertSurface;

/**
 * Shared services needed to build per-request {@link ToadletContextImpl} instances.
 *
 * <p>This record groups the long-lived collaborators that are passed together whenever a new
 * request context is created. It keeps request handling signatures compact while preserving the
 * existing wiring between the HTTP listener and the toadlet container.
 *
 * @param container the owning toadlet container that enforces request policies
 * @param pageMaker shared page renderer used by UI toadlets
 * @param userAlertManager alert surface used to render and mutate user-facing alerts
 * @param bookmarkManager bookmark subsystem handle for request handlers
 */
public record ToadletRequestServices(
    ToadletContainer container,
    PageMaker pageMaker,
    UserAlertSurface userAlertManager,
    BookmarkManagerHandle bookmarkManager) {}
