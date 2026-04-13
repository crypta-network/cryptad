package network.crypta.clients.http;

import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.ajaxpush.PushDataToadlet;
import network.crypta.clients.http.ajaxpush.PushFailoverToadlet;
import network.crypta.clients.http.ajaxpush.PushKeepaliveToadlet;
import network.crypta.clients.http.ajaxpush.PushLeavingToadlet;
import network.crypta.clients.http.ajaxpush.PushNotificationToadlet;
import network.crypta.clients.http.ajaxpush.PushTesterToadlet;

/**
 * Registers the AJAX-push browse routes owned by the current legacy FProxy shell.
 *
 * <p>This helper keeps the tightly related push toadlets together and out of {@link
 * LegacyFProxyBrowseRouteRegistrar} so the top-level browse registrar can stay focused on the phase
 * boundaries that matter for the physical browse split. The helper now lives in {@code
 * :adapter-http-legacy-browse} together with the browse-owned code it registers.
 *
 * <p>Callers use this helper only during one-shot HTTP startup. It instantiates the concrete
 * AJAX-push toadlets, registers them in the historical order already exposed by the legacy shell,
 * and leaves menu publication to the surrounding browse registrar. The helper is intentionally
 * stateless and does not retain the supplied client or server after registration completes.
 */
final class LegacyFProxyAjaxPushRouteRegistrar {

  /**
   * Creates a stateless helper for AJAX-push route publication.
   *
   * <p>The constructor exists only to make the helper's startup role explicit in generated API
   * documentation. Instances carry no mutable state and can be reused across startup attempts as
   * long as callers still treat registration as a one-shot shell-initialization step.
   */
  LegacyFProxyAjaxPushRouteRegistrar() {
    // This helper is intentionally stateless.
  }

  /**
   * Registers the AJAX-push routes that occupy the tail of the legacy browse surface.
   *
   * <p>The method publishes only the push toadlets that belong to the AJAX-update subfamily. It
   * preserves the current startup order, so the caller can still insert later browse-tail
   * registrations such as image creation and alert dismissal immediately afterward. The method does
   * not add menu links, perform deduplication, or mutate global shell state beyond adding routes to
   * the provided server.
   *
   * @param client a shared interactive client passed into each push toadlet constructor during
   *     startup
   * @param server legacy HTTP shell that receives the registered push routes in their fixed order
   */
  void registerRoutes(HighLevelSimpleClient client, SimpleToadletServer server) {
    PushDataToadlet pushDataToadlet = new PushDataToadlet(client);
    server.register(
        pushDataToadlet, ToadletRegistration.basic(null, pushDataToadlet.path(), true, false));

    PushNotificationToadlet pushNotificationToadlet = new PushNotificationToadlet(client);
    server.register(
        pushNotificationToadlet,
        ToadletRegistration.basic(null, pushNotificationToadlet.path(), true, false));

    PushKeepaliveToadlet pushKeepaliveToadlet = new PushKeepaliveToadlet(client);
    server.register(
        pushKeepaliveToadlet,
        ToadletRegistration.basic(null, pushKeepaliveToadlet.path(), true, false));

    PushFailoverToadlet pushFailoverToadlet = new PushFailoverToadlet(client);
    server.register(
        pushFailoverToadlet,
        ToadletRegistration.basic(null, pushFailoverToadlet.path(), true, false));

    PushTesterToadlet pushTesterToadlet = new PushTesterToadlet(client);
    server.register(
        pushTesterToadlet, ToadletRegistration.basic(null, pushTesterToadlet.path(), true, false));

    PushLeavingToadlet pushLeavingToadlet = new PushLeavingToadlet(client);
    server.register(
        pushLeavingToadlet,
        ToadletRegistration.basic(null, pushLeavingToadlet.path(), true, false));
  }
}
