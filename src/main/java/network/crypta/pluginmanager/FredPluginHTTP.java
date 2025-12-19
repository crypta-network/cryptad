package network.crypta.pluginmanager;

import network.crypta.support.api.HTTPRequest;

/**
 * Provides a minimal HTTP request/response hook for plugins.
 *
 * <p>This interface is a simple, string-based way for a plugin to respond to HTTP requests without
 * integrating deeply with the node's toadlet-based HTTP stack. It is intentionally limited: the
 * plugin is given the incoming {@link HTTPRequest} and returns an HTML payload as a {@link String},
 * or it signals an HTTP-level outcome by throwing a {@link PluginHTTPException}. The node calls
 * these methods as part of request handling and uses the result to build the HTTP response.
 *
 * <p>Implementations should keep request handling bounded and avoid long-running operations on the
 * request thread. If a plugin cannot handle a request it may return {@code null} so the node can
 * continue dispatching. For more advanced integration (menu entries, richer response control, and
 * finer routing), prefer the node's toadlet APIs.
 *
 * <ul>
 *   <li><b>GET/POST handling:</b> Implement {@link #handleHTTPGet(HTTPRequest)} and/or {@link
 *       #handleHTTPPost(HTTPRequest)} as needed.
 *   <li><b>Error mapping:</b> Throw specific {@link PluginHTTPException} subclasses to drive status
 *       codes and special behaviors (redirects, downloads).
 *   <li><b>Threading:</b> Consider also implementing {@link FredPluginThreadless} to avoid being
 *       registered before plugin initialization completes.
 * </ul>
 *
 * <p>IMPORTANT NOTE TO IMPLEMENTORS: We strongly recommend you implement FredPluginThreadless as
 * well, because if you do not we will have to register the plugin *before* calling runPlugin().
 * This means it won't be registered and you will probably get NPEs!
 */
public interface FredPluginHTTP {
  // Let them return null if unhandled
  /**
   * Handles an HTTP {@code GET} request and returns an HTML response body.
   *
   * <p>The node calls this method when dispatching a {@code GET} request to the plugin. If the
   * plugin handles the request, it should return an HTML payload as a {@link String}. If the plugin
   * does not handle the request, it may return {@code null} so the node can continue dispatching to
   * other handlers. To communicate non-success outcomes (such as {@code 403}, {@code 404},
   * redirects or forced downloads), throw a {@link PluginHTTPException} (prefer a specific subclass
   * where applicable).
   *
   * @param request the incoming HTTP request; read parameters and headers from this object, do not
   *     assume it is reusable across threads
   * @return HTML response body when handled, or {@code null} to indicate the request is not handled
   * @throws AccessDeniedPluginHTTPException to send a 403 error.
   * @throws DownloadPluginHTTPException to force data to be downloaded to disk, with a MIME type.
   * @throws NotFoundPluginHTTPException to send a 404 error.
   * @throws RedirectPluginHTTPException to send a redirect.
   * @throws PluginHTTPException for any other failure, treated as a 400 error.
   */
  String handleHTTPGet(HTTPRequest request) throws PluginHTTPException;

  /**
   * Handles an HTTP {@code POST} request and returns an HTML response body.
   *
   * <p>The node calls this method when dispatching a {@code POST} request to the plugin. The plugin
   * can inspect form fields and uploaded data through the provided {@link HTTPRequest}. If the
   * plugin handles the request, it returns an HTML payload. If it does not handle the request, it
   * may return {@code null} so other handlers can attempt to serve it. Use {@link
   * PluginHTTPException} (or a more specific subclass) to signal status codes and special behaviors
   * such as redirects or downloads.
   *
   * @param request the incoming HTTP request; contains submitted fields and any uploaded content
   * @return HTML response body when handled, or {@code null} to indicate the request is not handled
   * @throws PluginHTTPException to map failures or special HTTP outcomes to a response
   */
  String handleHTTPPost(HTTPRequest request) throws PluginHTTPException;
}
