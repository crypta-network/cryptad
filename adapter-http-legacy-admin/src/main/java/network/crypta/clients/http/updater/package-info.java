/**
 * HTTP-facing adapter surface for core updater actions.
 *
 * <p>This package contains the web-layer types that expose the core updater to browser clients
 * under {@code /core-update/}. Code here translates form submissions and request parameters into
 * calls on the runtime updater ports, then renders redirects or HTML result pages that fit the
 * existing FProxy user interface. It is the place for HTTP-specific concerns such as request
 * parsing, form-password checks, redirect targets, and browser-oriented success or failure
 * messaging.
 *
 * <p>The package does not own updater state, installer selection, download coordination, or package
 * validation rules. Those responsibilities remain in {@code network.crypta.runtime.updater} and the
 * runtime SPI it exposes. Keeping this package narrow preserves the intended architectural
 * boundary: runtime code stays independent of {@code clients.http}, while the HTTP shell remains
 * free to present the updater flow without embedding business logic.
 *
 * <p>In practice, types in this package should:
 *
 * <ul>
 *   <li>bridge UI actions to runtime ports with minimal translation logic
 *   <li>keep path handling and response rendering consistent with the rest of FProxy, and
 *   <li>avoid reimplementing updater policy that already belongs to the runtime layer.
 * </ul>
 */
package network.crypta.clients.http.updater;
