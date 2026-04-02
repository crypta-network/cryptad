/**
 * First-time setup wizard steps for the node's HTTP interface.
 *
 * <p>This package contains the individual screens used by the onboarding wizard served over the
 * built-in web UI. Each screen is implemented as a {@code Step} and is responsible for two related
 * concerns: rendering its HTML form during a GET request and processing submitted form fields
 * during a POST request. The surrounding HTTP handler orchestrates the flow by selecting a step,
 * invoking it, and then redirecting the browser to the next step based on the POST result.
 *
 * <p>The package is intentionally focused on wizard presentation and per-step validation, rather
 * than on general-purpose HTTP routing. Steps are not registered as standalone toadlets; they are
 * invoked only through the wizard flow. Where a step needs to apply changes, it typically writes
 * configuration values or toggles onboarding-related settings in a way that is suitable for an
 * interactive, user-driven setup process.
 *
 * <p>Threading and state: step implementations may be reused across many requests. Avoid retaining
 * request-scoped objects (such as request wrappers or page nodes) beyond the duration of a single
 * call. Treat all HTTP input as untrusted; validate and normalize form values before applying any
 * side effects.
 *
 * <ul>
 *   <li>Render wizard pages via {@code PageHelper}-built HTML.
 *   <li>Parse and validate submitted form fields for a single wizard screen.
 *   <li>Compute the redirect target for the next step in the flow.
 * </ul>
 */
package network.crypta.clients.http.wizardsteps;
