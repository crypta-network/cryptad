package network.crypta.clients.http.wizardsteps;

import java.io.IOException;
import network.crypta.support.api.HTTPRequest;

/**
 * Handler for a single first-time wizard screen.
 *
 * <p>A {@code Step} implementation renders one page in the onboarding wizard and optionally applies
 * changes when the user submits that page. Steps are invoked by {@link
 * network.crypta.clients.http.FirstTimeWizardToadlet} and are not registered as standalone FProxy
 * toadlets; they are reachable only through the wizard flow and its redirects.
 *
 * <p>Typical usage is a GET/POST pair: {@link #getStep(HTTPRequest, PageHelper)} builds the HTML
 * for the current screen using a per-request {@link PageHelper}, then {@link
 * #postStep(HTTPRequest)} validates submitted fields and performs any side effects for that screen
 * (for example, writing configuration values). The {@code postStep} return value is treated as a
 * redirect target, usually starting with a {@link
 * network.crypta.clients.http.FirstTimeWizardToadlet.WIZARD_STEP} name and optionally including
 * additional query parameters.
 *
 * <p>Threading and state: this interface does not define any synchronization. Callers construct a
 * new {@link PageHelper} for each request, but step implementations may be long-lived. Implementers
 * should avoid retaining request-specific objects beyond the call and should not rely on mutable
 * shared state unless it is externally synchronized.
 *
 * <ul>
 *   <li>Render wizard HTML for a single screen.
 *   <li>Parse and validate submitted form fields for that screen.
 *   <li>Return the next wizard redirect target after submission.
 * </ul>
 *
 * @see network.crypta.clients.http.FirstTimeWizardToadlet
 * @see network.crypta.clients.http.FirstTimeWizardToadlet.WIZARD_STEP
 */
public interface Step {
  /**
   * Renders the wizard screen for this step into a new page built by {@code helper}.
   *
   * <p>This method is called during the wizard's HTTP GET handling after the caller has created a
   * fresh {@link PageHelper}. Implementations typically call {@link
   * PageHelper#getPageContent(String)} to obtain the page content node and then append HTML
   * elements and forms to it. The caller is responsible for converting the resulting page tree to
   * HTML (for example via {@link PageHelper#generate()}).
   *
   * <p>Implementations may inspect {@code request} for query parameters that influence rendering
   * (for example, previously persisted wizard fields). This method should be safe to call multiple
   * times for the same inputs; it should not rely on hidden server-side session state.
   *
   * <pre>{@code
   * Step step = ...;
   * PageHelper helper = new PageHelper(ctx, persistFields, currentStep);
   * step.getStep(request, helper);
   * String html = helper.generate();
   * }</pre>
   *
   * @param request HTTP request wrapper for the current wizard page and query parameters.
   * @param helper per-request helper that creates page nodes, forms, and infoboxes for this step.
   */
  void getStep(HTTPRequest request, PageHelper helper);

  /**
   * Handles a form submission for this step and computes the next wizard redirect target.
   *
   * <p>This method is called during the wizard's HTTP POST handling. Implementations typically read
   * submitted parts from {@code request}, validate them, and apply any changes associated with this
   * step (for example, updating configuration or enabling a feature). If the submission is invalid,
   * an implementation may choose to redirect back to the same step by returning its own step name
   * as the redirect target.
   *
   * <p>The returned string is appended to the wizard base URL as {@code ?step=<target>}. For
   * compatibility with the surrounding wizard logic, the value usually starts with a {@link
   * network.crypta.clients.http.FirstTimeWizardToadlet.WIZARD_STEP} name and may append additional
   * query parameters (for example {@code "OPENNET&opennet=true"}).
   *
   * <pre>{@code
   * String target = step.postStep(request);
   * // Caller redirects to: /wizard/?step=<target>
   * }</pre>
   *
   * @param request HTTP request wrapper containing submitted form fields for this step.
   * @return redirect target appended after {@code ?step=}, optionally with extra query parameters.
   * @throws IOException if applying the step's changes requires IO that fails.
   */
  String postStep(HTTPRequest request) throws IOException;
}
