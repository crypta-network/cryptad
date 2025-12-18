package network.crypta.clients.http.wizardsteps;

import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.support.Fields;
import network.crypta.support.api.HTTPRequest;

/**
 * Parses and carries wizard state that should persist across HTTP requests.
 *
 * <p>This type extracts a small set of “persistence fields” from an incoming {@link HTTPRequest}
 * and exposes them as immutable, publicly readable values. These fields are used by the HTTP
 * first-time wizard to keep a user’s selected options stable while navigating between steps,
 * including when the wizard is rendered as multiple pages or as a single consolidated screen.
 *
 * <p>The parsing logic prefers query parameters (GET) when present and otherwise falls back to
 * multipart/body parts (POST). Invalid or missing values are handled defensively: booleans fall
 * back to {@code false}, and unknown presets result in {@code null} so callers can distinguish “not
 * provided or invalid” from a concrete preset selection.
 *
 * <p>This class is immutable and thread-safe after construction. It performs only lightweight
 * string parsing and does not validate broader wizard invariants; callers should apply higher-level
 * validation appropriate to the surrounding workflow.
 *
 * <ul>
 *   <li><b>Responsibilities</b>: parse wizard persistence parameters and make them available to
 *       later steps.
 *   <li><b>Notable behavior</b>: URL serialization uses raw enum names and does not perform URL
 *       encoding.
 * </ul>
 *
 * @see FirstTimeWizardToadlet.WIZARD_PRESET
 */
public class PersistFields {

  /**
   * Optional wizard preset selected by the client, or {@code null} when absent or invalid.
   *
   * <p>When present, the value is parsed from the {@code preset} parameter/part using {@link
   * Enum#valueOf(Class, String)} semantics for {@link FirstTimeWizardToadlet.WIZARD_PRESET}.
   * Callers should treat {@code null} as “no usable preset selection was provided”.
   */
  public final FirstTimeWizardToadlet.WIZARD_PRESET preset;

  /**
   * Whether the wizard should configure the node for opennet mode.
   *
   * <p>This flag is parsed from {@code opennet} and defaults to {@code false} when not provided or
   * not interpretable as a boolean. The value is immutable after construction and is intended to be
   * forwarded across wizard steps and back into generated links.
   */
  public final boolean opennet;

  /**
   * Whether the wizard is being rendered as a single step rather than a multipage flow.
   *
   * <p>This flag is parsed from {@code singlestep} and defaults to {@code false} when absent or
   * invalid. It is used primarily for link generation and conditional UI behavior in the wizard
   * templates.
   */
  public final boolean singleStep;

  /**
   * Creates an instance by parsing persistence fields from the given request.
   *
   * <p>Parsing prefers query parameters (GET) when present, and otherwise reads request parts
   * (POST) via a failsafe accessor. Unknown presets are treated as “not set” ({@code null});
   * boolean fields default to {@code false} when missing or invalid. The resulting instance is
   * immutable and may be safely reused across threads.
   *
   * @param request request to parse for persistence fields; checks parameters (GET) first, then
   *     request parts (POST) as a fallback when parameters are not present
   */
  public PersistFields(HTTPRequest request) {
    this.preset = parsePreset(request);
    this.opennet = parseOpennet(request);
    this.singleStep = parseSingleStep(request);
  }

  /**
   * Creates an instance using an explicit opennet value and parsing the remaining fields.
   *
   * <p>This overload is useful when the caller has already decided the opennet setting (for
   * example, derived from server-side state) but still wants to preserve or accept other wizard
   * parameters from the incoming request. The {@code preset} and {@code singlestep} fields are
   * parsed using the same rules as {@link #PersistFields(HTTPRequest)}.
   *
   * @param opennet opennet mode to use; persisted as-is without further parsing
   * @param request request to parse for remaining persistence fields, specifically {@code preset}
   *     and {@code singlestep}
   */
  public PersistFields(boolean opennet, HTTPRequest request) {
    this.preset = parsePreset(request);
    this.opennet = opennet;
    this.singleStep = parseSingleStep(request);
  }

  /**
   * Creates an instance using an explicit preset value and parsing the remaining fields.
   *
   * <p>This overload is intended for call sites that want to force a specific wizard preset while
   * still honoring {@code opennet} and {@code singlestep} from the request. The {@code opennet} and
   * {@code singlestep} values default to {@code false} when not provided or invalid.
   *
   * @param preset preset to persist; may be {@code null} to indicate no preset is active
   * @param request request to parse for remaining persistence fields, specifically {@code opennet}
   *     and {@code singlestep}
   */
  public PersistFields(FirstTimeWizardToadlet.WIZARD_PRESET preset, HTTPRequest request) {
    this.preset = preset;
    this.opennet = parseOpennet(request);
    this.singleStep = parseSingleStep(request);
  }

  private FirstTimeWizardToadlet.WIZARD_PRESET parsePreset(HTTPRequest request) {
    String presetRaw;
    FirstTimeWizardToadlet.WIZARD_PRESET parsedPreset;

    if (request.hasParameters()) {
      presetRaw = request.getParam("preset");
    } else {
      presetRaw = request.getPartAsStringFailsafe("preset", 4);
    }

    try {
      parsedPreset = FirstTimeWizardToadlet.WIZARD_PRESET.valueOf(presetRaw);
    } catch (IllegalArgumentException e) {
      parsedPreset = null;
    }

    return parsedPreset;
  }

  private boolean parseOpennet(HTTPRequest request) {
    String opennetRaw;

    if (request.hasParameters()) {
      opennetRaw = request.getParam("opennet", "false");
    } else {
      opennetRaw = request.getPartAsStringFailsafe("opennet", 5);
    }

    return Fields.stringToBool(opennetRaw, false);
  }

  private boolean parseSingleStep(HTTPRequest request) {
    String singleStepRaw;

    if (request.hasParameters()) {
      singleStepRaw = request.getParam("singlestep", "false");
    } else {
      singleStepRaw = request.getPartAsStringFailsafe("singlestep", 5);
    }

    return Fields.stringToBool(singleStepRaw, false);
  }

  /**
   * Returns whether this instance carries a concrete wizard preset selection.
   *
   * <p>This is a convenience predicate for checking {@link #preset} against {@code null}. The value
   * is determined during construction based on the request contents (or caller-provided preset) and
   * is stable for the lifetime of the instance. Callers typically use this to decide whether to
   * include {@code preset} in generated links or whether to apply preset-derived defaults elsewhere
   * in the wizard flow.
   *
   * @return {@code true} when {@link #preset} is non-null and should be treated as active
   */
  public boolean isUsingPreset() {
    return preset != null;
  }

  /**
   * Returns whether the wizard should be rendered as a single-step flow.
   *
   * <p>This value is derived from the {@code singlestep} parameter/part and defaults to {@code
   * false} when missing or invalid. It is typically used when generating links that should preserve
   * the current wizard mode. The method has no side effects and is safe to call repeatedly.
   *
   * @return {@code true} if single-step mode is enabled for this request context
   */
  public boolean isSingleStep() {
    return singleStep;
  }

  /**
   * Appends any defined persistence fields to the given URL.
   *
   * <p>The returned URL always includes the {@code opennet} field. The {@code preset} field is only
   * included when {@link #isUsingPreset()} is {@code true}, and {@code singlestep} is only included
   * when {@link #isSingleStep()} is {@code true}. This method does not perform URL encoding; it
   * simply appends raw values using {@code &} separators, and therefore assumes the caller provides
   * a base URL that already contains a query string (or otherwise tolerates an extra {@code &}).
   *
   * <p>This operation is not idempotent with respect to repeated calls: invoking it multiple times
   * on the same base string will duplicate query parameters.
   *
   * @param baseURL base URL to append fields to; typically already includes a {@code ?} and at
   *     least one query parameter
   * @return a URL string with persistence fields appended using {@code &} separators
   */
  public String appendTo(String baseURL) {
    StringBuilder url = new StringBuilder(baseURL).append("&opennet=").append(opennet);
    if (isUsingPreset()) {
      url.append("&preset=").append(preset);
    }
    if (isSingleStep()) {
      url.append("&singlestep=").append(singleStep);
    }
    return url.toString();
  }
}
