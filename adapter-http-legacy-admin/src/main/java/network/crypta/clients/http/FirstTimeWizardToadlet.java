package network.crypta.clients.http;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.EnumMap;
import java.util.Objects;
import network.crypta.clients.http.wizardsteps.Bandwidth;
import network.crypta.clients.http.wizardsteps.BandwidthMonthly;
import network.crypta.clients.http.wizardsteps.BandwidthRate;
import network.crypta.clients.http.wizardsteps.BrowserWarning;
import network.crypta.clients.http.wizardsteps.DatastoreSize;
import network.crypta.clients.http.wizardsteps.Misc;
import network.crypta.clients.http.wizardsteps.NameSelection;
import network.crypta.clients.http.wizardsteps.Opennet;
import network.crypta.clients.http.wizardsteps.PageHelper;
import network.crypta.clients.http.wizardsteps.PersistFields;
import network.crypta.clients.http.wizardsteps.SecurityNetwork;
import network.crypta.clients.http.wizardsteps.SecurityPhysical;
import network.crypta.clients.http.wizardsteps.Step;
import network.crypta.clients.http.wizardsteps.Welcome;
import network.crypta.config.BooleanCallback;
import network.crypta.config.Config;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.l10n.NodeL10n;
import network.crypta.runtime.spi.FirstTimeWizardPort;
import network.crypta.runtime.spi.SecurityNetworkThreatLevel;
import network.crypta.runtime.spi.SecurityPhysicalThreatLevel;
import network.crypta.support.api.HTTPRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HTTP toadlet that guides a first-time user through configuring a Crypta node. The wizard
 * sequences a fixed set of UI steps, persists choices across page transitions, and applies
 * side-effecting actions (such as enabling auto-update) only when the relevant presets or form
 * controls are chosen. It is intentionally self-contained, so the launcher and embedded HTTP UI can
 * share identical onboarding logic.
 *
 * <p>The toadlet coordinates several step handlers, each responsible for rendering and validating a
 * portion of the workflow. Requests are stateless; the wizard rebuilds its flow from submitted form
 * parameters and redirects between steps instead of maintaining a server-side session state. The
 * remaining live daemon reads and writes flow through the injected {@link FirstTimeWizardPort}.
 *
 * <p>Concurrency: requests for the same user are serialized by the HTTP layer, but the class does
 * not assume single-threaded execution. All I/O and state changes are delegated to the injected
 * collaborators or configuration APIs, preserving thread safety. Callers should treat instances as
 * request-safe but not share mutable wizard state beyond the persisted form parameters. Typical
 * usage is to register this toadlet at {@link #TOADLET_URL} so the user is redirected there after
 * first launch.
 */
public class FirstTimeWizardToadlet extends Toadlet {
  private static final Logger LOG = LoggerFactory.getLogger(FirstTimeWizardToadlet.class);
  private final FirstTimeWizardPort wizardPort;
  private final EnumMap<WIZARD_STEP, Step> steps;
  private final Misc stepMISC;
  private final SecurityNetwork stepSecurityNetwork;
  private final SecurityPhysical stepSecurityPhysical;

  // Legacy Logger threshold callbacks removed; use LOG.isDebugEnabled() directly.

  /**
   * Lists every screen in the first-time wizard. The ordering matches the forward navigation flow
   * when no preset is selected; preset-specific shortcuts may skip some steps. Consumers should not
   * reorder entries because the wizard uses ordinal switching and explicit mappings to compute
   * redirects, backlinks, and preset behavior.
   */
  public enum WIZARD_STEP {
    /**
     * Landing page that introduces the wizard, summarizes the flow, and offers either preset
     * buttons or a manual setup path so the user can choose their comfort level before any settings
     * are touched.
     */
    WELCOME,
    /**
     * Browser warning step that cautions users about supported browsers, highlights the limits of
     * incognito mode, and prepares them for network-related redirects used in later steps.
     */
    BROWSER_WARNING,
    /** Miscellaneous settings step where users decide on auto-update behavior. */
    MISC,
    /**
     * Step asking whether the node should join opennet or remain darknet-only; this choice
     * influences later defaults for threat levels and determines whether certain steps can be
     * skipped.
     */
    OPENNET,
    /**
     * Security step that collects the desired network threat level, optionally prefilled by
     * presets, and writes the selection so routing and connection policies can be tuned before the
     * node starts serving traffic.
     */
    SECURITY_NETWORK,
    /**
     * Physical security step for local risk posture; may be skipped for preset-driven quick paths.
     */
    SECURITY_PHYSICAL,
    /**
     * Optional node name selection presented mainly for darknet mode to aid peer identification;
     * the wizard bypasses this when opennet is enabled because a public node name is unnecessary.
     */
    NAME_SELECTION,
    /**
     * Datastore sizing step that recommends or accepts a custom store size based on disk
     * heuristics, ensuring background storage tasks start with a sensible capacity ceiling.
     */
    DATASTORE_SIZE,
    /**
     * Bandwidth step capturing overall link speed selections; the values seed later caps and guide
     * defaults for rate shaping and monthly allotments.
     */
    BANDWIDTH,
    /**
     * Monthly bandwidth cap step allowing users to constrain transfer volume over a billing cycle.
     */
    BANDWIDTH_MONTHLY,
    /**
     * Upload/download rate step for finer grained throughput control in steady-state operation,
     * applied after the base bandwidth step to let users tune regular vs. bursty traffic.
     */
    BANDWIDTH_RATE,
    /**
     * Terminal pseudo-step that redirects the user to the home page once onboarding is done and the
     * node is ready for regular use.
     */
    COMPLETE // Redirects to the front page
  }

  /**
   * Preset bundles that adjust wizard defaults. Presets primarily change threat level and
   * auto-update settings while skipping intermediate screens to reduce friction. When no preset is
   * selected, the wizard executes the full manual flow and defers side effects until explicit form
   * submission.
   */
  public enum WIZARD_PRESET {
    /**
     * Low-security preset favoring convenience: enables opennet and auto-update while keeping
     * physical safeguards at normal levels. Intended for users who prioritize ease of use and
     * faster onboarding over restrictive defaults.
     */
    LOW,
    /**
     * High-security preset favoring privacy: disables opennet and tightens network threat levels.
     * Suited to users who want to minimize attack surface even if it requires more manual setup.
     */
    HIGH
  }

  FirstTimeWizardToadlet(Config config, FirstTimeWizardToadletRuntimePorts runtimePorts) {
    // Generic Toadlet-related initialization.
    super();
    FirstTimeWizardToadletRuntimePorts ports = Objects.requireNonNull(runtimePorts, "runtimePorts");
    wizardPort = ports.firstTimeWizardPort();

    addWizardConfiguration(config);

    // Add step handlers that presets don't set
    steps = new EnumMap<>(WIZARD_STEP.class);
    steps.put(WIZARD_STEP.WELCOME, new Welcome(config));
    steps.put(WIZARD_STEP.BROWSER_WARNING, new BrowserWarning());
    steps.put(WIZARD_STEP.NAME_SELECTION, new NameSelection(config));
    steps.put(WIZARD_STEP.DATASTORE_SIZE, new DatastoreSize(ports.firstTimeWizardPort(), config));
    steps.put(WIZARD_STEP.OPENNET, new Opennet());
    steps.put(WIZARD_STEP.BANDWIDTH, new Bandwidth());
    steps.put(
        WIZARD_STEP.BANDWIDTH_MONTHLY, new BandwidthMonthly(ports.firstTimeWizardPort(), config));
    steps.put(WIZARD_STEP.BANDWIDTH_RATE, new BandwidthRate(ports.firstTimeWizardPort(), config));

    // Add step handlers that presets set
    stepMISC = new Misc(config);
    steps.put(WIZARD_STEP.MISC, stepMISC);

    stepSecurityNetwork = new SecurityNetwork(wizardPort);
    steps.put(WIZARD_STEP.SECURITY_NETWORK, stepSecurityNetwork);

    stepSecurityPhysical = new SecurityPhysical(wizardPort);
    steps.put(WIZARD_STEP.SECURITY_PHYSICAL, stepSecurityPhysical);
  }

  /**
   * Base path where the wizard toadlet is mounted. External callers can redirect users here after
   * startup; the toadlet uses this constant when building internal step URLs to keep routing
   * consistent across deployments.
   */
  public static final String TOADLET_URL = "/wizard/";

  private void addWizardConfiguration(Config configuration) {
    SubConfig wizardConfiguration = configuration.createSubConfig("firstTimeWizard");
    wizardConfiguration.register(
        "enableAutoUpdater",
        true,
        new Option.Meta(
            0,
            true,
            false,
            "FirstTimeWizardToadlet.enableAutoUpdater",
            "FirstTimeWizardToadlet.enableAutoUpdaterLong"),
        createEnableAutoUpdaterCallback());
    enableAutoUpdater = wizardConfiguration.getBoolean("enableAutoUpdater");
    wizardConfiguration.finishedInitialization();
  }

  private boolean enableAutoUpdater;

  private BooleanCallback createEnableAutoUpdaterCallback() {
    return new BooleanCallback() {
      @Override
      public Boolean get() {
        return enableAutoUpdater;
      }

      @Override
      public void set(Boolean value) {
        enableAutoUpdater = value;
      }
    };
  }

  /**
   * Processes HTTP GET requests by rendering the requested wizard step or redirecting when guard
   * conditions require skipping ahead. The method validates access rights, normalizes the step
   * parameter, applies preset-driven shortcuts, and ensures required parameters such as opennet
   * flags are present before continuing. Responses are generated synchronously; any failure while
   * producing HTML results in a redirect to the internal error page, so users are not left on a
   * partial screen.
   *
   * @param uri request URI provided by the toadlet dispatcher; currently used only for context
   *     logging and may be relative or absolute.
   * @param request HTTP request containing query parameters that identify the current step and
   *     persisted wizard fields; must not be {@code null}.
   * @param ctx toadlet context responsible for permissions and response writing; expected to be a
   *     live connection.
   * @throws ToadletContextClosedException if the client disconnects while the response is being
   *     written.
   * @throws IOException if HTML generation or redirect writing fails.
   */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!ctx.checkFullAccess(this)) return;

    // Read the current step from the URL parameter, defaulting to the welcome page if unset or
    // invalid.
    WIZARD_STEP currentStep;
    try {
      currentStep = WIZARD_STEP.valueOf(request.getParam("step", WIZARD_STEP.WELCOME.toString()));
    } catch (IllegalArgumentException _) {
      currentStep = WIZARD_STEP.WELCOME;
    }

    PersistFields persistFields = new PersistFields(request);

    // Skip the browser warning page if using Chrome in incognito mode
    if (currentStep == WIZARD_STEP.BROWSER_WARNING && request.isChrome() && request.isIncognito()) {
      super.writeTemporaryRedirect(
          ctx, "Skipping unneeded warning", persistFields.appendTo(TOADLET_URL + "?step=MISC"));
      return;
    } else if (currentStep == WIZARD_STEP.MISC && persistFields.isUsingPreset()) {
      StringBuilder redirectBase = new StringBuilder(TOADLET_URL + "?step=");
      if (persistFields.preset == WIZARD_PRESET.HIGH) {
        redirectBase.append(
            "SECURITY_NETWORK&preset=HIGH&confirm=true&opennet=false&security-levels.networkThreatLevel=HIGH");
      } else {
        redirectBase.append("DATASTORE_SIZE&preset=LOW&opennet=true");
      }
      // addPersistFields() is not used here because the fields are overridden.
      super.writeTemporaryRedirect(ctx, "Skipping to next necessary step", redirectBase.toString());
      return;
    } else if (currentStep == WIZARD_STEP.SECURITY_NETWORK && !request.isParameterSet("opennet")) {
      // If opennet isn't defined when attempting to set network security level, ask again.
      super.writeTemporaryRedirect(
          ctx, "Need opennet choice", persistFields.appendTo(TOADLET_URL + "?step=OPENNET"));
      return;
    } else if (currentStep == WIZARD_STEP.NAME_SELECTION && wizardPort.isOpennetEnabled()) {
      // Skip node name selection if not in darknet mode.
      super.writeTemporaryRedirect(
          ctx,
          "Skip name selection",
          persistFields.appendTo(stepURL(WIZARD_STEP.DATASTORE_SIZE.name())));
      return;
    } else if (currentStep == WIZARD_STEP.COMPLETE) {
      super.writeTemporaryRedirect(ctx, "Wizard complete", LegacyHttpPaths.ROOT_PATH);
      return;
    }

    Step getStep = steps.get(currentStep);
    PageHelper helper = new PageHelper(ctx, persistFields, currentStep);
    getStep.getStep(request, helper);
    writeHTMLReply(ctx, 200, "OK", helper.generate());
  }

  /**
   * Indicates whether wizard components should emit minor debug-level events. This is a thin helper
   * around the shared logger, so step implementations do not repeat the {@link
   * Logger#isDebugEnabled()} check. Returning {@code false} discourages verbose logging during
   * normal operation, while a {@code true} value makes it safe to log granular state transitions
   * that aid troubleshooting without changing behavior.
   *
   * @return {@code true} when debug logging is enabled and steps may log fine-grained progress;
   *     otherwise {@code false} to minimize noise.
   */
  public static boolean shouldLogMinor() {
    return LOG.isDebugEnabled();
  }

  /**
   * Processes HTTP POST submissions for the wizard. The method normalizes the current step, routes
   * preset button presses through {@link #handlePresetSelection(HTTPRequest, ToadletContext)}, and
   * delegates form handling to the relevant step implementation. Redirect targets are calculated
   * eagerly to keep clients in a consistent flow even when optional fields are missing. Any IO or
   * context failures are surfaced immediately because partial application of wizard state is
   * undesirable.
   *
   * @param uri request URI provided by the toadlet dispatcher; not inspected for routing logic.
   * @param request HTTP request containing form fields submitted by the user; must include the
   *     current step identifier.
   * @param ctx toadlet context that mediates access checks and redirect writing; expected to remain
   *     open for the duration of processing.
   * @throws ToadletContextClosedException if the client disconnects before the redirect is sent.
   * @throws IOException if redirect responses cannot be written or step handlers encounter IO
   *     issues.
   */
  public void handleMethodPOST(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    Objects.requireNonNull(uri, "uri");
    if (!ctx.checkFullAccess(this)) return;

    WIZARD_STEP currentStep = parseCurrentStep(request);
    PersistFields persistFields = new PersistFields(request);

    if (isPresetSelection(currentStep, request)) {
      handlePresetSelection(request, ctx);
      return;
    }

    RedirectResult redirectResult;
    try {
      redirectResult = determineRedirect(currentStep, persistFields, request);
    } catch (IOException e) {
      writeInternalError(ctx, e);
      return;
    }

    persistFields = redirectResult.persistFields;
    super.writeTemporaryRedirect(
        ctx, "Wizard redirect", stepURL(persistFields.appendTo(redirectResult.target)));
  }

  private WIZARD_STEP parseCurrentStep(HTTPRequest request) {
    try {
      String currentValue = request.getPartAsStringFailsafe("step", 20);
      return currentValue.isEmpty() ? WIZARD_STEP.WELCOME : WIZARD_STEP.valueOf(currentValue);
    } catch (IllegalArgumentException _) {
      return WIZARD_STEP.WELCOME;
    }
  }

  private boolean isPresetSelection(WIZARD_STEP currentStep, HTTPRequest request) {
    return currentStep.equals(WIZARD_STEP.WELCOME)
        && (request.isPartSet("presetLow")
            || request.isPartSet("presetHigh")
            || request.isPartSet("presetNone"));
  }

  private void handlePresetSelection(HTTPRequest request, ToadletContext ctx)
      throws IOException, ToadletContextClosedException {
    StringBuilder redirectTo = new StringBuilder(TOADLET_URL + "?step=BROWSER_WARNING&incognito=");
    redirectTo.append(request.getPartAsStringFailsafe("incognito", 5));

    boolean presetLow = request.isPartSet("presetLow");
    boolean presetHigh = request.isPartSet("presetHigh");

    if (presetLow) {
      stepMISC.setAutoUpdate(enableAutoUpdater);
      stepSecurityNetwork.setThreatLevel(SecurityNetworkThreatLevel.LOW);
      stepSecurityPhysical.setThreatLevel(SecurityPhysicalThreatLevel.NORMAL);
      redirectTo.append("&preset=LOW&opennet=true");
    } else if (presetHigh) {
      stepMISC.setAutoUpdate(enableAutoUpdater);
      redirectTo.append("&preset=HIGH&opennet=false");
    }

    super.writeTemporaryRedirect(ctx, "Wizard set preset", redirectTo.toString());
  }

  private RedirectResult determineRedirect(
      WIZARD_STEP currentStep, PersistFields persistFields, HTTPRequest request)
      throws IOException {
    if (request.isPartSet("back")) {
      String redirectTarget =
          request.isPartSet("singlestep")
              ? WIZARD_STEP.COMPLETE.name()
              : getPreviousStep(currentStep, persistFields.preset).name();
      return new RedirectResult(redirectTarget, persistFields);
    }

    String redirectTarget = steps.get(currentStep).postStep(request);
    if (request.isPartSet("singlestep") && !redirectTarget.startsWith(currentStep.name())) {
      redirectTarget = WIZARD_STEP.COMPLETE.name();
    }

    if (currentStep == WIZARD_STEP.OPENNET) {
      return adjustForOpenNet(redirectTarget, persistFields);
    }

    return new RedirectResult(redirectTarget, persistFields);
  }

  private RedirectResult adjustForOpenNet(String redirectTarget, PersistFields persistFields) {
    try {
      HTTPRequest newRequest = new HTTPRequestImpl(new URI(stepURL(redirectTarget)), "GET");
      if (newRequest.isPartSet("opennet")) {
        PersistFields updatedPersist = new PersistFields(persistFields.preset, newRequest);
        return new RedirectResult(WIZARD_STEP.SECURITY_NETWORK.name(), updatedPersist);
      }
      return new RedirectResult(redirectTarget, persistFields);
    } catch (URISyntaxException e) {
      LOG.error("Unexpected invalid query string from OPENNET step! {}", e, e);
      return new RedirectResult(WIZARD_STEP.WELCOME.name(), persistFields);
    }
  }

  private void writeInternalError(ToadletContext ctx, IOException e)
      throws IOException, ToadletContextClosedException {
    String title;
    if ("cantWriteNewMasterKeysFile".equals(e.getMessage())) {
      title = NodeL10n.getBase().getString("SecurityLevels.cantWriteNewMasterKeysFileTitle");
    } else {
      title = NodeL10n.getBase().getString("Toadlet.internalErrorPleaseReport");
    }

    StringBuilder msg =
        new StringBuilder("<html><head><title>")
            .append(title)
            .append("</title></head><body><h1>")
            .append(title)
            .append("</h1><pre>");

    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    e.printStackTrace(pw);
    pw.flush();
    msg.append(sw).append("</pre>");

    Throwable internal = e.getCause();
    if (internal != null) {
      msg.append("<h1>")
          .append(NodeL10n.getBase().getString("Toadlet.internalErrorPleaseReport"))
          .append("</h1>")
          .append("<pre>");

      sw = new StringWriter();
      pw = new PrintWriter(sw);
      internal.printStackTrace(pw);
      pw.flush();
      msg.append(sw).append("</pre>");
    }
    msg.append("</body></html>");
    writeHTMLReply(ctx, 500, "Internal Error", msg.toString());
  }

  private record RedirectResult(String target, PersistFields persistFields) {}

  private String stepURL(String step) {
    return TOADLET_URL + "?step=" + step;
  }

  /**
   * Computes the previous wizard step given the current position and any preset in effect. The
   * method respects preset-specific jumps (for example, HIGH can skip directly from the security
   * pages back to the welcome screen) while maintaining the default linear ordering for manual
   * flows. {@code null} presets are treated as manual mode. This helper is side-effect-free and can
   * be used by both server logic and template code when building back buttons.
   *
   * @param currentStep step for which the caller needs the previous page; must not be {@code null}.
   * @param preset active preset that may change the navigation path; may be {@code null} to signal
   *     manual setup.
   * @return the step users should be sent to when navigating backward from {@code currentStep},
   *     defaulting to {@link WIZARD_STEP#WELCOME} when unknown.
   */
  public static WIZARD_STEP getPreviousStep(WIZARD_STEP currentStep, WIZARD_PRESET preset) {

    // Might be obvious, but still: No breaks needed in cases because their only contents are
    // returns.

    // First pages for the presets
    if (preset == WIZARD_PRESET.HIGH) {
      WIZARD_STEP previous =
          switch (currentStep) {
            case SECURITY_NETWORK, SECURITY_PHYSICAL -> WIZARD_STEP.WELCOME;
            default -> null;
          };
      if (previous != null) {
        return previous;
      }
    } else if (preset == WIZARD_PRESET.LOW
        && Objects.requireNonNull(currentStep) == WIZARD_STEP.DATASTORE_SIZE) {
      return WIZARD_STEP.WELCOME;
    }

    // Otherwise normal order.
    return switch (currentStep) {
      case MISC, BROWSER_WARNING -> WIZARD_STEP.WELCOME;
      case OPENNET -> WIZARD_STEP.MISC;
      case SECURITY_NETWORK -> WIZARD_STEP.OPENNET;
      case SECURITY_PHYSICAL -> WIZARD_STEP.SECURITY_NETWORK;
      case NAME_SELECTION -> WIZARD_STEP.SECURITY_PHYSICAL;
      case DATASTORE_SIZE -> WIZARD_STEP.NAME_SELECTION;
      case BANDWIDTH -> WIZARD_STEP.DATASTORE_SIZE;
      case BANDWIDTH_MONTHLY, BANDWIDTH_RATE -> WIZARD_STEP.BANDWIDTH;
      default ->
          // do nothing
          // Should be matched by this point, unknown step.
          WIZARD_STEP.WELCOME;
    };
  }

  /**
   * {@inheritDoc} This implementation always returns {@link #TOADLET_URL}, ensuring the wizard is
   * consistently mounted even when instantiated in different hosting environments. Downstream code
   * should rely on this constant rather than duplicating path literals to avoid divergence between
   * registration and redirect construction.
   *
   * @return canonical mount path for this toadlet, suitable for redirect targets and registration.
   */
  @Override
  public String path() {
    return TOADLET_URL;
  }
}
