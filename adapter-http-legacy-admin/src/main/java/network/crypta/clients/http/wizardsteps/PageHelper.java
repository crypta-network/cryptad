package network.crypta.clients.http.wizardsteps;

import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.clients.http.PageMaker.RenderParameters;
import network.crypta.clients.http.PageNode;
import network.crypta.clients.http.ToadletContext;
import network.crypta.support.HTMLNode;

/**
 * Helper for building First Time Wizard HTML pages.
 *
 * <p>This class centralizes common First Time Wizard page-building operations so individual wizard
 * steps can focus on their own content rather than the details of {@link ToadletContext}, {@link
 * network.crypta.clients.http.PageMaker}, and the persistence fields that need to flow between
 * steps. Typical usage is to construct one instance for a single step execution, call {@link
 * #getPageContent(String)} to obtain the content node, add any forms and infoboxes via {@link
 * #addFormChild(HTMLNode, String, String, boolean)} and {@link #getInfobox(String, String,
 * HTMLNode, String, boolean)}, and finally call {@link #generate()} to emit the HTML string.
 *
 * <p>The instance maintains a small amount of per-render state (the {@code PageNode} created by
 * {@link #getPageContent(String)}). Callers must treat it as single-use: {@link #getPageOuter()}
 * and {@link #generate()} require that {@link #getPageContent(String)} has already been called, and
 * the object is not intended to be shared across concurrent requests. The helper does not perform
 * any I/O itself; it delegates to the {@link ToadletContext} and page maker infrastructure.
 *
 * <ul>
 *   <li><b>Responsibilities:</b> create wizard-specific pages, provide common form helpers, and
 *       persist cross-step hidden fields.
 *   <li><b>Thread-safety:</b> not thread-safe; intended for a single step execution on one thread.
 * </ul>
 *
 * @see FirstTimeWizardToadlet
 * @see PersistFields
 */
public class PageHelper {

  private static final String TAG_INPUT = "input";
  private static final String ATTR_TYPE = "type";
  private static final String ATTR_NAME = "name";
  private static final String ATTR_VALUE = "value";
  private static final String TYPE_HIDDEN = "hidden";
  private static final String[] HIDDEN_INPUT_ATTRS = {ATTR_TYPE, ATTR_NAME, ATTR_VALUE};

  private final ToadletContext toadletContext;
  private final PersistFields persistFields;
  private final FirstTimeWizardToadlet.WIZARD_STEP step;
  private PageNode pageNode;

  /**
   * Creates a helper for rendering a single First Time Wizard step.
   *
   * <p>Callers typically construct a new instance each time a step is executed (for example, once
   * per request). The helper retains the passed-in context and persistence settings, and records
   * the step identifier that will later be embedded as a hidden form field. The instance also
   * tracks the {@code PageNode} created by {@link #getPageContent(String)} so that {@link
   * #getPageOuter()} and {@link #generate()} can operate without re-building the page.
   *
   * @param ctx request context used to create and render wizard page nodes; must be non-null
   * @param persistFields cross-step fields (for example preset/opennet mode) to persist into forms;
   *     must be non-null
   * @param step wizard step identifier to persist into generated forms for subsequent POST
   *     handling; must be non-null
   */
  public PageHelper(
      ToadletContext ctx, PersistFields persistFields, FirstTimeWizardToadlet.WIZARD_STEP step) {
    this.toadletContext = ctx;
    this.persistFields = persistFields;
    this.step = step;
  }

  /**
   * Creates a wizard page and returns the content node that callers can populate.
   *
   * <p>The returned {@link HTMLNode} is the body/content portion of the page. Wizard steps append
   * their text, form controls, and infoboxes to this node. The helper configures the page maker for
   * wizard usage (for example, by hiding status and navigation UI) and allows the title to be
   * chosen dynamically by the step at runtime.
   *
   * <p>This method stores the underlying {@link PageNode} in the helper for later use; call {@link
   * #getPageOuter()} if you need the full page node tree, or {@link #generate()} to render the
   * final HTML. Calling this method multiple times replaces the stored page node for this helper
   * instance.
   *
   * @param title page title displayed for the wizard step; typically a short human-readable string
   * @return content node for appending step-specific HTML elements and controls
   */
  public HTMLNode getPageContent(String title) {
    pageNode =
        toadletContext
            .getPageMaker()
            .getPageNode(
                title,
                toadletContext,
                new RenderParameters().renderNavigationLinks(false).renderStatus(false));
    return pageNode.getContentNode();
  }

  /**
   * Returns the outer HTML node for the page previously created by {@link #getPageContent(String)}.
   *
   * <p>The outer node represents the full page structure (including any wrapper elements created by
   * the page maker). Use this when a step needs access to the whole tree rather than only the
   * content node. If the caller only needs the rendered HTML string, {@link #generate()} is a more
   * direct option.
   *
   * @return outer node used to render the entire page, including page wrapper elements
   * @throws NullPointerException if {@link #getPageContent(String)} has not been called yet
   */
  public HTMLNode getPageOuter() {
    if (pageNode == null) {
      throw new NullPointerException(
          "pageNode was not initialized. getPageContent must be called first.");
    }
    return pageNode.getOuterNode();
  }

  /**
   * Renders the page created by {@link #getPageContent(String)} into an HTML string.
   *
   * <p>Wizard steps typically call this after populating the content node and adding any forms or
   * infoboxes. The returned string is intended to be written to the HTTP response by the caller.
   * This method does not mutate the content; it delegates to {@link PageNode#generate()} on the
   * stored node.
   *
   * @return rendered HTML for the complete wizard page
   * @throws NullPointerException if {@link #getPageContent(String)} has not been called yet
   */
  public String generate() {
    if (pageNode == null) {
      throw new NullPointerException(
          "pageNode was not initialized. getPageContent must be called first.");
    }
    return pageNode.generate();
  }

  /**
   * Creates an InfoBox element using the page maker associated with this helper's {@link
   * ToadletContext}.
   *
   * <p>Wizard steps commonly use InfoBoxes to present contextual guidance, warnings, or
   * confirmations near form controls. This method is a thin convenience wrapper that forwards all
   * arguments to the underlying page maker while keeping wizard steps decoupled from direct context
   * access.
   *
   * @param category InfoBox category or style key used by the page maker; typically determines CSS
   *     class or visual treatment
   * @param header short heading text displayed at the top of the InfoBox; may be empty but should
   *     be user-facing
   * @param parent parent node that will receive the generated InfoBox element; must be non-null and
   *     part of the current page tree
   * @param title additional title attribute or identifier passed through to the page maker; used
   *     for consistent labeling
   * @param isUnique whether the InfoBox should be marked as unique to avoid duplicates on the page
   * @return the created InfoBox node, which may be further populated by the caller
   */
  public HTMLNode getInfobox(
      String category, String header, HTMLNode parent, String title, boolean isUnique) {
    return toadletContext.getPageMaker().getInfobox(category, header, parent, title, isUnique);
  }

  /**
   * Adds a form node as a child of {@code parentNode} and persists standard wizard hidden fields.
   *
   * <p>This overload uses the default wizard behavior of including the opennet persistence field
   * when applicable. Use {@link #addFormChild(HTMLNode, String, String, boolean)} when a step needs
   * to explicitly suppress persistence of the opennet field (for example, on the opennet selection
   * step itself).
   *
   * @param parentNode node that will receive the {@code <form>} element; must be non-null
   * @param target action target URL that the form should POST to; must be non-null and relative to
   *     the current wizard flow
   * @param id HTML {@code id} attribute for the form element; used for styling and scripting hooks
   * @return form node to which inputs, buttons, and other children may be appended
   */
  public HTMLNode addFormChild(HTMLNode parentNode, String target, String id) {
    return addFormChild(parentNode, target, id, true);
  }

  /**
   * Adds a form node as a child of {@code parentNode} and persists inter-step wizard fields.
   *
   * <p>The helper ensures that commonly needed wizard state is carried forward as hidden input
   * fields. Currently, this includes the preset selection (when applicable), a single-step mode
   * flag (when applicable), the opennet selection (when requested), and the current step name. The
   * step name is used by the wizard POST handler to route the submission back to the correct
   * processing logic.
   *
   * <p>This method does not validate the values beyond serializing them into hidden input fields;
   * it assumes {@link PersistFields} and the current {@code step} reflect the wizard's state model.
   * The returned node is a live part of the page tree and can be populated with additional inputs
   * and buttons by the caller.
   *
   * @param parentNode node that will receive the {@code <form>} element; must be non-null
   * @param target action target URL that the form should POST to; must be non-null and stable for
   *     the current wizard step
   * @param id HTML {@code id} attribute for the form element; used for styling and scripting hooks
   * @param includeOpennet whether to include the persisted opennet field as a hidden input; false
   *     for steps that choose opennet mode
   * @return form node to which inputs, buttons, and other children may be appended
   */
  public HTMLNode addFormChild(
      HTMLNode parentNode, String target, String id, boolean includeOpennet) {
    HTMLNode form = toadletContext.addFormChild(parentNode, target, id);
    if (persistFields.isUsingPreset()) {
      form.addChild(
          TAG_INPUT,
          HIDDEN_INPUT_ATTRS,
          new String[] {TYPE_HIDDEN, "preset", persistFields.preset.name()});
    }
    if (persistFields.isSingleStep()) {
      form.addChild(
          TAG_INPUT, HIDDEN_INPUT_ATTRS, new String[] {TYPE_HIDDEN, "singlestep", "true"});
    }
    if (includeOpennet) {
      form.addChild(
          TAG_INPUT,
          HIDDEN_INPUT_ATTRS,
          new String[] {TYPE_HIDDEN, "opennet", String.valueOf(persistFields.opennet)});
    }
    form.addChild(TAG_INPUT, HIDDEN_INPUT_ATTRS, new String[] {TYPE_HIDDEN, "step", step.name()});
    return form;
  }
}
