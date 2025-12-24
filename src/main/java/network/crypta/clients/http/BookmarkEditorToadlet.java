package network.crypta.clients.http;

import static network.crypta.clients.http.QueueToadlet.MAX_KEY_LENGTH;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.util.List;
import java.util.Objects;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.bookmark.Bookmark;
import network.crypta.clients.http.bookmark.BookmarkCategory;
import network.crypta.clients.http.bookmark.BookmarkItem;
import network.crypta.clients.http.bookmark.BookmarkManager;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.NodeClientCore;
import network.crypta.support.HTMLNode;
import network.crypta.support.URLDecoder;
import network.crypta.support.URLEncodedFormatException;
import network.crypta.support.URLEncoder;
import network.crypta.support.api.HTTPRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Presents the interactive bookmark management endpoint exposed at {@code /bookmarkEditor/}.
 *
 * <p>This toadlet renders the full bookmark tree, exposes editing controls, and coordinates
 * create/update/delete and share operations through {@link BookmarkManager}. It keeps a minimal
 * amount of mutable state (the currently “cut” bookmark path) to mirror a desktop-like cut/paste
 * flow across requests. HTML responses are assembled with {@link PageMaker} and emitted directly to
 * the requesting {@link ToadletContext}. Typical usage involves invoking {@link #handleMethodGET}
 * to render the editor UI and {@link #handleMethodPOST} to process form submissions. The toadlet
 * avoids changing stored data unless the request passes {@link
 * ToadletContext#checkFullAccess(Toadlet)} or completes the relevant confirmation steps.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Rendering bookmark lists with per-item controls for editing, moving, cutting, and sharing.
 *   <li>Validating inputs (name length, path limits, key format) before mutating the bookmark
 *       store.
 *   <li>Persisting changes via {@link BookmarkManager#storeBookmarks()} and propagating shares to
 *       connected darknet peers when requested.
 * </ul>
 *
 * <p>The instance is not designed for concurrent reuse: request handlers mutate {@code cutedPath}
 * to track clipboard state, so callers should ensure per-request isolation. All other operations
 * are delegated to thread-safe components owned by the surrounding node.
 */
public class BookmarkEditorToadlet extends Toadlet {
  private static final Logger LOG = LoggerFactory.getLogger(BookmarkEditorToadlet.class);
  private static final int MAX_ACTION_LENGTH = 20;
  private static final String ATTRIBUTE_CLASS = "class";
  private static final String ATTRIBUTE_TITLE = "title";
  private static final String ACTIONS_CLASS = "actions";
  private static final String SHARE_L10N_KEY = "BookmarkEditorToadlet.share";
  private static final String BOOKMARK_ERROR_ID = "bookmark-error";
  private static final String INFOBOX_SUCCESS = "infobox-success";
  private static final String PARAM_BOOKMARK = "bookmark";
  private static final String PARAM_ACTION = "action";
  private static final String INFOBOX_NORMAL = "infobox-normal";
  private static final String PARAM_ADD_DEFAULT = "AddDefaultBookmarks";
  private static final String TAG_INPUT = "input";
  private static final String ATTR_VALUE = "value";
  private static final String INPUT_SUBMIT = "submit";
  private static final String INPUT_HIDDEN = "hidden";
  private static final String TAG_LABEL = "label";
  private static final String ACTION_ADD_ITEM = "addItem";
  private static final String ACTION_ADD_CAT = "addCat";
  private static final String ACTION_SHARE = "share";
  private static final String ACTION_PASTE = "paste";
  private static final String INFOBOX_ERROR = "infobox-error";
  private static final String ACTION_QUERY_PREFIX = "?action=";
  private static final String BOOKMARK_QUERY_PARAM = "&bookmark=";
  private static final String DESC_FIELD = "descB";
  private static final String TEXTAREA = "textarea";
  private static final String EXPLAIN_FIELD = "explain";
  private static final String ACTIVE_LINK_FIELD = "hasAnActivelink";
  private static final String CHECKBOX = "checkbox";
  private static final String PUBLIC_DESC_FIELD = "publicDescB";
  private static final String ACTION_CANCEL_CUT = "cancelCut";

  private record ActionLabels(
      String edit,
      String delete,
      String cut,
      String moveUp,
      String moveDown,
      String paste,
      String addBookmark,
      String addCategory,
      boolean hasFriends) {}

  private record GetContext(
      PageMaker pageMaker,
      BookmarkManager bookmarkManager,
      HTMLNode content,
      HTTPRequest req,
      ToadletContext ctx,
      PageNode page,
      String error) {}

  private record PostContext(
      PageMaker pageMaker,
      BookmarkManager bookmarkManager,
      HTMLNode content,
      ToadletContext ctx,
      PageNode page) {}

  /** Max. bookmark name length */
  private static final int MAX_NAME_LENGTH = 500;

  /**
   * Max. bookmark path length (e.g. <code>
   * Freenet related software and documentation/Freenet Message System</code> )
   */
  private static final int MAX_BOOKMARK_PATH_LENGTH = 10 * MAX_NAME_LENGTH;

  private static final int MAX_EXPLANATION_LENGTH = 1024;

  private final NodeClientCore core;
  private String cutedPath;

  // Legacy Logger threshold callbacks removed; use LOG.isDebugEnabled() directly.

  BookmarkEditorToadlet(HighLevelSimpleClient client, NodeClientCore core) {
    super(client);
    this.core = core;
    this.cutedPath = null;
  }

  /** Get all bookmark as a tree of &lt;li&gt;...&lt;/li&gt;s */
  private void addCategoryToList(
      BookmarkCategory cat, String path, HTMLNode list, BookmarkManager bookmarkManager) {
    ActionLabels labels =
        new ActionLabels(
            NodeL10n.getBase().getString("BookmarkEditorToadlet.edit"),
            NodeL10n.getBase().getString("BookmarkEditorToadlet.delete"),
            NodeL10n.getBase().getString("BookmarkEditorToadlet.cut"),
            NodeL10n.getBase().getString("BookmarkEditorToadlet.moveUp"),
            NodeL10n.getBase().getString("BookmarkEditorToadlet.moveDown"),
            NodeL10n.getBase().getString("BookmarkEditorToadlet.paste"),
            NodeL10n.getBase().getString("BookmarkEditorToadlet.addBookmark"),
            NodeL10n.getBase().getString("BookmarkEditorToadlet.addCategory"),
            core.getNode().getDarknetConnections().length > 0);
    List<BookmarkItem> items = cat.getItems();
    for (int i = 0; i < items.size(); i++) {
      addBookmarkItemToList(items, path, list, labels, i);
    }

    List<BookmarkCategory> cats = cat.getSubCategories();
    for (int i = 0; i < cats.size(); i++) {
      addBookmarkCategoryToList(bookmarkManager, path, list, labels, cats, i);
    }
  }

  private void addBookmarkItemToList(
      List<BookmarkItem> items, String path, HTMLNode list, ActionLabels labels, int index) {
    BookmarkItem item = items.get(index);

    String itemPath = URLEncoder.encode(path + item.getName(), false);
    HTMLNode li = new HTMLNode("li", ATTRIBUTE_CLASS, "item", item.getVisibleName());
    String explain = item.getShortDescription();
    if (explain != null && !explain.isEmpty()) {
      li.addChild("#", " (");
      li.addChild("#", explain);
      li.addChild("#", ")");
    }

    HTMLNode actions = new HTMLNode("span", ATTRIBUTE_CLASS, ACTIONS_CLASS);
    actions
        .addChild("a", "href", buildActionHref("edit", itemPath))
        .addChild(
            "img",
            new String[] {"src", "alt", ATTRIBUTE_TITLE},
            new String[] {"/static/icon/edit.png", labels.edit(), labels.edit()});

    actions
        .addChild("a", "href", buildActionHref("del", itemPath))
        .addChild(
            "img",
            new String[] {"src", "alt", ATTRIBUTE_TITLE},
            new String[] {"/static/icon/delete.png", labels.delete(), labels.delete()});

    if (cutedPath == null) {
      actions
          .addChild("a", "href", buildActionHref("cut", itemPath))
          .addChild(
              "img",
              new String[] {"src", "alt", ATTRIBUTE_TITLE},
              new String[] {"/static/icon/cut.png", labels.cut(), labels.cut()});
    }

    if (index != 0) {
      actions
          .addChild("a", "href", buildActionHref("up", itemPath))
          .addChild(
              "img",
              new String[] {"src", "alt", ATTRIBUTE_TITLE},
              new String[] {"/static/icon/go-up.png", labels.moveUp(), labels.moveUp()});
    }

    if (index != items.size() - 1) {
      actions
          .addChild("a", "href", buildActionHref("down", itemPath))
          .addChild(
              "img",
              new String[] {"src", "alt", ATTRIBUTE_TITLE},
              new String[] {"/static/icon/go-down.png", labels.moveDown(), labels.moveDown()});
    }

    if (labels.hasFriends()) {
      actions.addChild(
          "a",
          "href",
          buildActionHref(ACTION_SHARE, itemPath),
          NodeL10n.getBase().getString(SHARE_L10N_KEY));
    }

    li.addChild(actions);
    list.addChild(li);
  }

  private void addBookmarkCategoryToList(
      BookmarkManager bookmarkManager,
      String path,
      HTMLNode list,
      ActionLabels labels,
      List<BookmarkCategory> cats,
      int index) {
    String catPath = path + cats.get(index).getName() + '/';
    String catPathEncoded = URLEncoder.encode(catPath, false);

    HTMLNode subCat = list.addChild("li", ATTRIBUTE_CLASS, "cat", cats.get(index).getVisibleName());

    HTMLNode actions = new HTMLNode("span", ATTRIBUTE_CLASS, ACTIONS_CLASS);

    actions
        .addChild("a", "href", buildActionHref("edit", catPathEncoded))
        .addChild(
            "img",
            new String[] {"src", "alt", ATTRIBUTE_TITLE},
            new String[] {"/static/icon/edit.png", labels.edit(), labels.edit()});

    actions
        .addChild("a", "href", buildActionHref("del", catPathEncoded))
        .addChild(
            "img",
            new String[] {"src", "alt", ATTRIBUTE_TITLE},
            new String[] {"/static/icon/delete.png", labels.delete(), labels.delete()});

    actions
        .addChild("a", "href", buildActionHref(ACTION_ADD_ITEM, catPathEncoded))
        .addChild(
            "img",
            new String[] {"src", "alt", ATTRIBUTE_TITLE},
            new String[] {
              "/static/icon/bookmark-new.png", labels.addBookmark(), labels.addBookmark()
            });

    actions
        .addChild("a", "href", buildActionHref(ACTION_ADD_CAT, catPathEncoded))
        .addChild(
            "img",
            new String[] {"src", "alt", ATTRIBUTE_TITLE},
            new String[] {
              "/static/icon/folder-new.png", labels.addCategory(), labels.addCategory()
            });

    if (cutedPath == null) {
      actions
          .addChild("a", "href", buildActionHref("cut", catPathEncoded))
          .addChild(
              "img",
              new String[] {"src", "alt", ATTRIBUTE_TITLE},
              new String[] {"/static/icon/cut.png", labels.cut(), labels.cut()});
    }

    if (index != 0) {
      actions
          .addChild("a", "href", buildActionHref("up", catPathEncoded))
          .addChild(
              "img",
              new String[] {"src", "alt", ATTRIBUTE_TITLE},
              new String[] {"/static/icon/go-up.png", labels.moveUp(), labels.moveUp()});
    }

    if (index != cats.size() - 1) {
      actions
          .addChild("a", "href", buildActionHref("down", catPathEncoded))
          .addChild(
              "img",
              new String[] {"src", "alt", ATTRIBUTE_TITLE},
              new String[] {"/static/icon/go-down.png", labels.moveDown(), labels.moveDown()});
    }

    if (cutedPath != null
        && !catPathEncoded.startsWith(cutedPath)
        && !catPathEncoded.equals(bookmarkManager.parentPath(cutedPath))) {
      actions
          .addChild("a", "href", buildActionHref(ACTION_PASTE, catPathEncoded))
          .addChild(
              "img",
              new String[] {"src", "alt", ATTRIBUTE_TITLE},
              new String[] {"/static/icon/paste.png", labels.paste(), labels.paste()});
    }

    subCat.addChild(actions);
    if (cats.get(index).size() != 0)
      addCategoryToList(
          cats.get(index), catPath, list.addChild("li").addChild("ul"), bookmarkManager);
  }

  private String buildActionHref(String action, String bookmarkPath) {
    return ACTION_QUERY_PREFIX + action + BOOKMARK_QUERY_PARAM + bookmarkPath;
  }

  private void sendBookmarkFeeds(HTTPRequest req, BookmarkItem item, String publicDescription) {
    for (DarknetPeerNode peer : core.getNode().getDarknetConnections())
      if (req.isPartSet("node_" + peer.hashCode()))
        peer.sendBookmarkFeed(
            item.getURI(), item.getName(), publicDescription, item.hasAnActivelink());
  }

  private HTMLNode getBookmarksList(BookmarkManager bookmarkManager) {
    HTMLNode bookmarks = new HTMLNode("ul", "id", "bookmarks");

    HTMLNode root = bookmarks.addChild("li", ATTRIBUTE_CLASS, "cat root", "/");
    HTMLNode actions = new HTMLNode("span", ATTRIBUTE_CLASS, ACTIONS_CLASS);
    String addBookmark = NodeL10n.getBase().getString("BookmarkEditorToadlet.addBookmark");
    String addCategory = NodeL10n.getBase().getString("BookmarkEditorToadlet.addCategory");
    String paste = NodeL10n.getBase().getString("BookmarkEditorToadlet.paste");
    actions
        .addChild("a", "href", buildActionHref(ACTION_ADD_ITEM, "/"))
        .addChild(
            "img",
            new String[] {"src", "alt", ATTRIBUTE_TITLE},
            new String[] {"/static/icon/bookmark-new.png", addBookmark, addBookmark});
    actions
        .addChild("a", "href", buildActionHref(ACTION_ADD_CAT, "/"))
        .addChild(
            "img",
            new String[] {"src", "alt", ATTRIBUTE_TITLE},
            new String[] {"/static/icon/folder-new.png", addCategory, addCategory});

    if (cutedPath != null && !"/".equals(bookmarkManager.parentPath(cutedPath)))
      actions
          .addChild("a", "href", buildActionHref(ACTION_PASTE, "/"))
          .addChild(
              "img",
              new String[] {"src", "alt", ATTRIBUTE_TITLE},
              new String[] {"/static/icon/paste.png", paste, paste});

    root.addChild(actions);
    addCategoryToList(BookmarkManager.MAIN_CATEGORY, "/", root.addChild("ul"), bookmarkManager);

    return bookmarks;
  }

  /**
   * Handles GET requests for the bookmark editor page, rendering the current tree and any pending
   * action forms.
   *
   * <p>The method enforces full-access checks, decodes and validates the requested bookmark path,
   * dispatches lightweight actions (move, cut, paste, delete confirmation, edit/share forms), and
   * finally emits an HTML page containing the bookmark list plus auxiliary controls such as the
   * “Add default bookmarks” button. Responses are written directly to the provided {@link
   * ToadletContext}, and no storage mutation occurs unless an action explicitly requires it (for
   * example, moving a bookmark up/down).
   *
   * @param uri request target URI; only the path is relevant and must match {@link #path()}.
   * @param req HTTP request containing query parameters such as {@code action} and {@code
   *     bookmark}; parameters should already be decoded to UTF-8 semantics.
   * @param ctx toadlet context providing access control, page construction helpers, and bookmark
   *     management for the current session.
   * @throws ToadletContextClosedException if the connection closes before the response finishes
   *     writing; callers should treat this as a non-fatal interruption.
   * @throws IOException if underlying I/O (typically response writing) fails while generating the
   *     HTML page.
   */
  public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!ctx.checkFullAccess(this)) return;

    PageMaker pageMaker = ctx.getPageMaker();
    BookmarkManager bookmarkManager = ctx.getBookmarkManager();
    String editorTitle = NodeL10n.getBase().getString("BookmarkEditorToadlet.title");
    PageNode page = pageMaker.getPageNode(editorTitle, ctx);
    HTMLNode content = page.getContentNode();
    String error = NodeL10n.getBase().getString("BookmarkEditorToadlet.error");
    String originalBookmark = req.getParam(PARAM_BOOKMARK);
    GetContext getCtx = new GetContext(pageMaker, bookmarkManager, content, req, ctx, page, error);
    if (!req.getParam(PARAM_ACTION).isEmpty()
        && !originalBookmark.isEmpty()
        && handleGetAction(req.getParam(PARAM_ACTION), originalBookmark, getCtx)) {
      return;
    }

    addCutInfoBox(pageMaker, content, ctx);

    pageMaker
        .getInfobox(
            INFOBOX_NORMAL,
            NodeL10n.getBase().getString("BookmarkEditorToadlet.myBookmarksTitle"),
            content,
            "bookmark-title",
            false)
        .addChild(getBookmarksList(bookmarkManager));

    HTMLNode addDefaultBookmarksForm = ctx.addFormChild(content, "", PARAM_ADD_DEFAULT);
    addDefaultBookmarksForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {
          INPUT_SUBMIT,
          PARAM_ADD_DEFAULT,
          NodeL10n.getBase().getString("BookmarkEditorToadlet.addDefaultBookmarks")
        });

    if (LOG.isTraceEnabled()) LOG.trace("Returning:\n{}", page.generate());

    this.writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private boolean handleGetAction(String action, String originalBookmark, GetContext ctx)
      throws ToadletContextClosedException, IOException {
    String bookmarkPath = decodeBookmarkPath(originalBookmark, ctx);
    if (bookmarkPath == null) {
      return true;
    }
    Bookmark bookmark = getBookmarkFromPath(ctx.bookmarkManager(), bookmarkPath);

    if (bookmark == null) {
      showMissingBookmarkError(ctx, bookmarkPath);
      return true;
    }
    switch (action) {
      case "del" ->
          addDeleteConfirmation(ctx.pageMaker(), ctx.content(), bookmark, bookmarkPath, ctx.ctx());
      case "cut" -> cutedPath = bookmarkPath;
      case ACTION_PASTE -> handlePasteAction(ctx.bookmarkManager(), bookmarkPath);
      case "edit", ACTION_ADD_ITEM, ACTION_ADD_CAT, ACTION_SHARE ->
          addEditOrShareForm(
              action, bookmark, bookmarkPath, ctx.pageMaker(), ctx.content(), ctx.req(), ctx.ctx());
      case "up" -> ctx.bookmarkManager().moveBookmarkUp(bookmarkPath, true);
      case "down" -> ctx.bookmarkManager().moveBookmarkDown(bookmarkPath, true);
      default -> {
        // nothing to do
      }
    }
    return false;
  }

  private String decodeBookmarkPath(String originalBookmark, GetContext ctx)
      throws ToadletContextClosedException, IOException {
    try {
      return URLDecoder.decode(originalBookmark, false);
    } catch (URLEncodedFormatException _) {
      ctx.pageMaker()
          .getInfobox(INFOBOX_ERROR, ctx.error(), ctx.content(), "bookmark-url-decode-error", false)
          .addChild("#", NodeL10n.getBase().getString("BookmarkEditorToadlet.urlDecodeError"));
      writeHTMLReply(ctx.ctx(), 200, "OK", ctx.page().generate());
      return null;
    }
  }

  private Bookmark getBookmarkFromPath(BookmarkManager bookmarkManager, String bookmarkPath) {
    if (bookmarkPath.endsWith("/")) {
      return bookmarkManager.getCategoryByPath(bookmarkPath);
    }
    return bookmarkManager.getItemByPath(bookmarkPath);
  }

  private void showMissingBookmarkError(GetContext ctx, String bookmarkPath)
      throws ToadletContextClosedException, IOException {
    ctx.pageMaker()
        .getInfobox(INFOBOX_ERROR, ctx.error(), ctx.content(), "bookmark-does-not-exist", false)
        .addChild(
            "#",
            NodeL10n.getBase()
                .getString(
                    "BookmarkEditorToadlet.bookmarkDoesNotExist",
                    new String[] {PARAM_BOOKMARK},
                    new String[] {bookmarkPath}));
    this.writeHTMLReply(ctx.ctx(), 200, "OK", ctx.page().generate());
  }

  private void addDeleteConfirmation(
      PageMaker pageMaker,
      HTMLNode content,
      Bookmark bookmark,
      String bookmarkPath,
      ToadletContext ctx) {
    String[] bm = new String[] {PARAM_BOOKMARK};
    String[] path = new String[] {bookmarkPath};
    String queryTitle =
        NodeL10n.getBase()
            .getString(
                "BookmarkEditorToadlet."
                    + ((bookmark instanceof BookmarkItem) ? "deleteBookmark" : "deleteCategory"));
    HTMLNode infoBoxContent =
        pageMaker.getInfobox("infobox-query", queryTitle, content, "bookmark-delete", false);

    String query =
        NodeL10n.getBase()
            .getString(
                "BookmarkEditorToadlet."
                    + ((bookmark instanceof BookmarkItem)
                        ? "deleteBookmarkConfirm"
                        : "deleteCategoryConfirm"),
                bm,
                path);
    infoBoxContent.addChild("p").addChild("#", query);

    HTMLNode confirmForm = ctx.addFormChild(infoBoxContent, "", "confirmDeleteForm");
    confirmForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {INPUT_HIDDEN, PARAM_BOOKMARK, bookmarkPath});
    confirmForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {INPUT_SUBMIT, "cancel", NodeL10n.getBase().getString("Toadlet.cancel")});
    confirmForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {
          INPUT_SUBMIT,
          "confirmdelete",
          NodeL10n.getBase().getString("BookmarkEditorToadlet.confirmDelete")
        });
  }

  private void handlePasteAction(BookmarkManager bookmarkManager, String bookmarkPath) {
    if (cutedPath == null) {
      return;
    }
    bookmarkManager.moveBookmark(cutedPath, bookmarkPath);
    bookmarkManager.storeBookmarks();
    cutedPath = null;
  }

  private void addEditOrShareForm(
      String action,
      Bookmark bookmark,
      String bookmarkPath,
      PageMaker pageMaker,
      HTMLNode content,
      HTTPRequest req,
      ToadletContext ctx) {
    boolean isNew = ACTION_ADD_ITEM.equals(action) || ACTION_ADD_CAT.equals(action);
    String header = resolveHeader(action, bookmark);

    HTMLNode actionBoxContent =
        pageMaker.getInfobox("infobox-query", header, content, "bookmark-action", false);

    HTMLNode form = ctx.addFormChild(actionBoxContent, "", "editBookmarkForm");
    addNameField(form, isNew, bookmark);
    addItemSectionIfNeeded(action, isNew, bookmark, form);
    addShareSectionIfNeeded(action, isNew, bookmark, form);

    addHiddenFields(form, bookmarkPath, req.getParam(PARAM_ACTION));
    addSubmitButton(form, action);
  }

  private String resolveHeader(String action, Bookmark bookmark) {
    return switch (action) {
      case "edit" ->
          NodeL10n.getBase()
              .getString(
                  "BookmarkEditorToadlet.edit"
                      + ((bookmark instanceof BookmarkItem) ? "Bookmark" : "Category")
                      + "Title");
      case ACTION_ADD_ITEM -> NodeL10n.getBase().getString("BookmarkEditorToadlet.addNewBookmark");
      case ACTION_SHARE -> NodeL10n.getBase().getString(SHARE_L10N_KEY);
      default -> NodeL10n.getBase().getString("BookmarkEditorToadlet.addNewCategory");
    };
  }

  private void addNameField(HTMLNode form, boolean isNew, Bookmark bookmark) {
    form.addChild(
        TAG_LABEL,
        "for",
        "name",
        (NodeL10n.getBase().getString("BookmarkEditorToadlet.nameLabel") + ' '));
    form.addChild(
        TAG_INPUT,
        new String[] {"type", "id", "name", "size", ATTR_VALUE},
        new String[] {"text", "name", "name", "20", !isNew ? bookmark.getVisibleName() : ""});
    form.addChild("br");
  }

  private void addItemSectionIfNeeded(
      String action, boolean isNew, Bookmark bookmark, HTMLNode form) {
    if (!requiresItemSection(action, bookmark)) {
      return;
    }
    BookmarkItem item = isNew ? null : (BookmarkItem) bookmark;
    String key = !isNew ? item.getKey() : "";
    form.addChild(
        TAG_LABEL,
        "for",
        "key",
        (NodeL10n.getBase().getString("BookmarkEditorToadlet.keyLabel") + ' '));
    form.addChild(
        TAG_INPUT,
        new String[] {"type", "id", "name", "size", ATTR_VALUE},
        new String[] {"text", "key", "key", "50", key});
    form.addChild("br");
    if ("edit".equals(action) || ACTION_ADD_ITEM.equals(action)) {
      addDescriptions(form, isNew, item);
    }
    addActiveLinkField(form, isNew, item);
  }

  private boolean requiresItemSection(String action, Bookmark bookmark) {
    return ("edit".equals(action) && bookmark instanceof BookmarkItem)
        || ACTION_ADD_ITEM.equals(action)
        || ACTION_SHARE.equals(action);
  }

  private void addDescriptions(HTMLNode form, boolean isNew, BookmarkItem item) {
    form.addChild(
        TAG_LABEL,
        "for",
        DESC_FIELD,
        (NodeL10n.getBase().getString("BookmarkEditorToadlet.descLabel") + ' '));
    form.addChild("br");
    form.addChild(
        TEXTAREA,
        new String[] {"id", "name", "row", "cols"},
        new String[] {DESC_FIELD, DESC_FIELD, "3", "70"},
        (isNew ? "" : item.getDescription()));
    form.addChild("br");
    form.addChild(
        TAG_LABEL,
        "for",
        DESC_FIELD,
        (NodeL10n.getBase().getString("BookmarkEditorToadlet.explainLabel") + ' '));
    form.addChild("br");
    form.addChild(
        TEXTAREA,
        new String[] {"id", "name", "row", "cols"},
        new String[] {EXPLAIN_FIELD, EXPLAIN_FIELD, "3", "70"},
        (isNew ? "" : item.getShortDescription()));
    form.addChild("br");
  }

  private void addActiveLinkField(HTMLNode form, boolean isNew, BookmarkItem item) {
    form.addChild(
        TAG_LABEL,
        "for",
        ACTIVE_LINK_FIELD,
        (NodeL10n.getBase().getString("BookmarkEditorToadlet.hasAnActivelinkLabel") + ' '));
    if (!isNew && item.hasAnActivelink()) {
      form.addChild(
          TAG_INPUT,
          new String[] {"type", "id", "name", "checked"},
          new String[] {
            CHECKBOX, ACTIVE_LINK_FIELD, ACTIVE_LINK_FIELD, String.valueOf(item.hasAnActivelink())
          });
    } else {
      form.addChild(
          TAG_INPUT,
          new String[] {"type", "id", "name"},
          new String[] {CHECKBOX, ACTIVE_LINK_FIELD, ACTIVE_LINK_FIELD});
    }
  }

  private void addShareSectionIfNeeded(
      String action, boolean isNew, Bookmark bookmark, HTMLNode form) {
    if (!shouldDisplayShareSection(action)) {
      return;
    }
    BookmarkItem item = isNew ? null : (BookmarkItem) bookmark;
    form.addChild("br");
    form.addChild("br");
    if (core.getNode().isFProxyJavascriptEnabled()) {
      form.addChild(
          "script",
          new String[] {"type", "src"},
          new String[] {"text/javascript", "/static/js/checkall.js"});
    }
    HTMLNode peerTable = form.addChild("table", ATTRIBUTE_CLASS, "darknet_connections");
    addPeerTableHeader(peerTable);
    for (DarknetPeerNode peer : core.getNode().getDarknetConnections()) {
      HTMLNode peerRow = peerTable.addChild("tr", ATTRIBUTE_CLASS, "darknet_connections_normal");
      peerRow
          .addChild("td", ATTRIBUTE_CLASS, "peer-marker")
          .addChild(
              TAG_INPUT,
              new String[] {"type", "name"},
              new String[] {CHECKBOX, "node_" + peer.hashCode()});
      peerRow.addChild("td", ATTRIBUTE_CLASS, "peer-name").addChild("#", peer.getName());
    }
    form.addChild(
        TAG_LABEL,
        "for",
        DESC_FIELD,
        (NodeL10n.getBase().getString("BookmarkEditorToadlet.publicDescLabel") + ' '));
    form.addChild("br");
    form.addChild(
        TEXTAREA,
        new String[] {"id", "name", "row", "cols"},
        new String[] {DESC_FIELD, PUBLIC_DESC_FIELD, "3", "70"},
        (isNew ? "" : item.getDescription()));
    form.addChild("br");
  }

  private void addPeerTableHeader(HTMLNode peerTable) {
    if (core.getNode().isFProxyJavascriptEnabled()) {
      HTMLNode headerRow = peerTable.addChild("tr");
      headerRow
          .addChild("th")
          .addChild(
              TAG_INPUT,
              new String[] {"type", "onclick"},
              new String[] {CHECKBOX, "checkAll(this, 'darknet_connections')"});
      headerRow.addChild("th", NodeL10n.getBase().getString("QueueToadlet.recommendToFriends"));
    } else {
      peerTable
          .addChild("tr")
          .addChild(
              "th",
              "colspan",
              "2",
              NodeL10n.getBase().getString("QueueToadlet.recommendToFriends"));
    }
  }

  private boolean shouldDisplayShareSection(String action) {
    return core.getNode().getDarknetConnections().length > 0
        && (ACTION_ADD_ITEM.equals(action) || ACTION_SHARE.equals(action));
  }

  private void addHiddenFields(HTMLNode form, String bookmarkPath, String action) {
    form.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {INPUT_HIDDEN, PARAM_BOOKMARK, bookmarkPath});

    form.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {INPUT_HIDDEN, PARAM_ACTION, action});
  }

  private void addSubmitButton(HTMLNode form, String action) {
    form.addChild(
        TAG_INPUT,
        new String[] {"type", ATTR_VALUE},
        new String[] {
          INPUT_SUBMIT,
          ACTION_SHARE.equals(action)
              ? NodeL10n.getBase().getString(SHARE_L10N_KEY)
              : NodeL10n.getBase().getString("BookmarkEditorToadlet.save")
        });
  }

  private void addCutInfoBox(PageMaker pageMaker, HTMLNode content, ToadletContext ctx) {
    if (cutedPath == null) {
      return;
    }
    HTMLNode infoBoxContent =
        pageMaker.getInfobox(
            INFOBOX_NORMAL,
            NodeL10n.getBase().getString("BookmarkEditorToadlet.pasteTitle"),
            content,
            null,
            false);
    infoBoxContent.addChild(
        "#", NodeL10n.getBase().getString("BookmarkEditorToadlet.pasteOrCancel"));
    HTMLNode cancelForm = ctx.addFormChild(infoBoxContent, "/bookmarkEditor/", "cancelCutForm");
    cancelForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {
          INPUT_SUBMIT,
          ACTION_CANCEL_CUT,
          NodeL10n.getBase().getString("BookmarkEditorToadlet.cancelCut")
        });
    cancelForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {INPUT_HIDDEN, PARAM_ACTION, ACTION_CANCEL_CUT});
  }

  /**
   * Processes POST submissions from the bookmark editor forms, applying mutations and redirects as
   * needed.
   *
   * <p>The handler normalizes and validates the submitted bookmark path, routes the request to
   * deletion, cut/cancel, edit, add, or share flows, persists any resulting changes through the
   * {@link BookmarkManager}, and optionally triggers bookmark feed notifications to connected
   * darknet peers. It responds with either a redirect (for default bookmark restoration) or a fully
   * rendered HTML page reflecting the updated state. Names and keys are checked for length and
   * basic validity before being persisted to avoid corrupting the store.
   *
   * @param uri original request URI; the path should equal {@link #path()} for correct routing.
   * @param req POST request containing form parts such as {@code action}, {@code bookmark}, {@code
   *     name}, and optional sharing fields; missing parts are treated as empty strings.
   * @param ctx execution context used for page creation, access control, redirects, and bookmark
   *     management; must not be {@code null}.
   * @throws ToadletContextClosedException if the response stream closes while emitting output,
   *     indicating the client disconnected mid-request.
   * @throws IOException if reading form data or writing the HTML response encounters an I/O error.
   */
  public void handleMethodPOST(URI uri, HTTPRequest req, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    Objects.requireNonNull(uri, "uri");
    PageMaker pageMaker = ctx.getPageMaker();
    BookmarkManager bookmarkManager = ctx.getBookmarkManager();
    PageNode page =
        pageMaker.getPageNode(NodeL10n.getBase().getString("BookmarkEditorToadlet.title"), ctx);
    HTMLNode content = page.getContentNode();
    PostContext postCtx = new PostContext(pageMaker, bookmarkManager, content, ctx, page);

    if (req.isPartSet(PARAM_ADD_DEFAULT)) {
      bookmarkManager.reAddDefaultBookmarks();
      this.writeTemporaryRedirect(ctx, "Ok", "/");
      return;
    }

    String bookmarkPath = req.getPartAsStringFailsafe(PARAM_BOOKMARK, MAX_BOOKMARK_PATH_LENGTH);
    try {
      Bookmark bookmark = getBookmarkFromPath(bookmarkManager, bookmarkPath);
      if (bookmark == null && handleMissingBookmarkOnPost(req, bookmarkPath, postCtx)) {
        return;
      }

      String action = req.getPartAsStringFailsafe(PARAM_ACTION, MAX_ACTION_LENGTH);
      processPostAction(req, bookmarkPath, bookmark, action, postCtx);
    } catch (MalformedURLException _) {
      addInvalidKeyError(pageMaker, content);
    }
    renderBookmarksPostResponse(bookmarkManager, pageMaker, content, ctx, page);
  }

  private boolean handleMissingBookmarkOnPost(
      HTTPRequest req, String bookmarkPath, PostContext postCtx)
      throws ToadletContextClosedException, IOException {
    if (req.isPartSet(ACTION_CANCEL_CUT)) {
      return false;
    }
    postCtx
        .pageMaker()
        .getInfobox(
            INFOBOX_ERROR,
            NodeL10n.getBase().getString("BookmarkEditorToadlet.error"),
            postCtx.content(),
            BOOKMARK_ERROR_ID,
            false)
        .addChild(
            "#",
            NodeL10n.getBase()
                .getString(
                    "BookmarkEditorToadlet.bookmarkDoesNotExist",
                    new String[] {PARAM_BOOKMARK},
                    new String[] {bookmarkPath}));
    this.writeHTMLReply(postCtx.ctx(), 200, "OK", postCtx.page().generate());
    return true;
  }

  private void processPostAction(
      HTTPRequest req, String bookmarkPath, Bookmark bookmark, String action, PostContext postCtx)
      throws MalformedURLException {
    if (req.isPartSet("confirmdelete")) {
      handleConfirmDelete(
          postCtx.bookmarkManager(), postCtx.pageMaker(), postCtx.content(), bookmarkPath);
    } else if (req.isPartSet(ACTION_CANCEL_CUT)) {
      cutedPath = null;
    } else if (isEditOrAddAction(action)) {
      handleEditOrAddPost(req, bookmarkPath, bookmark, action, postCtx);
    } else if (ACTION_SHARE.equals(action) && bookmark instanceof BookmarkItem item) {
      sendBookmarkFeeds(req, item, req.getPartAsStringFailsafe(PUBLIC_DESC_FIELD, MAX_KEY_LENGTH));
    }
  }

  private void handleConfirmDelete(
      BookmarkManager bookmarkManager, PageMaker pageMaker, HTMLNode content, String bookmarkPath) {
    bookmarkManager.removeBookmark(bookmarkPath);
    bookmarkManager.storeBookmarks();
    pageMaker
        .getInfobox(
            INFOBOX_SUCCESS,
            NodeL10n.getBase().getString("BookmarkEditorToadlet.deleteSucceededTitle"),
            content,
            "bookmark-successful-delete",
            false)
        .addChild("p", NodeL10n.getBase().getString("BookmarkEditorToadlet.deleteSucceeded"));
  }

  private boolean isEditOrAddAction(String action) {
    return "edit".equals(action) || ACTION_ADD_ITEM.equals(action) || ACTION_ADD_CAT.equals(action);
  }

  private void handleEditOrAddPost(
      HTTPRequest req, String bookmarkPath, Bookmark bookmark, String action, PostContext postCtx)
      throws MalformedURLException {
    String name =
        req.isPartSet("name") ? req.getPartAsStringFailsafe("name", MAX_NAME_LENGTH) : "unnamed";
    Bookmark targetBookmark =
        postCtx
            .bookmarkManager()
            .getBookmarkByPath(postCtx.bookmarkManager().parentPath(bookmarkPath) + name);
    if (!isValidName(name) || (targetBookmark != null && targetBookmark != bookmark)) {
      addNameError(postCtx.pageMaker(), postCtx.content());
      return;
    }
    if ("edit".equals(action)) {
      processEditAction(
          req,
          postCtx.pageMaker(),
          postCtx.bookmarkManager(),
          postCtx.content(),
          bookmarkPath,
          bookmark,
          name);
    } else {
      processAddAction(req, bookmarkPath, name, action, postCtx);
    }
  }

  private void processEditAction(
      HTTPRequest req,
      PageMaker pageMaker,
      BookmarkManager bookmarkManager,
      HTMLNode content,
      String bookmarkPath,
      Bookmark bookmark,
      String name)
      throws MalformedURLException {
    bookmarkManager.renameBookmark(bookmarkPath, name);
    boolean hasAnActivelink = req.isPartSet(ACTIVE_LINK_FIELD);
    if (bookmark instanceof BookmarkItem item) {
      item.update(
          new FreenetURI(req.getPartAsStringFailsafe("key", MAX_KEY_LENGTH)),
          hasAnActivelink,
          req.getPartAsStringFailsafe(DESC_FIELD, MAX_KEY_LENGTH),
          req.getPartAsStringFailsafe(EXPLAIN_FIELD, MAX_EXPLANATION_LENGTH));
      sendBookmarkFeeds(req, item, req.getPartAsStringFailsafe(PUBLIC_DESC_FIELD, MAX_KEY_LENGTH));
    }
    bookmarkManager.storeBookmarks();

    pageMaker
        .getInfobox(
            INFOBOX_SUCCESS,
            NodeL10n.getBase().getString("BookmarkEditorToadlet.changesSavedTitle"),
            content,
            BOOKMARK_ERROR_ID,
            false)
        .addChild("p", NodeL10n.getBase().getString("BookmarkEditorToadlet.changesSaved"));
  }

  private void processAddAction(
      HTTPRequest req, String bookmarkPath, String name, String action, PostContext postCtx)
      throws MalformedURLException {
    Bookmark newBookmark;
    if (ACTION_ADD_ITEM.equals(action)) {
      FreenetURI key = new FreenetURI(req.getPartAsStringFailsafe("key", MAX_KEY_LENGTH));
      // Checkbox values are treated as true when present.
      boolean hasAnActivelink = req.isPartSet(ACTIVE_LINK_FIELD);
      newBookmark =
          new BookmarkItem(
              key,
              name,
              req.getPartAsStringFailsafe(DESC_FIELD, MAX_KEY_LENGTH),
              req.getPartAsStringFailsafe(EXPLAIN_FIELD, MAX_EXPLANATION_LENGTH),
              hasAnActivelink,
              postCtx.bookmarkManager(),
              postCtx.ctx().getAlertManager());
    } else {
      newBookmark = new BookmarkCategory(name);
    }

    postCtx.bookmarkManager().addBookmark(bookmarkPath, newBookmark);
    postCtx.bookmarkManager().storeBookmarks();
    if (newBookmark instanceof BookmarkItem item) {
      sendBookmarkFeeds(req, item, req.getPartAsStringFailsafe(PUBLIC_DESC_FIELD, MAX_KEY_LENGTH));
    }

    postCtx
        .pageMaker()
        .getInfobox(
            INFOBOX_SUCCESS,
            NodeL10n.getBase().getString("BookmarkEditorToadlet.addedNewBookmarkTitle"),
            postCtx.content(),
            "bookmark-add-new",
            false)
        .addChild("p", NodeL10n.getBase().getString("BookmarkEditorToadlet.addedNewBookmark"));
  }

  private void addInvalidKeyError(PageMaker pageMaker, HTMLNode content) {
    pageMaker
        .getInfobox(
            INFOBOX_ERROR,
            NodeL10n.getBase().getString("BookmarkEditorToadlet.invalidKeyTitle"),
            content,
            BOOKMARK_ERROR_ID,
            false)
        .addChild("#", NodeL10n.getBase().getString("BookmarkEditorToadlet.invalidKey"));
  }

  private void renderBookmarksPostResponse(
      BookmarkManager bookmarkManager,
      PageMaker pageMaker,
      HTMLNode content,
      ToadletContext ctx,
      PageNode page)
      throws ToadletContextClosedException, IOException {
    pageMaker
        .getInfobox(
            INFOBOX_NORMAL,
            NodeL10n.getBase().getString("BookmarkEditorToadlet.myBookmarksTitle"),
            content,
            "bookmarks",
            false)
        .addChild(getBookmarksList(bookmarkManager));

    HTMLNode addDefaultBookmarksForm = ctx.addFormChild(content, "", PARAM_ADD_DEFAULT);
    addDefaultBookmarksForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {
          INPUT_SUBMIT,
          PARAM_ADD_DEFAULT,
          NodeL10n.getBase().getString("BookmarkEditorToadlet.addDefaultBookmarks")
        });

    this.writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  /**
   * Returns the mount path used to register this toadlet within the HTTP dispatcher.
   *
   * <p>The value is constant and includes leading and trailing slashes so it can be concatenated
   * directly with relative resource links in generated pages. Callers typically read this during
   * registration with the router and when building redirects or form actions from other toadlets.
   * The string is immutable, contains only ASCII characters, and does not reflect runtime state,
   * making it safe to cache across requests. Any incoming request whose {@link URI#getPath()} does
   * not match this value will be rejected by the surrounding dispatcher before reaching the
   * handler.
   *
   * @return fixed path segment {@code "/bookmarkEditor/"} identifying the editor endpoint.
   */
  @Override
  public String path() {
    return "/bookmarkEditor/";
  }

  private boolean isValidName(String name) {
    return !name.isEmpty() && !name.contains("/");
  }

  private void addNameError(PageMaker pageMaker, HTMLNode parent) {
    HTMLNode errorBox =
        pageMaker.getInfobox(
            INFOBOX_ERROR,
            NodeL10n.getBase().getString("BookmarkEditorToadlet.invalidNameTitle"),
            parent,
            BOOKMARK_ERROR_ID,
            false);
    errorBox.addChild("#", NodeL10n.getBase().getString("BookmarkEditorToadlet.invalidName"));
  }
}
