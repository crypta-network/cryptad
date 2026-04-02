package network.crypta.clients.http;

import network.crypta.support.HTMLNode;

/**
 * Represents a complete HTML page shell with convenient access to the document head and content
 * sections.
 *
 * <p>PageNode mirrors {@link InfoboxNode} but targets full-page composition instead of a boxed
 * fragment. The {@code outer} node holds the entire document markup, while {@code content} acts as
 * the primary insertion point for user-visible body elements such as paragraphs, lists, or
 * interactive widgets. The {@code headNode} references the document {@code <head>} so callers can
 * register metadata, stylesheets, or preloads alongside an already-set title. Typical usage creates
 * a PageNode, writes metadata through {@link #getHeadNode()} or {@link #addForwardLink(String,
 * String, String, String)}, and then populates {@code content} with the rendered body before
 * serialization.
 *
 * <p>Instances are mutable during construction; after the page is emitted, callers should avoid
 * further mutation to prevent divergence between cached and streamed output. This class performs no
 * synchronization and is not thread-safe; confine each instance to a single thread or coordinate
 * external locking when building pages concurrently. The contained {@link HTMLNode} references are
 * live and changes apply immediately to the output tree.
 *
 * <ul>
 *   <li>Responsibilities: expose the head node, provide helpers for common link relations, and
 *       inherit content management from {@link InfoboxNode}.
 *   <li>Notable behaviors: does not deduplicate head entries and does not validate URLs or media
 *       types.
 * </ul>
 */
public class PageNode extends InfoboxNode {

  /**
   * Return the HTMLNode corresponding to the {@code <head>} tag, so we can add stuff to it, e.g.
   * {@code <meta>} tags.
   */
  public final HTMLNode headNode;

  PageNode(HTMLNode page, HTMLNode head, HTMLNode content) {
    super(page, content);
    this.headNode = head;
  }

  /**
   * Returns the live {@link HTMLNode} that represents the document {@code <head>} element.
   *
   * <p>Callers can attach metadata, preload hints, stylesheets, or other standard head children to
   * this node before the enclosing page is rendered. The returned reference is mutable and updates
   * apply immediately; it is not copied or wrapped. No validation or duplication checks are
   * performed, so callers should avoid adding the same relationship multiple times unless intended.
   * Use this accessor when helper methods such as {@link #addCustomStyleSheet(String)} are too
   * restrictive or when precise control over ordering is required.
   *
   * @return mutable {@code HTMLNode} for the {@code <head>} element; never {@code null}
   */
  public HTMLNode getHeadNode() {
    return headNode;
  }

  /**
   * Adds a custom style sheet link element to the page head for screen media.
   *
   * <p>This is a convenience wrapper around {@link #addForwardLink(String, String, String, String)}
   * that sets the relationship to {@code stylesheet}, declares the MIME type as {@code text/css},
   * and targets the {@code screen} media attribute. The method performs no URL validation or
   * deduplication, so callers should ensure the same stylesheet is not added repeatedly unless
   * multiple identical declarations are acceptable to downstream consumers. Invoke this before
   * serializing the page to ensure the link appears in the emitted head section.
   *
   * @param customStyleSheet absolute or relative URL pointing to the CSS resource; must be non-null
   */
  public void addCustomStyleSheet(String customStyleSheet) {
    addForwardLink("stylesheet", customStyleSheet, "text/css", "screen");
  }

  /**
   * Adds a document relationship forward link to the HTML document's HEAD node.
   *
   * <p>This overload delegates to the four-argument variant while leaving {@code type} and {@code
   * media} unspecified. Use it when only the relationship and target URL matter and the user agent
   * can infer other attributes. The link is appended as a new {@code <link>} child under the
   * existing head element without attempting to reorder or merge similar entries.
   *
   * @param linkType relationship value for the {@code rel} attribute; typically non-null
   * @param href hyperlink reference that resolves to the related resource; absolute or relative
   */
  @SuppressWarnings("unused")
  public void addForwardLink(String linkType, String href) {
    addForwardLink(linkType, href, null, null);
  }

  /**
   * Adds a document relationship forward link to the HTML document's HEAD node.
   *
   * <p>The method constructs a new {@code <link>} element with {@code rel} and {@code href}
   * attributes, then conditionally applies {@code type} and {@code media} when non-null. It does
   * not canonicalize values, resolve URLs, or prevent duplicates, making it suitable for callers
   * that need full control over link semantics or wish to emit multiple variants (for example,
   * alternate stylesheets or icons). Invoke this helper prior to final rendering so the generated
   * link appears in the document head in insertion order. The call is idempotent only when clients
   * avoid passing identical combinations repeatedly.
   *
   * @param linkType relationship to the referenced document (e.g., {@code stylesheet})
   * @param href destination URI for the linked resource; relative paths are permitted
   * @param type optional MIME type describing the linked content; {@code null} skips the attribute
   * @param media optional media descriptor such as {@code screen} or {@code print}; null omits it
   */
  public void addForwardLink(String linkType, String href, String type, String media) {
    HTMLNode linkNode =
        headNode.addChild("link", new String[] {"rel", "href"}, new String[] {linkType, href});
    if (type != null) {
      linkNode.addAttribute("type", type);
    }
    if (media != null) {
      linkNode.addAttribute("media", media);
    }
  }
}
