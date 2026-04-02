package network.crypta.clients.http;

import network.crypta.support.HTMLNode;

/**
 * Lightweight wrapper that bundles an outer HTML container with the inner content region for a
 * rendered infobox or page fragment. Typical usage builds the surrounding structural markup once
 * (header, chrome, borders) and then hands the content node to callers so they can append user
 * interface elements or textual content without needing to understand the container shape. The
 * class is intentionally minimal: it stores the two relevant {@link HTMLNode} instances and
 * delegates HTML generation to the outer node.
 *
 * <p>Use this type when building HTTP responses or templated page sections where you want to expose
 * a safe place to insert body content while retaining control over the wrapping markup. The outer
 * node normally represents the element added to a parent document, whereas the content node marks
 * the interior where consumers can append children. Instances are mutable only through the
 * contained {@link HTMLNode} objects; the references themselves are final, so the pairing remains
 * stable after construction.
 *
 * <p>Thread-safety follows the underlying {@link HTMLNode} implementation: nodes are not
 * thread-safe, and callers should confine instances to a single thread or apply their own
 * synchronization when mutating child structures.
 *
 * @author toad
 */
public class InfoboxNode {

  /**
   * Top-level container node for the infobox or page fragment. Add this node to a parent document
   * or render it directly to produce complete HTML for the wrapper around the inner content. The
   * reference is stable, but the underlying node remains mutable.
   */
  public final HTMLNode outer;

  /**
   * Content region inside the infobox. Callers can append additional HTML children here to populate
   * the visible body of the box while leaving the outer markup unchanged. The node is mutable and
   * shared with the {@link #outer} tree.
   */
  public final HTMLNode content;

  InfoboxNode(HTMLNode box, HTMLNode content) {
    this.outer = box;
    this.content = content;
  }

  /**
   * Calls {@link HTMLNode#generate()} on the {@link #getOuterNode() outer node} and returns the
   * generated HTML.
   *
   * <p>This method is a convenience that renders the full outer container along with any content
   * appended to it. It does not perform defensive copying; repeated invocations reflect any
   * mutations made to either the outer or content nodes between calls. Generation occurs entirely
   * in memory and does not perform I/O.
   *
   * @return serialized HTML markup for the outer node and its current descendants; never {@code
   *     null} but may be empty when no tags or text are present
   */
  public String generate() {
    return outer.generate();
  }

  /**
   * Returns the outer container node.
   *
   * <p>Use this handle when you need to attach the infobox to another {@link HTMLNode} or modify
   * attributes on the wrapper element. The returned reference is the same instance supplied at
   * construction time.
   *
   * @return live reference to the outer HTML node pairing this infobox with surrounding markup
   */
  public HTMLNode getOuterNode() {
    return outer;
  }

  /**
   * Returns the inner content node.
   *
   * <p>Callers typically append children or text to this node to fill the box body. Changes are
   * immediately reflected when {@link #generate()} is called on the infobox or directly on the
   * outer node.
   *
   * @return live reference to the content node inside the infobox
   */
  public HTMLNode getContentNode() {
    return content;
  }
}
