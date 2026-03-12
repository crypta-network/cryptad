package network.crypta.clients.http.complexhtmlnodes;

import network.crypta.support.HTMLNode;
import network.crypta.support.TimeUtil;

/**
 * Renders a second-based counter widget in HTML.
 *
 * <p>This node is an {@link HTMLNode} subtree that emits a {@code <span>} container with a CSS
 * class indicating whether the counter should increment or decrement. It also includes a hidden
 * {@code <input>} element that stores the initial numeric value for client-side code. When
 * JavaScript is enabled, the page can update the displayed value once per second without requiring
 * a server refresh.
 *
 * <p>The initial value is formatted using {@link TimeUtil#formatTime(long)} and placed next to (or
 * inside) the provided surrounding text. If the text contains the marker {@code {0}}, this
 * constructor treats it as an insertion point for the formatted time; otherwise the text is emitted
 * before the time.
 *
 * <ul>
 *   <li><b>Primary responsibility:</b> Generate stable, predictable HTML markup for a counter.
 *   <li><b>Mutability:</b> Instances are assembled during construction; the browser updates the UI.
 *   <li><b>Thread-safety:</b> Not thread-safe; intended for single-threaded page construction.
 * </ul>
 */
public class SecondCounterNode extends HTMLNode {
  /**
   * Creates a counter node that is updated once per second by client-side JavaScript.
   *
   * <p>The generated markup consists of a {@code <span>} container (with a CSS class indicating
   * direction), a hidden {@code <input>} storing the raw initial value, and one or more child
   * {@code <span>} nodes containing the surrounding text and the formatted time. If {@code text}
   * includes the marker {@code {0}}, it is split around that marker and the formatted time is
   * inserted between the two halves; otherwise the formatted time is appended after the text.
   *
   * <p>This constructor performs only markup assembly; it does not start timers itself. The counter
   * changes are driven externally by JavaScript that recognizes the CSS class and the hidden input.
   *
   * @param initialValue the initial numeric value, in the units expected by {@link TimeUtil}.
   * @param ascending whether the counter should increment, otherwise it should decrement.
   * @param text surrounding text for the counter, optionally containing {@code {0}} as a marker.
   */
  public SecondCounterNode(long initialValue, boolean ascending, String text) {
    super("span", "class", ascending ? "needsIncrement" : "needsDecrement");
    addChild(
        "input",
        new String[] {"type", "value"},
        new String[] {"hidden", String.valueOf(initialValue)});
    // If the text contains "{0}", it is treated as the insertion point for the formatted time so
    // text can appear both before and after the counter.
    if (!text.contains("{0}")) {
      addChild("span", text);
      addChild("span", TimeUtil.formatTime(initialValue));
    } else {
      addChild("span", text.substring(0, text.indexOf("{0}")));
      addChild("span", TimeUtil.formatTime(initialValue));
      addChild("span", text.substring(text.indexOf("{0}") + "{0}".length()));
    }
  }
}
