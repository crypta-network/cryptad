package network.crypta.client.filter;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import network.crypta.support.Fields;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tokenizing and validating filter for CSS 2.1 used by the client-side HTML/CSS sanitization
 * pipeline.
 *
 * <p>This component reads CSS from a {@link Reader}, tokenizes it with a small state machine, and
 * applies a conservative allowlist of properties, values, selectors, and at-rules. The primary goal
 * is to preserve a wide subset of legitimate stylesheet constructs while reliably rejecting or
 * neutralizing values and selectors that could break layout assumptions or enable content
 * exfiltration when rendered by a browser. The implementation predates a formal grammar; it focuses
 * on robust handling of edge cases encountered in the wild and predictable output suitable for
 * re-serialization to a {@link Writer}.
 *
 * <p>Typical usage is to construct a filter with an input {@code Reader}, an output {@code Writer},
 * and a {@link FilterCallback} that validates and possibly rewrites URIs. Call {@link #parse()}
 * once to filter the input stream into the output writer. The filter keeps a small number of states
 * around quotes, comments, braces, and current property context. It does not attempt to preserve
 * unreachable or structurally invalid content.
 *
 * <ul>
 *   <li>Selectors: normalized and validated; unsupported or banned pseudo-classes are removed.
 *   <li>Properties: validated per-property using dedicated verifiers; unknown properties are
 *       dropped.
 *   <li>URIs: validated through the provided {@link FilterCallback}; rewritten URIs are propagated.
 *   <li>Charsets and imports: {@code @charset} is detected; {@code @import} is sanitized and
 *       retained when valid.
 * </ul>
 *
 * <p>Thread-safety: instances are not thread-safe and are intended for single-threaded, single-use
 * operation. Reuse across inputs is not supported.
 *
 * @author kurmiashish
 * @author Matthew Toseland {@literal <toad@amphibian.dyndns.org>} (0xE43DA450)
 * @see #parse()
 * @see FilterCallback
 */
class CSSTokenizerFilter {
  // Common string literals (SonarLint java:S1192)
  private static final String S_BORDER_TOP_WIDTH = "border-top-width";
  private static final String S_BORDER_RIGHT_WIDTH = "border-right-width";
  private static final String S_BORDER_BOTTOM_WIDTH = "border-bottom-width";
  private static final String S_BORDER_LEFT_WIDTH = "border-left-width";

  private static final String V_BOTTOM = "bottom";
  private static final String V_COLOR = "color";
  private static final String V_CONTENT = "content";
  private static final String V_RIGHT = "right";
  private static final String V_CENTER = "center";
  private static final String V_HIDDEN = "hidden";
  private static final String V_DOTTED = "dotted";
  private static final String V_DASHED = "dashed";
  private static final String V_SOLID = "solid";
  private static final String V_DOUBLE = "double";
  private static final String V_GROOVE = "groove";
  private static final String V_RIDGE = "ridge";
  private static final String V_INSET = "inset";
  private static final String V_OUTSET = "outset";
  private static final String V_MEDIUM = "medium";
  private static final String V_THICK = "thick";
  private static final String V_CIRCLE = "circle";
  private static final String V_STRETCH = "stretch";
  private static final String V_REPEAT = "repeat";
  private static final String V_NORMAL = "normal";
  private static final String V_BASELINE = "baseline";
  private static final String V_LAST_BASELINE = "last-baseline";
  private static final String V_START = "start";
  private static final String V_VISIBLE = "visible";
  private static final String V_SCROLL = "scroll";
  private static final String V_FIXED = "fixed";
  private static final String V_SCREEN = "screen";
  private static final String V_TRANSPARENT = "transparent";
  private static final String V_CONTAIN = "contain";
  private static final String V_COLLAPSE = "collapse";
  private static final String V_ALWAYS = "always";
  private static final String V_AVOID = "avoid";
  private static final String V_COLUMN = "column";
  private static final String V_AVOID_PAGE = "avoid-page";
  private static final String V_AVOID_COLUMN = "avoid-column";
  private static final String V_BALANCE = "balance";
  private static final String V_NOWRAP = "nowrap";
  private static final String V_UNDER = "under";

  private static final String P_13_1_4 = "13<1,4>";
  private static final String P_14_1_4 = "14<1,4>";
  private static final String P_143_144_Q = "143 144?";

  private static final String WS_T_R_N = " \t\r\n";
  private static final String WS_T_R_N_F = " \t\r\n\f";

  private static final String MSG_HTML_COMMENT_WS_LEADING =
      "HTML comment marker invalid in leading scan: <!-- not followed by whitespace!";
  private static final String MSG_HTML_COMMENT_WS_PREFIX =
      "HTML comment marker invalid in prefix scan: <!-- not followed by whitespace!";
  private static final String MSG_SPLIT_STATE1_OPEN_BRACE =
      "Split tokens for STATE1 '{' processing: {}";
  private static final String MSG_SPLIT_STATE3_SEMI =
      "Split property value tokens at ';' in STATE3: {}";
  private static final String MSG_SPLIT_STATE3_RBRACE =
      "Split property value tokens before '}' in STATE3: {}";
  private static final String MSG_OPEN_BRACES_S3_COLON =
      "STATE3 ':' inside nested braces: openBraces={} start={}";
  private static final String MSG_OPEN_BRACES_S3_SEMI =
      "STATE3 ';' inside nested braces: openBraces={} start={}";
  private static final String MSG_OPEN_BRACES_S3_RBRACE =
      "STATE3 '}' inside nested braces: openBraces={} start={}";
  private static final String MSG_PROPERTY_VALUE_SEMI =
      "Parsed property value at ';' in STATE3: {}";
  private static final String MSG_PROPERTY_VALUE_RBRACE =
      "Parsed property value before '}' in STATE3: {}";
  private static final String MSG_NO_SUCH_PROPERTY_NAME_SEMI =
      "Unknown property name at ';' in STATE3: \"{}\"";
  private static final String MSG_NO_SUCH_PROPERTY_NAME_RBRACE =
      "Unknown property name before '}' in STATE3: \"{}\"";
  private static final String MSG_APPEND_WS_AFTER_COLON_RBRACE =
      "Captured whitespace after colon before '}' in STATE3: {}";
  private static final String MSG_APPEND_WS_PREFIX_RBRACE =
      "Captured prefix whitespace before '}' in STATE3: {}";
  private static final String MSG_APPEND_WS_STATE2 = "Appending whitespace in STATE2: \"{}\"";
  private static final String TOK_COUNTERS = "counters(";
  private static final String TOK_COUNTER = "counter(";
  private static final Logger LOG = LoggerFactory.getLogger(CSSTokenizerFilter.class);
  private Reader r;

  /**
   * Destination for filtered CSS. The filter writes only validated tokens and sanitized constructs
   * to this writer; callers own the lifecycle of the underlying stream.
   */
  Writer w = null;

  /**
   * Callback used to validate and optionally rewrite URIs encountered in CSS values (e.g., {@code
   * url(...)}). Implementations may return {@code null} to reject a URI.
   */
  FilterCallback cb;

  private final String passedCharset;
  private String detectedCharset;
  private final boolean stopAtDetectedCharset;
  private final boolean isInline;

  // no static init required

  /**
   * Creates a filter with a default configuration suitable for basic uses in tests. The input and
   * callback must be supplied before calling {@link #parse()}.
   */
  CSSTokenizerFilter() {
    passedCharset = "UTF-8";
    stopAtDetectedCharset = false;
    isInline = false;
  }

  /**
   * Creates a filter bound to the given input, output, and URI processing callback.
   *
   * <p>The filter reads from {@code r}, emits sanitized CSS to {@code w}, and consults {@code cb}
   * for URI validation and rewriting. The declared charset influences how {@code @charset} handling
   * behaves — see {@link #parse()} for details.
   *
   * @param r input character stream to read CSS from; must not be {@code null} for {@link
   *     #parse()}.
   * @param w output writer that receives filtered CSS; caller closes the stream when done.
   * @param cb callback responsible for URI checking and rewriting; may reject disallowed schemes.
   * @param charset declared input charset name used for {@code @charset} comparisons;
   *     case-insensitive.
   * @param stopAtDetectedCharset when {@code true}, parsing stops immediately after detecting
   *     {@code @charset} and nothing is written.
   * @param isInline when {@code true}, enables slightly different parsing heuristics for inline
   *     style attributes compared to full stylesheets.
   */
  CSSTokenizerFilter(
      Reader r,
      Writer w,
      FilterCallback cb,
      String charset,
      boolean stopAtDetectedCharset,
      boolean isInline) {
    this.r = r;
    this.w = w;
    this.cb = cb;
    passedCharset = charset;
    this.stopAtDetectedCharset = stopAtDetectedCharset;
    this.isInline = isInline;
  }

  /**
   * Returns whether the callback considers the given URI valid in this filtering context.
   *
   * <p>The method forwards the URI to {@link FilterCallback#processURI(String, String)} with a
   * {@code null} override type. If the callback throws or returns a different value, the URI is
   * considered invalid for acceptance in CSS.
   *
   * @param uri absolute or relative URI to validate; must be a non-null, non-empty string.
   * @return {@code true} when the callback returns the same value; {@code false} on rewrite,
   *     rejection ({@code null}) or exception.
   */
  public boolean isValidURI(String uri) {
    try {
      return uri.equals(cb.processURI(uri, null));
    } catch (CommentException _) {
      return false;
    }
  }

  // Removed: unused generic array concat helper.

  /* To save the memory, only those Verifier objects would be created which are actually present in the CSS document.
   * allelementVerifiers contain all the CSS property tags as String. All loaded Verifier objects are stored in elementVerifier.
   * When retrieving a Verifier object, first it is searched in elementVerifiers to see if it is already loaded.
   * If it is not loaded, then allelementVerifiers are checked to see if the property name is valid. If it is valid, then the desired Verifier object is loaded in allelemntVerifiers.
   */
  // Note: this is probably overkill, initializing all of them on startup would probably be cleaner
  // code, less synchronization, at very little memory cost.
  // Note: check how many bytes we save by lazy init here.
  private static final Map<String, CSSPropertyVerifier> elementVerifiers = new HashMap<>();
  private static final HashSet<String> allelementVerifiers = new HashSet<>();

  // Reference http://www.w3.org/TR/CSS2/propidx.html
  static {
    allelementVerifiers.add("accent-color");
    allelementVerifiers.add("align-content");
    allelementVerifiers.add("align-items");
    allelementVerifiers.add("align-self");
    allelementVerifiers.add("all");
    allelementVerifiers.add("appearance");
    allelementVerifiers.add("azimuth");
    allelementVerifiers.add("backface-visibility");
    allelementVerifiers.add("background-attachment");
    allelementVerifiers.add("background-blend-mode");
    allelementVerifiers.add("background-clip");
    allelementVerifiers.add("background-color");
    allelementVerifiers.add("background-image");
    allelementVerifiers.add("background-origin");
    allelementVerifiers.add("background-position");
    allelementVerifiers.add("background-position-x");
    allelementVerifiers.add("background-position-y");
    allelementVerifiers.add("background-repeat");
    allelementVerifiers.add("background-size");
    allelementVerifiers.add("background");
    allelementVerifiers.add("block-size");
    allelementVerifiers.add("border-collapse");
    allelementVerifiers.add("border-color");
    allelementVerifiers.add("border-top-color");
    allelementVerifiers.add("border-bottom-color");
    allelementVerifiers.add("border-right-color");
    allelementVerifiers.add("border-left-color");
    allelementVerifiers.add("border-block-end-color");
    allelementVerifiers.add("border-block-start-color");
    allelementVerifiers.add("border-inline-end-color");
    allelementVerifiers.add("border-inline-start-color");
    allelementVerifiers.add("border-spacing");
    allelementVerifiers.add("border-style");
    allelementVerifiers.add("border-top-style");
    allelementVerifiers.add("border-bottom-style");
    allelementVerifiers.add("border-left-style");
    allelementVerifiers.add("border-right-style");
    allelementVerifiers.add("border-block-end-style");
    allelementVerifiers.add("border-block-start-style");
    allelementVerifiers.add("border-inline-end-style");
    allelementVerifiers.add("border-inline-start-style");
    allelementVerifiers.add("border-left");
    allelementVerifiers.add("border-top");
    allelementVerifiers.add("border-right");
    allelementVerifiers.add("border-bottom");
    allelementVerifiers.add("border-block-end");
    allelementVerifiers.add("border-block-start");
    allelementVerifiers.add("border-inline-end");
    allelementVerifiers.add("border-inline-start");
    allelementVerifiers.add(S_BORDER_TOP_WIDTH);
    allelementVerifiers.add(S_BORDER_RIGHT_WIDTH);
    allelementVerifiers.add(S_BORDER_BOTTOM_WIDTH);
    allelementVerifiers.add(S_BORDER_LEFT_WIDTH);
    allelementVerifiers.add("border-width");
    allelementVerifiers.add("border-block-end-width");
    allelementVerifiers.add("border-block-start-width");
    allelementVerifiers.add("border-inline-end-width");
    allelementVerifiers.add("border-inline-start-width");
    allelementVerifiers.add("border-radius");
    allelementVerifiers.add("border-bottom-left-radius");
    allelementVerifiers.add("border-bottom-right-radius");
    allelementVerifiers.add("border-end-end-radius");
    allelementVerifiers.add("border-end-start-radius");
    allelementVerifiers.add("border-start-end-radius");
    allelementVerifiers.add("border-start-start-radius");
    allelementVerifiers.add("border-top-left-radius");
    allelementVerifiers.add("border-top-right-radius");
    allelementVerifiers.add("border-image-source");
    allelementVerifiers.add("border-image-slice");
    allelementVerifiers.add("border-image-width");
    allelementVerifiers.add("border-image-outset");
    allelementVerifiers.add("border-image-repeat");
    allelementVerifiers.add("border-image");
    allelementVerifiers.add("border");
    allelementVerifiers.add(V_BOTTOM);
    allelementVerifiers.add("box-decoration-break");
    allelementVerifiers.add("box-shadow");
    allelementVerifiers.add("box-sizing");
    allelementVerifiers.add("box-suppress");
    allelementVerifiers.add("caption-side");
    allelementVerifiers.add("caret-color");
    allelementVerifiers.add("clear");
    allelementVerifiers.add("clip");
    allelementVerifiers.add("break-before");
    allelementVerifiers.add("break-after");
    allelementVerifiers.add("break-inside");
    allelementVerifiers.add("color-scheme");
    allelementVerifiers.add("column-count");
    allelementVerifiers.add("column-fill");
    allelementVerifiers.add("column-gap");
    allelementVerifiers.add("column-rule-color");
    allelementVerifiers.add("column-rule-style");
    allelementVerifiers.add("column-rule-width");
    allelementVerifiers.add("column-span");
    allelementVerifiers.add("column-rule");
    allelementVerifiers.add("column-width");
    allelementVerifiers.add("columns");
    allelementVerifiers.add(V_COLOR);
    allelementVerifiers.add("color-interpolation");
    allelementVerifiers.add("color-rendering");
    allelementVerifiers.add(V_CONTENT);
    allelementVerifiers.add("counter-increment");
    allelementVerifiers.add("counter-reset");
    allelementVerifiers.add("cue-after");
    allelementVerifiers.add("cue-before");
    allelementVerifiers.add("cue");
    allelementVerifiers.add("cursor");
    allelementVerifiers.add("direction");
    allelementVerifiers.add("display");
    allelementVerifiers.add("dominant-baseline");
    allelementVerifiers.add("elevation");
    allelementVerifiers.add("empty-cells");
    allelementVerifiers.add("flex");
    allelementVerifiers.add("flex-basis");
    allelementVerifiers.add("flex-direction");
    allelementVerifiers.add("flex-flow");
    allelementVerifiers.add("flex-grow");
    allelementVerifiers.add("flex-shrink");
    allelementVerifiers.add("flex-wrap");
    allelementVerifiers.add("float");
    allelementVerifiers.add("font-family");
    allelementVerifiers.add("font-kerning");
    allelementVerifiers.add("font-optical-sizing");
    allelementVerifiers.add("font-size");
    allelementVerifiers.add("font-style");
    allelementVerifiers.add("font-variant");
    allelementVerifiers.add("font-weight");
    allelementVerifiers.add("font");
    allelementVerifiers.add("hanging-punctuation");
    allelementVerifiers.add("height");
    allelementVerifiers.add("hyphenate-character");
    allelementVerifiers.add("hyphens");
    allelementVerifiers.add("image-orientation");
    allelementVerifiers.add("image-rendering");
    allelementVerifiers.add("inline-size");
    allelementVerifiers.add("isolation");
    allelementVerifiers.add("justify-content");
    allelementVerifiers.add("justify-items");
    allelementVerifiers.add("justify-self");
    allelementVerifiers.add("left");
    allelementVerifiers.add("letter-spacing");
    allelementVerifiers.add("line-break");
    allelementVerifiers.add("line-height");
    allelementVerifiers.add("list-style-image");
    allelementVerifiers.add("list-style-position");
    allelementVerifiers.add("list-style-type");
    allelementVerifiers.add("list-style");
    allelementVerifiers.add("margin-block");
    allelementVerifiers.add("margin-block-end");
    allelementVerifiers.add("margin-block-start");
    allelementVerifiers.add("margin-bottom");
    allelementVerifiers.add("margin-inline");
    allelementVerifiers.add("margin-inline-end");
    allelementVerifiers.add("margin-inline-start");
    allelementVerifiers.add("margin-left");
    allelementVerifiers.add("margin-right");
    allelementVerifiers.add("margin-top");
    allelementVerifiers.add("margin");
    allelementVerifiers.add("math-style");
    allelementVerifiers.add("max-block-size");
    allelementVerifiers.add("max-height");
    allelementVerifiers.add("max-inline-size");
    allelementVerifiers.add("max-width");
    allelementVerifiers.add("min-block-size");
    allelementVerifiers.add("min-height");
    allelementVerifiers.add("min-inline-size");
    allelementVerifiers.add("min-width");
    allelementVerifiers.add("mix-blend-mode");
    allelementVerifiers.add("nav-down");
    allelementVerifiers.add("nav-left");
    allelementVerifiers.add("nav-right");
    allelementVerifiers.add("nav-up");
    allelementVerifiers.add("object-fit");
    allelementVerifiers.add("object-position");
    allelementVerifiers.add("opacity");
    allelementVerifiers.add("order");
    allelementVerifiers.add("orphans");
    allelementVerifiers.add("outline-color");
    allelementVerifiers.add("outline-offset");
    allelementVerifiers.add("outline-style");
    allelementVerifiers.add("outline-width");
    allelementVerifiers.add("outline");
    allelementVerifiers.add("overflow");
    allelementVerifiers.add("overflow-block");
    allelementVerifiers.add("overflow-inline");
    allelementVerifiers.add("overflow-wrap");
    allelementVerifiers.add("overflow-x");
    allelementVerifiers.add("overflow-y");
    allelementVerifiers.add("overscroll-behavior");
    allelementVerifiers.add("overscroll-behavior-block");
    allelementVerifiers.add("overscroll-behavior-inline");
    allelementVerifiers.add("overscroll-behavior-x");
    allelementVerifiers.add("overscroll-behavior-y");
    allelementVerifiers.add("padding-block");
    allelementVerifiers.add("padding-block-end");
    allelementVerifiers.add("padding-block-start");
    allelementVerifiers.add("padding-bottom");
    allelementVerifiers.add("padding-inline");
    allelementVerifiers.add("padding-inline-end");
    allelementVerifiers.add("padding-inline-start");
    allelementVerifiers.add("padding-left");
    allelementVerifiers.add("padding-right");
    allelementVerifiers.add("padding-top");
    allelementVerifiers.add("padding");
    allelementVerifiers.add("page-break-after");
    allelementVerifiers.add("page-break-before");
    allelementVerifiers.add("page-break-inside");
    allelementVerifiers.add("pause-after");
    allelementVerifiers.add("pause-before");
    allelementVerifiers.add("pause");
    allelementVerifiers.add("perspective");
    allelementVerifiers.add("pitch-range");
    allelementVerifiers.add("pitch");
    allelementVerifiers.add("play-during");
    allelementVerifiers.add("punctuation-trim");
    allelementVerifiers.add("pointer-events");
    allelementVerifiers.add("position");
    allelementVerifiers.add("quotes");
    allelementVerifiers.add("resize");
    allelementVerifiers.add("richness");
    allelementVerifiers.add(V_RIGHT);
    allelementVerifiers.add("rotate");
    allelementVerifiers.add("row-gap");
    allelementVerifiers.add("ruby-align");
    allelementVerifiers.add("ruby-position");
    allelementVerifiers.add("scroll-behavior");
    allelementVerifiers.add("scroll-margin");
    allelementVerifiers.add("scroll-margin-block");
    allelementVerifiers.add("scroll-margin-block-end");
    allelementVerifiers.add("scroll-margin-block-start");
    allelementVerifiers.add("scroll-margin-bottom");
    allelementVerifiers.add("scroll-margin-inline");
    allelementVerifiers.add("scroll-margin-inline-end");
    allelementVerifiers.add("scroll-margin-inline-start");
    allelementVerifiers.add("scroll-margin-left");
    allelementVerifiers.add("scroll-margin-right");
    allelementVerifiers.add("scroll-margin-top");
    allelementVerifiers.add("scroll-padding");
    allelementVerifiers.add("scroll-padding-block");
    allelementVerifiers.add("scroll-padding-block-end");
    allelementVerifiers.add("scroll-padding-block-start");
    allelementVerifiers.add("scroll-padding-bottom");
    allelementVerifiers.add("scroll-padding-inline");
    allelementVerifiers.add("scroll-padding-inline-end");
    allelementVerifiers.add("scroll-padding-inline-start");
    allelementVerifiers.add("scroll-padding-left");
    allelementVerifiers.add("scroll-padding-right");
    allelementVerifiers.add("scroll-padding-top");
    allelementVerifiers.add("scroll-snap-align");
    allelementVerifiers.add("scroll-snap-stop");
    allelementVerifiers.add("scroll-snap-type");
    allelementVerifiers.add("speak-header");
    allelementVerifiers.add("speak-numeral");
    allelementVerifiers.add("speak-punctuation");
    allelementVerifiers.add("speak");
    allelementVerifiers.add("speech-rate");
    allelementVerifiers.add("stress");
    allelementVerifiers.add("table-layout");
    allelementVerifiers.add("tab-size");
    allelementVerifiers.add("text-align");
    allelementVerifiers.add("text-align-last");
    allelementVerifiers.add("text-autospace");
    allelementVerifiers.add("text-combine-upright");
    allelementVerifiers.add("text-decoration");
    allelementVerifiers.add("text-decoration-color");
    allelementVerifiers.add("text-decoration-line");
    allelementVerifiers.add("text-decoration-skip");
    allelementVerifiers.add("text-decoration-skip-ink");
    allelementVerifiers.add("text-decoration-style");
    allelementVerifiers.add("text-decoration-thickness");
    allelementVerifiers.add("text-emphasis");
    allelementVerifiers.add("text-emphasis-color");
    allelementVerifiers.add("text-emphasis-position");
    allelementVerifiers.add("text-emphasis-style");
    allelementVerifiers.add("text-indent");
    allelementVerifiers.add("text-justify");
    allelementVerifiers.add("text-orientation");
    allelementVerifiers.add("text-outline");
    allelementVerifiers.add("text-overflow");
    allelementVerifiers.add("text-shadow");
    allelementVerifiers.add("text-transform");
    allelementVerifiers.add("text-underline-offset");
    allelementVerifiers.add("text-underline-position");
    allelementVerifiers.add("text-wrap");
    allelementVerifiers.add("text-wrap-mode");
    allelementVerifiers.add("text-wrap-style");
    allelementVerifiers.add("top");
    allelementVerifiers.add("transform");
    allelementVerifiers.add("transform-origin");
    allelementVerifiers.add("transition-delay");
    allelementVerifiers.add("transition-duration");
    allelementVerifiers.add("transition-property");
    allelementVerifiers.add("transition-timing-function");
    allelementVerifiers.add("translate");
    allelementVerifiers.add("unicode-bidi");
    allelementVerifiers.add("vertical-align");
    allelementVerifiers.add("visibility");
    allelementVerifiers.add("voice-family");
    allelementVerifiers.add("volume");
    allelementVerifiers.add("white-space");
    allelementVerifiers.add("white-space-collapse");
    allelementVerifiers.add("widows");
    allelementVerifiers.add("width");
    allelementVerifiers.add("word-break");
    allelementVerifiers.add("word-spacing");
    allelementVerifiers.add("word-wrap");
    allelementVerifiers.add("writing-mode");
    allelementVerifiers.add("z-index");
    allelementVerifiers.add("zoom");
  }

  /*
   * Array for storing additional Verifier objects for validating Regular expressions in CSS Property value
   * e.g. [ <color> | transparent]{1,4}. It is explained in detail in CSSPropertyVerifier class
   */
  private static final CSSPropertyVerifier[] auxilaryVerifiers = new CSSPropertyVerifier[149];

  static {
    // CSSPropertyVerifier(String[] allowedValues, String[] possibleValues, String expression,
    // boolean onlyValueVerifier)
    // for background-position
    auxilaryVerifiers[2] =
        new CSSPropertyVerifier(
            Arrays.asList("left", V_CENTER, V_RIGHT),
            Arrays.asList("pe", "le"),
            null,
            null,
            true); // Side-relative values with 2 tokens
    auxilaryVerifiers[3] =
        new CSSPropertyVerifier(
            Arrays.asList("top", V_CENTER, V_BOTTOM),
            Arrays.asList("pe", "le"),
            null,
            null,
            true); // Side-relative values with 2 tokens
    auxilaryVerifiers[4] =
        new CSSPropertyVerifier(Arrays.asList("left", V_CENTER, V_RIGHT), null, null, null, true);
    auxilaryVerifiers[5] =
        new CSSPropertyVerifier(Arrays.asList("top", V_CENTER, V_BOTTOM), null, null, null, true);
    // <border-color>
    auxilaryVerifiers[11] = new CSSPropertyVerifier(null, List.of("co"), null, null, true);
    // <border-style>
    auxilaryVerifiers[13] =
        new CSSPropertyVerifier(
            Arrays.asList(
                "none", V_HIDDEN, V_DOTTED, V_DASHED, V_SOLID, V_DOUBLE, V_GROOVE, V_RIDGE, V_INSET,
                V_OUTSET),
            List.of("le"),
            null,
            null,
            true);
    // <border-width>
    auxilaryVerifiers[14] =
        new CSSPropertyVerifier(
            Arrays.asList("thin", V_MEDIUM, V_THICK), List.of("le"), null, null, true);
    // list-style-type
    auxilaryVerifiers[35] =
        new CSSPropertyVerifier(
            Arrays.asList(
                "disc",
                V_CIRCLE,
                "square",
                "decimal",
                "decimal-leading-zero",
                "lower-roman",
                "upper-roman",
                "lower-greek",
                "lower-latin",
                "upper-latin",
                "armenian",
                "georgian",
                "lower-alpha",
                "upper-alpha",
                "none",
                "arabic-indic",
                "bengali",
                "cambodian",
                "cjk-decimal",
                "cjk-earthly-branch",
                "cjk-heavenly-stem",
                "cjk-ideographic",
                "devanagari",
                "disclosure-closed",
                "disclosure-open",
                "ethiopic-numeric",
                "gujarati",
                "gurmukhi",
                "hebrew",
                "hiragana",
                "hiragana-iroha",
                "japanese-formal",
                "japanese-informal",
                "kannada",
                "katakana",
                "katakana-iroha",
                "khmer",
                "korean-hangul-formal",
                "korean-hanja-formal",
                "lao",
                "lower-armenian",
                "malayalam",
                "mongolian",
                "myanmar",
                "oriya",
                "persian",
                "simp-chinese-formal",
                "simp-chinese-informal",
                "tamil",
                "telugu",
                "thai",
                "tibetan",
                "trad-chinese-formal",
                "trad-chinese-informal",
                "upper-armenian"),
            List.of("st"),
            null,
            null,
            true);
    // margin-width
    auxilaryVerifiers[36] =
        new CSSPropertyVerifier(List.of("auto"), Arrays.asList("le", "pe"), null, null, true);
    // padding-width
    auxilaryVerifiers[40] =
        new CSSPropertyVerifier(null, Arrays.asList("le", "pe"), null, null, true);
    // <background-clip> <background-origin>
    auxilaryVerifiers[61] =
        new CSSPropertyVerifier(
            Arrays.asList("border-box", "padding-box", "content-box"), null, null, null, true);
    // <shadow>
    auxilaryVerifiers[71] = new CSSPropertyVerifier(List.of(V_INSET), null, null, null, true);
    auxilaryVerifiers[72] = new CSSPropertyVerifier(null, List.of("le"), null, null, true);
    auxilaryVerifiers[74] = new CSSPropertyVerifier(null, null, List.of("72<1,4>"), null, true);
    auxilaryVerifiers[75] = new CSSPropertyVerifier(null, null, List.of("71a74a11"), null, true);
    // <border-image-source>
    auxilaryVerifiers[76] =
        new CSSPropertyVerifier(List.of("none"), List.of("ur"), null, null, true);
    // <border-image-slice>
    auxilaryVerifiers[68] =
        new CSSPropertyVerifier(List.of("auto"), Arrays.asList("le", "pe", "in"), null, null, true);
    auxilaryVerifiers[77] = new CSSPropertyVerifier(null, null, List.of("68<1,4>"), null, true);
    // <border-image-repeat>
    auxilaryVerifiers[70] =
        new CSSPropertyVerifier(
            Arrays.asList(V_STRETCH, V_REPEAT, "round"), null, null, null, true);
    auxilaryVerifiers[78] = new CSSPropertyVerifier(null, null, List.of("70<1,2>"), null, true);
    // <text-shadow>
    auxilaryVerifiers[79] =
        new CSSPropertyVerifier(
            null,
            null,
            Arrays.asList("11 72 72 72", "11 72 72", "72 72 72 11", "72 72 11", "72 72"),
            null,
            true);
    // <spacing-limit>
    auxilaryVerifiers[85] =
        new CSSPropertyVerifier(List.of(V_NORMAL), Arrays.asList("le", "pe"), null, null, true);
    // <text-decoration-line>
    auxilaryVerifiers[100] = new CSSPropertyVerifier(List.of("underline"), null, null, null, true);
    auxilaryVerifiers[101] = new CSSPropertyVerifier(List.of("overline"), null, null, null, true);
    auxilaryVerifiers[102] =
        new CSSPropertyVerifier(List.of("line-through"), null, null, null, true);
    auxilaryVerifiers[115] =
        new CSSPropertyVerifier(List.of("none"), null, null, List.of("100a101a102"));
    auxilaryVerifiers[116] = new CSSPropertyVerifier(List.of("blink"), null, null, null, true);
    // <text-decoration-style>
    auxilaryVerifiers[104] =
        new CSSPropertyVerifier(
            Arrays.asList(V_SOLID, V_DOUBLE, V_DOTTED, V_DASHED, "wavy"), null, null, null, true);
    // <text-emphasis-style>
    auxilaryVerifiers[105] =
        new CSSPropertyVerifier(Arrays.asList("filled", "open"), null, null, null, true);
    auxilaryVerifiers[106] =
        new CSSPropertyVerifier(
            Arrays.asList("dot", V_CIRCLE, "double-circle", "triangle", "sesame"),
            null,
            null,
            null,
            true);
    auxilaryVerifiers[107] =
        new CSSPropertyVerifier(List.of("none"), null, List.of("st"), List.of("105a106"));
    // <align-content> and <justify-content>
    // auto, <baseline-position>, <content-distribution> with optional <overflow-position> and
    // <content-position>
    // <content-position> = center, start, end, flex-start, flex-end, left, right
    auxilaryVerifiers[121] =
        new CSSPropertyVerifier(
            Arrays.asList(
                "auto",
                V_BASELINE,
                V_LAST_BASELINE,
                "space-between",
                "space-around",
                "space-evenly",
                V_STRETCH),
            null,
            null,
            null,
            true);
    // <overflow-position>
    auxilaryVerifiers[122] =
        new CSSPropertyVerifier(Arrays.asList("true", "safe"), null, null, null, true);
    auxilaryVerifiers[123] =
        new CSSPropertyVerifier(
            Arrays.asList(V_CENTER, V_START, "end", "flex-start", "flex-end", "left", V_RIGHT),
            null,
            null,
            null,
            true);
    auxilaryVerifiers[124] =
        new CSSPropertyVerifier(
            null,
            ElementInfo.VISUALMEDIA,
            null,
            Arrays.asList("122 123", "123", "123 122"),
            true,
            true);
    // <align-items>
    // auto | stretch | <baseline-position> | [ <item-position> && <overflow-position>? ]
    auxilaryVerifiers[125] =
        new CSSPropertyVerifier(
            Arrays.asList("auto", V_STRETCH, V_BASELINE, V_LAST_BASELINE), null, null, null, true);
    // <item-position> = center, start, end, self-start, self-end, flex-start, flex-end, left, right
    auxilaryVerifiers[126] =
        new CSSPropertyVerifier(
            Arrays.asList(
                V_CENTER,
                V_START,
                "end",
                "self-start",
                "self-end",
                "flex-start",
                "flex-end",
                "left",
                V_RIGHT),
            null,
            null,
            null,
            true);
    // [ <item-position> && <overflow-position>? ]
    auxilaryVerifiers[127] =
        new CSSPropertyVerifier(
            null,
            ElementInfo.VISUALMEDIA,
            null,
            Arrays.asList("122 126", "126", "126 122"),
            true,
            true);
    // <justify-items>
    // auto | stretch | <baseline-position> | [ <item-position> && <overflow-position>? ] | [ legacy
    // && [ left | right | center ] ]
    auxilaryVerifiers[128] = new CSSPropertyVerifier(List.of("legacy"), null, null, null, true);
    auxilaryVerifiers[129] =
        new CSSPropertyVerifier(
            null, ElementInfo.VISUALMEDIA, null, Arrays.asList("4 128", "128 4"), true, true);
    auxilaryVerifiers[130] =
        new CSSPropertyVerifier(
            null,
            ElementInfo.VISUALMEDIA,
            null,
            Arrays.asList("122 126", "126", "126 122"),
            true,
            true);
    // used in nav-down, nav-left, nav-right and nav-up
    auxilaryVerifiers[143] = new CSSPropertyVerifier(null, List.of("se"), null, null, true);
    auxilaryVerifiers[144] =
        new CSSPropertyVerifier(Arrays.asList("current", "root"), List.of("st"), null, null, true);
    // <transition-delay> & <transition-duration>
    auxilaryVerifiers[145] = new CSSPropertyVerifier(null, List.of("ti"), null, null, true);
    // <transition-property>
    auxilaryVerifiers[146] = new CSSPropertyVerifier(null, List.of("id"), null, null, true);
    // <transition-timing-function>
    // Note: Add function values: steps(...) & cubic-bezier(...) similar to
    // freenet.client.filter.FilterUtils.isCSSTransform(String)
    auxilaryVerifiers[147] =
        new CSSPropertyVerifier(
            Arrays.asList(
                "ease", "ease-in", "ease-out", "ease-in-out", "linear", "step-start", "step-end"),
            null,
            null,
            null,
            true);
  }

  // --- Data-driven dispatch for property verifiers (reduces addVerifier() complexity) ---
  @FunctionalInterface
  private interface PropertyRule {
    void apply(String element);
  }

  private static void putAndRemove(String element, CSSPropertyVerifier v) {
    elementVerifiers.put(element, v);
    allelementVerifiers.remove(element);
  }

  private static void aux(int idx, CSSPropertyVerifier v) {
    auxilaryVerifiers[idx] = v;
  }

  private static void register(Map<String, PropertyRule> m, PropertyRule rule, String... names) {
    for (String n : names) m.put(n.toLowerCase(Locale.ROOT), rule);
  }

  private static final Map<String, PropertyRule> RULES = buildRules();

  private static Map<String, PropertyRule> buildRules() {
    Map<String, PropertyRule> m = new HashMap<>();

    // Example ports to the registry. Remaining properties fall back to the legacy handler.

    // accent-color
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(List.of("auto"), ElementInfo.VISUALMEDIA, List.of("co"))),
        "accent-color");

    // align-content, justify-content
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    null, ElementInfo.VISUALMEDIA, null, List.of("121a124"), true, true)),
        "align-content",
        "justify-content");

    // clear
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("none", "left", V_RIGHT, "both", "inline-start", "inline-end"),
                    ElementInfo.VISUALMEDIA)),
        "clear");

    // background-repeat
    register(
        m,
        element -> {
          aux(
              57,
              new CSSPropertyVerifier(
                  Arrays.asList(V_REPEAT, "space", "round", "no-repeat"), null, null, null, true));
          aux(
              58,
              new CSSPropertyVerifier(
                  Arrays.asList("repeat-x", "repeat-y"), null, null, null, true));
          aux(59, new CSSPropertyVerifier(null, null, Arrays.asList("58", "57<1,2>"), null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  null, ElementInfo.VISUALMEDIA, null, List.of("59<1,65535>"), true, true));
        },
        "background-repeat");

    // background-attachment
    register(
        m,
        element -> {
          aux(
              60,
              new CSSPropertyVerifier(
                  Arrays.asList("local", V_SCROLL, V_FIXED), null, null, null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  null, ElementInfo.VISUALMEDIA, null, List.of("60<1,65535>"), true, true));
        },
        "background-attachment");

    // background-blend-mode / mix-blend-mode
    register(
        m,
        element -> {
          aux(
              148,
              new CSSPropertyVerifier(
                  Arrays.asList(
                      V_NORMAL,
                      "multiply",
                      V_SCREEN,
                      "overlay",
                      "darken",
                      "lighten",
                      "color-dodge",
                      "color-burn",
                      "hard-light",
                      "soft-light",
                      "difference",
                      "exclusion",
                      "hue",
                      "saturation",
                      V_COLOR,
                      "luminosity"),
                  null,
                  null,
                  null,
                  true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  null, ElementInfo.VISUALMEDIA, null, List.of("148<1,2>"), true, true));
        },
        "background-blend-mode",
        "mix-blend-mode");

    // background-clip / background-origin
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    null, ElementInfo.VISUALMEDIA, null, List.of("61<1,65535>"), true, true)),
        "background-clip",
        "background-origin");

    // background-color
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    List.of(V_TRANSPARENT), ElementInfo.VISUALMEDIA, List.of("co"))),
        "background-color");

    // background-image
    register(
        m,
        element -> {
          aux(56, new CSSPropertyVerifier(List.of("none"), List.of("ur"), null, null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  null, ElementInfo.VISUALMEDIA, null, List.of("56<1,65535>"), true, true));
        },
        "background-image");

    // background-size
    register(
        m,
        element -> {
          aux(
              62,
              new CSSPropertyVerifier(Arrays.asList("cover", V_CONTAIN), null, null, null, true));
          aux(63, new CSSPropertyVerifier(null, null, Arrays.asList("36<1,2>", "62"), null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  null, ElementInfo.VISUALMEDIA, null, List.of("63<1,65535>"), true, true));
        },
        "background-size");

    // background (composite)
    register(
        m,
        element -> {
          aux(6, new CSSPropertyVerifier(Arrays.asList(V_SCROLL, V_FIXED), null, null, null, true));
          aux(7, new CSSPropertyVerifier(List.of(V_TRANSPARENT), List.of("co"), null, null, true));
          aux(8, new CSSPropertyVerifier(List.of("none"), List.of("ur"), null, null, true));
          aux(9, new CSSPropertyVerifier(null, null, Arrays.asList("2 3?", "4a5"), null, true));
          aux(
              10,
              new CSSPropertyVerifier(
                  Arrays.asList(V_REPEAT, "repeat-x", "repeat-y", "no-repeat"),
                  null,
                  null,
                  null,
                  true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("6a7a8a9a10")));
        },
        "background");

    // background-position / object-position
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    null,
                    ElementInfo.VISUALPAGEDMEDIA,
                    null,
                    Arrays.asList("4a5a40", "40 40", "4 5", "5 4", "4 40 5 40", "5 40 4 40"))),
        "background-position",
        "object-position");

    // background-position-x
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALPAGEDMEDIA, null, List.of("2"))),
        "background-position-x");

    // background-position-y
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALPAGEDMEDIA, null, List.of("3"))),
        "background-position-y");

    // --- Border family ---
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(V_COLLAPSE, "separate"), ElementInfo.VISUALMEDIA)),
        "border-collapse");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    null, ElementInfo.VISUALMEDIA, List.of("co"), List.of("11<1,4>"))),
        "border-color");

    register(
        m,
        element -> {
          aux(12, new CSSPropertyVerifier(null, List.of("le"), null, null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("12 12?")));
        },
        "border-spacing");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of(P_13_1_4))),
        "border-style",
        "column-rule-style");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, null, List.of("13"), ElementInfo.VISUALMEDIA, true)),
        "border-top-style",
        "border-bottom-style",
        "border-left-style",
        "border-right-style",
        "border-block-end-style",
        "border-block-start-style",
        "border-inline-end-style",
        "border-inline-start-style");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("13a14a11"))),
        "border-left",
        "border-right",
        "border-top",
        "border-bottom",
        "border-block-end",
        "border-block-start",
        "border-inline-end",
        "border-inline-start",
        "border");

    register(
        m,
        element ->
            putAndRemove(
                element, new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, List.of("co"))),
        "border-top-color",
        "border-bottom-color",
        "border-left-color",
        "border-right-color",
        "border-inline-end-color",
        "border-inline-start-color",
        "border-block-start-color",
        "border-block-end-color",
        "column-rule-color",
        V_COLOR);

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of(P_14_1_4))),
        "border-width",
        "column-rule-width");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("14"))),
        S_BORDER_TOP_WIDTH,
        S_BORDER_BOTTOM_WIDTH,
        S_BORDER_LEFT_WIDTH,
        S_BORDER_RIGHT_WIDTH,
        "border-block-end-width",
        "border-block-start-width",
        "border-inline-end-width",
        "border-inline-start-width");

    register(
        m,
        element -> {
          aux(65, new CSSPropertyVerifier(List.of("/"), null, null, null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  null,
                  ElementInfo.VISUALMEDIA,
                  null,
                  Arrays.asList("40<1,4>", "40<1,4> 65 40<1,4>")));
        },
        "border-radius");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("40<1,2>"))),
        "border-bottom-left-radius",
        "border-bottom-right-radius",
        "border-top-left-radius",
        "border-top-right-radius",
        "border-start-end-radius",
        "border-start-start-radius",
        "border-end-end-radius",
        "border-end-start-radius",
        "padding-block",
        "padding-inline",
        "scroll-margin-block",
        "scroll-margin-inline");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("76"))),
        "border-image-source");

    register(
        m,
        element -> {
          aux(66, new CSSPropertyVerifier(null, Arrays.asList("pe", "in"), null, null, true));
          aux(67, new CSSPropertyVerifier(List.of("fill"), null, null, null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("66<1,4> 67?")));
        },
        "border-image-slice");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("77"))),
        "border-image-width");

    register(
        m,
        element -> {
          aux(69, new CSSPropertyVerifier(null, Arrays.asList("le", "in"), null, null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("69<1,4>")));
        },
        "border-image-outset");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("78"))),
        "border-image-repeat");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("76a77a78"))),
        "border-image");

    // --- Columns & z-index ---
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(List.of("auto"), ElementInfo.VISUALMEDIA, List.of("in"))),
        "column-count",
        "z-index");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(Arrays.asList("auto", V_BALANCE), ElementInfo.VISUALMEDIA)),
        "column-fill");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(List.of(V_NORMAL), ElementInfo.VISUALMEDIA, List.of("le"))),
        "column-gap");

    register(
        m,
        element -> {
          // column-rule: width + style + color
          aux(54, new CSSPropertyVerifier(null, null, null, List.of(P_14_1_4)));
          aux(55, new CSSPropertyVerifier(null, null, null, List.of(P_13_1_4)));
          putAndRemove(
              element,
              new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("54a55a11")));
        },
        "column-rule");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(Arrays.asList("1", "all"), ElementInfo.VISUALMEDIA)),
        "column-span");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(List.of("auto"), ElementInfo.VISUALMEDIA, List.of("le"))),
        "column-width");

    register(
        m,
        element -> {
          // columns: column-width + column-count
          aux(52, new CSSPropertyVerifier(List.of("auto"), List.of("le"), null, null, true));
          aux(53, new CSSPropertyVerifier(List.of("auto"), List.of("in"), null, null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("52a53")));
        },
        "columns");

    // --- Sizing and position properties (auto | <length> | <percentage>) ---
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    List.of("auto"), ElementInfo.VISUALMEDIA, Arrays.asList("le", "pe"))),
        "block-size",
        V_BOTTOM,
        "height",
        "inline-size",
        "left",
        "min-width",
        "min-height",
        "min-block-size",
        "min-inline-size",
        V_RIGHT,
        "top",
        "width");

    // --- Outline ---
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALINTERACTIVEMEDIA, List.of("co"))),
        "outline-color");

    register(
        m,
        element ->
            putAndRemove(
                element, new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, List.of("le"))),
        "outline-offset");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(
                        "none", V_HIDDEN, V_DOTTED, V_DASHED, V_SOLID, V_DOUBLE, V_GROOVE, V_RIDGE,
                        V_INSET, V_OUTSET),
                    ElementInfo.VISUALINTERACTIVEMEDIA)),
        "outline-style");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("thin", V_MEDIUM, V_THICK),
                    ElementInfo.VISUALINTERACTIVEMEDIA,
                    List.of("le"))),
        "outline-width");

    register(
        m,
        element -> {
          aux(37, new CSSPropertyVerifier(List.of("invert"), List.of("co"), null, null, true));
          aux(
              38,
              new CSSPropertyVerifier(
                  Arrays.asList(
                      "none", V_HIDDEN, V_DOTTED, V_DASHED, V_SOLID, V_DOUBLE, V_GROOVE, V_RIDGE,
                      V_INSET, V_OUTSET),
                  null,
                  null,
                  null,
                  true));
          aux(
              39,
              new CSSPropertyVerifier(
                  Arrays.asList("thin", V_MEDIUM, V_THICK), List.of("le"), null, null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  null, ElementInfo.VISUALINTERACTIVEMEDIA, List.of("le"), List.of("37a38a39")));
        },
        "outline");

    // --- Overflow ---
    register(
        m,
        element -> {
          aux(
              32,
              new CSSPropertyVerifier(
                  Arrays.asList(V_VISIBLE, V_HIDDEN, V_SCROLL, "auto", "clip"),
                  null,
                  null,
                  null,
                  true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("32<1,2>")));
        },
        "overflow");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(V_VISIBLE, V_HIDDEN, V_SCROLL, "auto", "clip"),
                    ElementInfo.VISUALMEDIA)),
        "overflow-x",
        "overflow-y",
        "overflow-block",
        "overflow-inline");

    // --- Overscroll behavior ---
    register(
        m,
        element -> {
          aux(
              64,
              new CSSPropertyVerifier(
                  Arrays.asList("auto", V_CONTAIN, "none"), null, null, null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("64<1,2>")));
        },
        "overscroll-behavior");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("auto", V_CONTAIN, "none"), ElementInfo.VISUALMEDIA)),
        "overscroll-behavior-x",
        "overscroll-behavior-y",
        "overscroll-behavior-block",
        "overscroll-behavior-inline");

    // --- Display ---
    register(
        m,
        element -> {
          // [ <display-outside> || <display-inside> ] | <display-listitem> | <display-internal> |
          // <display-box> | <display-legacy>
          aux(
              131,
              new CSSPropertyVerifier(
                  Arrays.asList("block", "inline", "run-in"), null, null, null, true));
          aux(
              132,
              new CSSPropertyVerifier(
                  Arrays.asList("flow", "flow-root", "table", "flex", "grid", "ruby"),
                  null,
                  null,
                  null,
                  true));
          aux(133, new CSSPropertyVerifier(List.of("list-item"), null, null, null, true));
          aux(
              134,
              new CSSPropertyVerifier(Arrays.asList("flow", "flow-root"), null, null, null, true));
          aux(135, new CSSPropertyVerifier(null, null, List.of("131?"), null, true));
          aux(136, new CSSPropertyVerifier(null, null, List.of("134?"), null, true));
          aux(
              137,
              new CSSPropertyVerifier(
                  Arrays.asList(
                      "table-row-group",
                      "table-header-group",
                      "table-footer-group",
                      "table-row",
                      "table-cell",
                      "table-column-group",
                      "table-column",
                      "table-caption",
                      "ruby-base",
                      "ruby-text",
                      "ruby-base-container",
                      "ruby-text-container"),
                  null,
                  null,
                  null,
                  true));
          aux(
              138,
              new CSSPropertyVerifier(Arrays.asList("contents", "none"), null, null, null, true));
          aux(
              139,
              new CSSPropertyVerifier(
                  Arrays.asList(
                      "inline-block",
                      "inline-list-item",
                      "inline-table",
                      "inline-flex",
                      "inline-grid"),
                  null,
                  null,
                  null,
                  true));
          aux(140, new CSSPropertyVerifier(null, null, List.of("133b135b136"), null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  null,
                  null,
                  Arrays.asList("131a132", "140<0,1>[1,3]", "137", "138", "139"),
                  null,
                  true));
        },
        "display");

    // --- Flexbox ---
    register(
        m,
        element -> {
          aux(119, new CSSPropertyVerifier(null, null, List.of("in")));
          aux(
              120,
              new CSSPropertyVerifier(Arrays.asList(V_CONTENT, "auto"), null, null, null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("119a120")));
        },
        "flex");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(V_CONTENT, "auto"),
                    ElementInfo.VISUALMEDIA,
                    Arrays.asList("le", "pe"))),
        "flex-basis");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("row", "row-reverse", V_COLUMN, "column-reverse"),
                    ElementInfo.VISUALMEDIA,
                    null)),
        "flex-direction");

    register(
        m,
        element -> {
          aux(
              117,
              new CSSPropertyVerifier(
                  Arrays.asList("row", "row-reverse", V_COLUMN, "column-reverse"),
                  null,
                  null,
                  null,
                  true));
          aux(
              118,
              new CSSPropertyVerifier(
                  Arrays.asList(V_NOWRAP, "wrap", "wrap-reverse"), null, null, null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("117a118")));
        },
        "flex-flow");

    register(
        m,
        element ->
            putAndRemove(
                element, new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, List.of("in"))),
        "flex-grow",
        "flex-shrink",
        "widows");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(V_NOWRAP, "wrap", "wrap-reverse"), ElementInfo.VISUALMEDIA)),
        "flex-wrap");

    // Alignment / justification
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    null, ElementInfo.VISUALMEDIA, null, Arrays.asList("125", "127"), true, true)),
        "align-items");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("auto", V_STRETCH, V_BASELINE, V_LAST_BASELINE),
                    ElementInfo.VISUALMEDIA,
                    null,
                    List.of("127"),
                    true,
                    true)),
        "align-self",
        "justify-self");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    null,
                    ElementInfo.VISUALMEDIA,
                    null,
                    Arrays.asList("125", "130", "129"),
                    true,
                    true)),
        "justify-items");

    // --- Typography & Fonts ---
    register(m, element -> putAndRemove(element, new FontPropertyVerifier(false)), "font-family");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("auto", "none", V_NORMAL), ElementInfo.VISUALMEDIA)),
        "font-kerning");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(Arrays.asList("auto", "none"), ElementInfo.VISUALMEDIA)),
        "font-optical-sizing",
        "pointer-events");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(
                        "xx-small",
                        "x-small",
                        "small",
                        V_MEDIUM,
                        "large",
                        "x-large",
                        "xx-large",
                        "xxx-large",
                        "larger",
                        "smaller"),
                    ElementInfo.VISUALMEDIA,
                    Arrays.asList("le", "pe"))),
        "font-size");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(V_NORMAL, "italic", "oblique"), ElementInfo.VISUALMEDIA)),
        "font-style");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(V_NORMAL, "small-caps"), ElementInfo.VISUALMEDIA)),
        "font-variant");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(
                        V_NORMAL, "bold", "bolder", "lighter", "100", "200", "300", "400", "500",
                        "600", "700", "800", "900"),
                    ElementInfo.VISUALMEDIA)),
        "font-weight");

    register(
        m,
        element -> {
          aux(
              27,
              new CSSPropertyVerifier(
                  Arrays.asList(V_NORMAL, "italic", "oblique"), null, null, null, true));
          aux(
              28,
              new CSSPropertyVerifier(
                  Arrays.asList(V_NORMAL, "small-caps"), null, null, null, true));
          aux(
              29,
              new CSSPropertyVerifier(
                  Arrays.asList(
                      V_NORMAL, "bold", "bolder", "lighter", "100", "200", "300", "400", "500",
                      "600", "700", "800", "900"),
                  null,
                  null,
                  null,
                  true));
          aux(30, new CSSPropertyVerifier(null, null, List.of("27a28a29"), null, true));
          aux(31, new FontPartPropertyVerifier());
          aux(59, new FontPropertyVerifier(true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  Arrays.asList(
                      "caption", "icon", "menu", "message-box", "small-caption", "status-bar"),
                  ElementInfo.VISUALMEDIA,
                  null,
                  List.of("30<0,1>[1,3] 31<0,1>[1,3] 59"),
                  false,
                  true));
        },
        "font");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, null, ElementInfo.VISUALMEDIA, List.of("85<1,3>"))),
        "letter-spacing",
        "word-spacing");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    List.of(V_NORMAL),
                    ElementInfo.VISUALMEDIA,
                    Arrays.asList("le", "pe", "re", "in"))),
        "line-height");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("auto", "anywhere", V_NORMAL, "strict", "loose"),
                    ElementInfo.VISUALMEDIA)),
        "line-break");

    // List style
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(List.of("none"), ElementInfo.VISUALMEDIA, List.of("ur"))),
        "list-style-image");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("inside", "outside"), ElementInfo.VISUALMEDIA)),
        "list-style-position");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("35"))),
        "list-style-type");

    register(
        m,
        element -> {
          aux(33, new CSSPropertyVerifier(List.of("none"), List.of("ur"), null, null, true));
          aux(
              34,
              new CSSPropertyVerifier(Arrays.asList("inside", "outside"), null, null, null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("33a34a35")));
        },
        "list-style");

    // Basic layout
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(Arrays.asList("ltr", "rtl"), ElementInfo.VISUALMEDIA)),
        "direction");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("left", V_RIGHT, "none", "inline-start", "inline-end"),
                    ElementInfo.VISUALMEDIA)),
        "float");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("static", "relative", "absolute", V_FIXED, "sticky"),
                    ElementInfo.VISUALMEDIA)),
        "position");

    // Images
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("none", "from-image"), ElementInfo.VISUALMEDIA)),
        "image-orientation");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("auto", "crisp-edges", "pixelated"), ElementInfo.VISUALMEDIA)),
        "image-rendering");

    // Hyphenation
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(List.of("auto"), ElementInfo.VISUALMEDIA, List.of("st"))),
        "hyphenate-character");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("none", "auto", "manual"), ElementInfo.VISUALMEDIA)),
        "hyphens");

    // Gaps
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("85<1,2>"))),
        "gap");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    List.of(V_NORMAL), ElementInfo.VISUALMEDIA, Arrays.asList("le", "pe"))),
        "row-gap");

    // Transforms and transitions
    register(
        m,
        element -> {
          aux(110, new CSSPropertyVerifier(null, List.of("tr"), null, null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  null, ElementInfo.VISUALMEDIA, null, List.of("110<0,65536>"), true, true));
        },
        "transform");

    register(
        m,
        element -> {
          aux(111, new CSSPropertyVerifier(null, null, List.of("2 3<0,1>"), null, true));
          aux(
              112,
              new CSSPropertyVerifier(
                  Arrays.asList("left", V_CENTER, V_RIGHT), null, null, null, true));
          aux(
              113,
              new CSSPropertyVerifier(
                  Arrays.asList("top", V_CENTER, V_BOTTOM), null, null, null, true));
          aux(114, new CSSPropertyVerifier(null, null, List.of("112a113"), null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  null, ElementInfo.VISUALMEDIA, null, Arrays.asList("111", "114"), true, true));
        },
        "transform-origin");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    List.of("none"),
                    ElementInfo.VISUALMEDIA,
                    null,
                    Arrays.asList("40", "40 40", "40 40 72"))),
        "translate");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    null, ElementInfo.VISUALMEDIA, null, List.of("145<1,65535>"), false, true)),
        "transition-delay",
        "transition-duration");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    null, ElementInfo.VISUALMEDIA, null, List.of("146<1,65535>"), false, true)),
        "transition-property");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    null, ElementInfo.VISUALMEDIA, null, List.of("147<1,65535>"), false, true)),
        "transition-timing-function");

    // --- Miscellaneous ---
    register(
        m,
        element ->
            putAndRemove(
                element, new CSSPropertyVerifier(null, ElementInfo.MEDIA, null, null, true, true)),
        "all");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(
                        "auto",
                        "none",
                        "base",
                        "searchfield",
                        "textarea",
                        "checkbox",
                        "radio",
                        "menulist",
                        "listbox",
                        "meter",
                        "progress-bar",
                        "button",
                        "textfield",
                        "menulist-button"),
                    ElementInfo.VISUALMEDIA,
                    null,
                    null,
                    true,
                    true)),
        "appearance");

    register(
        m,
        element -> {
          aux(
              0,
              new CSSPropertyVerifier(
                  Arrays.asList(
                      "left-side",
                      "far-left",
                      "left",
                      "center-left",
                      V_CENTER,
                      "center-right",
                      V_RIGHT,
                      "far-right",
                      "right-side"),
                  null,
                  null,
                  null,
                  true));
          aux(1, new CSSPropertyVerifier(List.of("behind"), null, null, null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  Arrays.asList("leftwards", "rightwards"),
                  ElementInfo.AURALMEDIA,
                  List.of("an"),
                  List.of("0a1")));
        },
        "azimuth");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(V_VISIBLE, V_HIDDEN),
                    ElementInfo.VISUALMEDIA,
                    null,
                    null,
                    true,
                    true)),
        "backface-visibility");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("auto", V_TRANSPARENT, "currentcolor"),
                    ElementInfo.VISUALMEDIA,
                    List.of("co"))),
        "caret-color");

    // --- Text decoration & shadow ---
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    null, ElementInfo.VISUALMEDIA, null, List.of("115a11a104a116"))),
        "text-decoration");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("11"))),
        "text-decoration-color",
        "text-emphasis-color");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    List.of("none"), ElementInfo.VISUALMEDIA, null, List.of("100a101a102"))),
        "text-decoration-line");

    register(
        m,
        element -> {
          aux(48, new CSSPropertyVerifier(List.of("images"), null, null, null, true));
          aux(49, new CSSPropertyVerifier(List.of("spaces"), null, null, null, true));
          aux(50, new CSSPropertyVerifier(List.of("ink"), null, null, null, true));
          aux(51, new CSSPropertyVerifier(List.of("all"), null, null, null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  List.of("none"), ElementInfo.VISUALMEDIA, null, List.of("48a49a50a51")));
        },
        "text-decoration-skip");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("none", "auto", "all"), ElementInfo.VISUALMEDIA)),
        "text-decoration-skip-ink");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("104"))),
        "text-decoration-style");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("from-font", "auto"),
                    ElementInfo.VISUALMEDIA,
                    Arrays.asList("le", "pe"))),
        "text-decoration-thickness");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("11a107"))),
        "text-emphasis");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(Arrays.asList("over", V_UNDER), ElementInfo.VISUALMEDIA)),
        "text-emphasis-position");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("107"))),
        "text-emphasis-style");

    register(
        m,
        element -> {
          aux(
              94,
              new CSSPropertyVerifier(
                  Arrays.asList("hanging", "each-line"), null, null, null, true));
          aux(95, new CSSPropertyVerifier(null, null, List.of("94<0,2>"), null, true));
          aux(96, new CSSPropertyVerifier(null, Arrays.asList("le", "pe"), null, null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("96 95")));
        },
        "text-indent");

    register(
        m,
        element -> {
          aux(
              83,
              new CSSPropertyVerifier(
                  Arrays.asList(
                      "inter-word", "inter-ideograph", "inter-cluster", "distribute", "kashida"),
                  null,
                  null,
                  null,
                  true));
          aux(84, new CSSPropertyVerifier(List.of("trim"), null, null, null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  List.of("auto"), ElementInfo.VISUALMEDIA, null, List.of("84a83")));
        },
        "text-justify");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("mixed", "upright", "sideways", "sideways-right"),
                    ElementInfo.VISUALMEDIA)),
        "text-orientation");

    register(
        m,
        element -> {
          aux(108, new CSSPropertyVerifier(null, null, List.of("11 72 72<0,1>"), null, true));
          aux(109, new CSSPropertyVerifier(null, null, List.of("72 72<0,1> 11"), null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  List.of("none"), ElementInfo.VISUALMEDIA, null, List.of("108a109")));
        },
        "text-outline");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("clip", "ellipsis"), ElementInfo.VISUALMEDIA, List.of("st"))),
        "text-overflow");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    List.of("none"), ElementInfo.VISUALMEDIA, null, List.of("79"), true, true)),
        "text-shadow");

    // --- Margin/Padding, scroll padding/margin ---
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("36"))),
        "margin-right",
        "margin-left",
        "margin-top",
        "margin-bottom",
        "margin-block-end",
        "margin-block-start",
        "margin-inline-end",
        "margin-inline-start",
        "scroll-padding-right",
        "scroll-padding-left",
        "scroll-padding-top",
        "scroll-padding-bottom",
        "scroll-padding-block-end",
        "scroll-padding-block-start",
        "scroll-padding-inline-end",
        "scroll-padding-inline-start",
        "text-underline-offset");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("36<1,2>"))),
        "margin-block",
        "margin-inline",
        "scroll-padding-block",
        "scroll-padding-inline");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("36<1,4>"))),
        "margin",
        "scroll-padding");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("40"))),
        "padding-top",
        "padding-right",
        "padding-bottom",
        "padding-left",
        "padding-block-end",
        "padding-block-start",
        "padding-inline-end",
        "padding-inline-start",
        "scroll-margin-top",
        "scroll-margin-right",
        "scroll-margin-bottom",
        "scroll-margin-left",
        "scroll-margin-block-end",
        "scroll-margin-block-start",
        "scroll-margin-inline-end",
        "scroll-margin-inline-start");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("40<1,4>"))),
        "padding",
        "scroll-margin");

    // --- Scroll and snapping ---
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(Arrays.asList("auto", "smooth"), ElementInfo.VISUALMEDIA)),
        "scroll-behavior");

    register(
        m,
        element -> {
          aux(
              82,
              new CSSPropertyVerifier(
                  Arrays.asList("none", V_START, "end", V_CENTER), null, null, null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, List.of("82<1,2>")));
        },
        "scroll-snap-align");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(V_NORMAL, V_ALWAYS), ElementInfo.VISUALMEDIA)),
        "scroll-snap-stop");

    register(
        m,
        element -> {
          aux(
              103,
              new CSSPropertyVerifier(
                  Arrays.asList("x", "y", "block", "inline", "both"), null, null, null, true));
          aux(
              80,
              new CSSPropertyVerifier(
                  Arrays.asList("mandatory", "proximity"), null, null, null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  List.of("none"), ElementInfo.VISUALMEDIA, null, Arrays.asList("103", "103 80")));
        },
        "scroll-snap-type");

    // --- Cursor & interactivity, visibility & opacity ---
    register(
        m,
        element -> {
          aux(25, new CSSPropertyVerifier(null, List.of("ur"), null, null, true));
          aux(141, new CSSPropertyVerifier(null, Arrays.asList("in", "re"), null, null, true));
          aux(
              142,
              new CSSPropertyVerifier(
                  null, null, null, Arrays.asList("25 141 141", "25"), true, true));
          aux(
              26,
              new CSSPropertyVerifier(
                  Arrays.asList(
                      "auto",
                      "default",
                      "none",
                      "context-menu",
                      "help",
                      "pointer",
                      "progress",
                      "wait",
                      "cell",
                      "crosshair",
                      "text",
                      "vertical-text",
                      "alias",
                      "copy",
                      "move",
                      "no-drop",
                      "not-allowed",
                      "grab",
                      "grabbing",
                      "e-resize",
                      "n-resize",
                      "ne-resize",
                      "nw-resize",
                      "s-resize",
                      "se-resize",
                      "sw-resize",
                      "w-resize",
                      "ew-resize",
                      "ns-resize",
                      "nesw-resize",
                      "nwse-resize",
                      "col-resize",
                      "row-resize",
                      "all-scroll",
                      "zoom-in",
                      "zoom-out"),
                  null,
                  null,
                  null,
                  true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  null,
                  ElementInfo.VISUALINTERACTIVEMEDIA,
                  null,
                  List.of("142<0," + ElementInfo.UPPERLIMIT + ">[1,3] 26"),
                  false,
                  true));
        },
        "cursor");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(Arrays.asList("auto", "isolate"), ElementInfo.VISUALMEDIA)),
        "isolation");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALPAGEDMEDIA, List.of("re"))),
        "opacity");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(V_VISIBLE, V_HIDDEN, V_COLLAPSE), ElementInfo.VISUALMEDIA)),
        "visibility");

    // --- Ruby & Aural ---
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(V_START, V_CENTER, "space-between", "space-around"),
                    ElementInfo.VISUALMEDIA)),
        "ruby-align");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(Arrays.asList("over", V_UNDER), ElementInfo.VISUALMEDIA)),
        "ruby-position");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("below", "level", "above", "higher", "lower"),
                    ElementInfo.AURALMEDIA,
                    List.of("an"))),
        "elevation");

    register(
        m,
        element -> putAndRemove(element, new VoiceFamilyPropertyVerifier(false)),
        "voice-family");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("silent", "x-soft", "soft", V_MEDIUM, "loud", "x-loud"),
                    ElementInfo.AURALMEDIA,
                    Arrays.asList("re", "le", "pe"))),
        "volume");

    // --- Clip ---
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(List.of("auto"), ElementInfo.VISUALMEDIA, List.of("sh"))),
        "clip");

    // --- Hanging punctuation ---
    register(
        m,
        element -> {
          aux(
              97,
              new CSSPropertyVerifier(
                  Arrays.asList("allow-end", "force-end"), null, null, null, true));
          aux(98, new CSSPropertyVerifier(List.of("first"), null, null, null, true));
          aux(99, new CSSPropertyVerifier(List.of("last"), null, null, null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  List.of("none"), ElementInfo.VISUALMEDIA, null, List.of("97a98a99")));
        },
        "hanging-punctuation");

    // --- Math style ---
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(V_NORMAL, "compact"), ElementInfo.VISUALMEDIA)),
        "math-style");

    // --- Speech ---
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(Arrays.asList("once", V_ALWAYS), ElementInfo.AURALMEDIA)),
        "speak-header");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("digits", "continuous"), ElementInfo.AURALMEDIA)),
        "speak-numeral");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(Arrays.asList("code", "none"), ElementInfo.AURALMEDIA)),
        "speak-punctuation");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(V_NORMAL, "none", "spell-out"), ElementInfo.AURALMEDIA)),
        "speak");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("x-slow", "slow", V_MEDIUM, "fast", "x-fast", "faster", "slower"),
                    ElementInfo.AURALMEDIA,
                    Arrays.asList("re", "in"))),
        "speech-rate");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.AURALMEDIA, Arrays.asList("ti", "pe"))),
        "pause-after",
        "pause-before");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.AURALMEDIA, Arrays.asList("in", "re"))),
        "pitch-range");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("x-low", "low", V_MEDIUM, "high", "x-high"),
                    ElementInfo.AURALMEDIA,
                    List.of("fr"))),
        "pitch");

    register(
        m,
        element -> {
          aux(41, new CSSPropertyVerifier(null, Arrays.asList("ti", "pe"), null, null, true));
          putAndRemove(element, new CSSPropertyVerifier(null, null, null, List.of("41<1,2>")));
        },
        "pause");

    register(
        m,
        element -> {
          aux(42, new CSSPropertyVerifier(null, List.of("ur"), null, null, true));
          aux(43, new CSSPropertyVerifier(List.of("mix"), null, null, null, true));
          aux(44, new CSSPropertyVerifier(List.of(V_REPEAT), null, null, null, true));
          aux(45, new CSSPropertyVerifier(null, null, List.of("43a44"), null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  Arrays.asList("auto", "none"),
                  ElementInfo.AURALMEDIA,
                  null,
                  List.of("42 45<0,1>[1,2]")));
        },
        "play-during");

    register(
        m,
        element -> {
          aux(86, new CSSPropertyVerifier(List.of(V_START), null, null, null, true));
          aux(
              87,
              new CSSPropertyVerifier(Arrays.asList("end", "allow-end"), null, null, null, true));
          aux(88, new CSSPropertyVerifier(List.of("adjacent"), null, null, null, true));
          aux(89, new CSSPropertyVerifier(null, null, List.of("86a87a88"), null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  List.of("none"), ElementInfo.AURALMEDIA, null, List.of("89")));
        },
        "punctuation-trim");

    // --- Box model & captions ---
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("slice", "clone"), ElementInfo.VISUALMEDIA, null)),
        "box-decoration-break");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    List.of("none"),
                    ElementInfo.VISUALMEDIA,
                    null,
                    List.of("75<1,65535>"),
                    true,
                    true)),
        "box-shadow");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("content-box", "border-box"), ElementInfo.VISUALMEDIA, null)),
        "box-sizing");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("show", "discard", "hide"), ElementInfo.VISUALMEDIA, null)),
        "box-suppress");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(Arrays.asList("top", V_BOTTOM), ElementInfo.VISUALMEDIA)),
        "caption-side");

    // --- Breaks (paged/column) ---
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(
                        "auto",
                        V_ALWAYS,
                        V_AVOID,
                        "all",
                        "left",
                        V_RIGHT,
                        "recto",
                        "verso",
                        "page",
                        V_COLUMN,
                        V_AVOID_PAGE,
                        V_AVOID_COLUMN),
                    ElementInfo.VISUALPAGEDMEDIA)),
        "break-after",
        "page-break-after",
        "break-before",
        "page-break-before");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("auto", V_AVOID, V_AVOID_PAGE, V_AVOID_COLUMN),
                    ElementInfo.VISUALPAGEDMEDIA)),
        "break-inside",
        "page-break-inside");

    // --- Color & rendering ---
    register(
        m,
        element -> {
          aux(
              81,
              new CSSPropertyVerifier(
                  Arrays.asList("light", "dark", "only"), null, null, null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  List.of(V_NORMAL), ElementInfo.VISUALMEDIA, null, List.of("81<1,3>")));
        },
        "color-scheme");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("auto", "sRGB", "linearRGB"), ElementInfo.VISUALMEDIA)),
        "color-interpolation");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("auto", "optimizeSpeed", "optimizeQuality"),
                    ElementInfo.VISUALMEDIA)),
        "color-rendering");

    // --- Content & counters ---
    register(
        m,
        element -> {
          aux(
              16,
              new ContentPropertyVerifier(
                  Arrays.asList("open-quote", "close-quote", "no-open-quote", "no-close-quote")));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  Arrays.asList(V_NORMAL, "none"),
                  ElementInfo.MEDIA,
                  null,
                  List.of("16<1," + ElementInfo.UPPERLIMIT + ">")));
        },
        V_CONTENT);

    register(
        m,
        element -> {
          aux(17, new CSSPropertyVerifier(null, List.of("id"), null, null, true));
          aux(18, new CSSPropertyVerifier(null, List.of("in"), null, null, true));
          aux(19, new CSSPropertyVerifier(null, null, List.of("17 18?"), null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  List.of("none"),
                  ElementInfo.MEDIA,
                  null,
                  List.of("19<1," + ElementInfo.UPPERLIMIT + ">[1,2]")));
        },
        "counter-increment");

    register(
        m,
        element -> {
          aux(20, new CSSPropertyVerifier(null, List.of("id"), null, null, true));
          aux(21, new CSSPropertyVerifier(null, List.of("in"), null, null, true));
          aux(22, new CSSPropertyVerifier(null, null, List.of("20 21?"), null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  List.of("none"),
                  ElementInfo.MEDIA,
                  null,
                  List.of("22<1," + ElementInfo.UPPERLIMIT + ">[1,2]")));
        },
        "counter-reset");

    // --- Cue & aural ---
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(List.of("none"), ElementInfo.AURALMEDIA, List.of("ur"))),
        "cue-after",
        "cue-before");

    register(
        m,
        element -> {
          aux(23, new CSSPropertyVerifier(List.of("none"), List.of("ur"), null, null, true));
          aux(24, new CSSPropertyVerifier(List.of("none"), List.of("ur"), null, null, true));
          putAndRemove(
              element, new CSSPropertyVerifier(null, ElementInfo.MEDIA, null, List.of("23a24")));
        },
        "cue");

    // --- Baseline & tables ---
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(
                        "auto",
                        "text-bottom",
                        "alphabetic",
                        "ideographic",
                        "middle",
                        "central",
                        "mathematical",
                        "hanging",
                        "text-top"),
                    ElementInfo.VISUALMEDIA)),
        "dominant-baseline");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(Arrays.asList("show", "hide"), ElementInfo.VISUALMEDIA)),
        "empty-cells");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(Arrays.asList("auto", V_FIXED), ElementInfo.VISUALMEDIA)),
        "table-layout");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, Arrays.asList("le", "in"))),
        "tab-size");

    // --- Max/min & nav ---
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    List.of("none"), ElementInfo.VISUALMEDIA, Arrays.asList("le", "pe"))),
        "max-width",
        "max-height",
        "max-block-size",
        "max-inline-size");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    List.of("auto"),
                    ElementInfo.VISUALINTERACTIVEMEDIA,
                    null,
                    List.of(P_143_144_Q))),
        "nav-down",
        "nav-left",
        "nav-right",
        "nav-up");

    // --- Object fit ---
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(V_CONTAIN, "cover", "fill", "none", "scale-down"),
                    ElementInfo.VISUALMEDIA)),
        "object-fit");

    // --- Ordering & pagination ---
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.VISUALPAGEDMEDIA, List.of("in"))),
        "order",
        "orphans");

    // --- Quotes, resize, stress/richness ---
    register(
        m,
        element -> {
          aux(46, new CSSPropertyVerifier(null, List.of("st"), null, null, true));
          aux(47, new CSSPropertyVerifier(null, null, List.of("46 46"), null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  List.of("none"),
                  null,
                  ElementInfo.VISUALMEDIA,
                  List.of("47<1," + ElementInfo.UPPERLIMIT + ">[2,2]")));
        },
        "quotes");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("none", "both", "horizontal", "vertical"),
                    ElementInfo.VISUALMEDIA,
                    null)),
        "resize");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(null, ElementInfo.AURALMEDIA, Arrays.asList("re", "in"))),
        "richness",
        "stress");

    // --- Rotate & perspective ---
    register(
        m,
        element -> {
          aux(141, new CSSPropertyVerifier(null, Arrays.asList("in", "re"), null, null, true));
          aux(73, new CSSPropertyVerifier(null, List.of("an"), null, null, true));
          aux(15, new CSSPropertyVerifier(Arrays.asList("x", "y", "z"), null, null, null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  List.of("none"),
                  ElementInfo.VISUALMEDIA,
                  null,
                  Arrays.asList("73", "15 73", "141 141 141 73")));
        },
        "rotate");

    register(
        m,
        element ->
            putAndRemove(element, new CSSPropertyVerifier(List.of("none"), null, List.of("le"))),
        "perspective");

    // --- Text align & wrap ---
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(
                        V_START, "end", "left", V_RIGHT, V_CENTER, "justify", "match-parent"),
                    ElementInfo.VISUALMEDIA)),
        "text-align");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(V_START, "end", "left", V_RIGHT, V_CENTER, "justify"),
                    ElementInfo.VISUALMEDIA)),
        "text-align-last");

    register(
        m,
        element -> {
          aux(90, new CSSPropertyVerifier(List.of("ideograph-numeric"), null, null, null, true));
          aux(91, new CSSPropertyVerifier(List.of("ideograph-alpha"), null, null, null, true));
          aux(92, new CSSPropertyVerifier(List.of("ideograph-space"), null, null, null, true));
          aux(
              93,
              new CSSPropertyVerifier(List.of("ideograph-parenthesis"), null, null, null, true));
          putAndRemove(
              element,
              new CSSPropertyVerifier(
                  List.of("none"), ElementInfo.VISUALMEDIA, null, List.of("90a91a92a93")));
        },
        "text-autospace");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("none", "all"), ElementInfo.VISUALMEDIA, null, null)),
        "text-combine-upright");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(
                        "capitalize",
                        "uppercase",
                        "lowercase",
                        "none",
                        "fullwidth",
                        "full-size-kana",
                        "math-auto"),
                    ElementInfo.VISUALMEDIA)),
        "text-transform");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("auto", V_UNDER, "left", V_RIGHT), ElementInfo.VISUALMEDIA)),
        "text-underline-position");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("wrap", V_NOWRAP, V_BALANCE), ElementInfo.VISUALMEDIA)),
        "text-wrap");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(Arrays.asList("wrap", V_NOWRAP), ElementInfo.VISUALMEDIA)),
        "text-wrap-mode");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList("auto", V_BALANCE, "stable", "pretty", "avoid-orphans"),
                    ElementInfo.VISUALMEDIA)),
        "text-wrap-style");

    // --- Unicode bidi & vertical-align ---
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(
                        V_NORMAL,
                        "embed",
                        "bidi-override",
                        "isolate",
                        "isolate-override",
                        "plaintext"),
                    ElementInfo.VISUALMEDIA)),
        "unicode-bidi");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(
                        V_BASELINE,
                        "sub",
                        "super",
                        "top",
                        "text-top",
                        "middle",
                        V_BOTTOM,
                        "text-bottom"),
                    ElementInfo.VISUALMEDIA,
                    Arrays.asList("pe", "le"))),
        "vertical-align");

    // --- White space, word wrapping, writing mode, zoom ---
    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(V_NORMAL, "pre", V_NOWRAP, "pre-wrap", "pre-line"),
                    ElementInfo.VISUALMEDIA)),
        "white-space");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(
                        "preserve", "preserve-break", V_COLLAPSE, "discard", "break-spaces"),
                    null,
                    ElementInfo.VISUALMEDIA)),
        "white-space-collapse");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(V_NORMAL, "break-all", "hyphenate", "keep-all"),
                    ElementInfo.VISUALMEDIA)),
        "word-break");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(V_NORMAL, "break-word", "anywhere"), ElementInfo.VISUALMEDIA)),
        "word-wrap",
        "overflow-wrap");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    Arrays.asList(
                        "horizontal-tb",
                        "vertical-rl",
                        "vertical-lr",
                        "lr",
                        "lr-tb",
                        "rl",
                        "tb",
                        "tb-lr",
                        "tb-rl"),
                    ElementInfo.VISUALMEDIA)),
        "writing-mode");

    register(
        m,
        element ->
            putAndRemove(
                element,
                new CSSPropertyVerifier(
                    List.of(V_NORMAL), ElementInfo.VISUALMEDIA, Arrays.asList("re", "pe"))),
        "zoom");

    return Collections.unmodifiableMap(m);
  }

  /* This function loads a verifier object in elementVerifiers.
   * After the object has been loaded, the property name is removed from allelementVerifier.
   */
  private static void addVerifier(String element) {
    PropertyRule rule = RULES.get(element.toLowerCase(Locale.ROOT));
    if (rule != null) {
      rule.apply(element);
    }
  }

  /*
   * This function returns the Verifier for a property. If it is not already loaded in the elementVerifier, then it is loaded and then returned to the caller.
   * Note: Lazy init probably doesn't make sense, but while we are initting lazily, we need to hold a lock here.
   */
  private static synchronized CSSPropertyVerifier getVerifier(String element) {
    element = element.toLowerCase(Locale.ROOT);
    if (elementVerifiers.get(element) != null) return elementVerifiers.get(element);
    else if (allelementVerifiers.contains(element)) {
      addVerifier(element);
      return elementVerifiers.get(element);
    } else return null;
  }

  /**
   * Validates and normalizes a selector (or element token) according to the filter’s rules.
   *
   * <p>The input may include an element name, class or ID, attribute selectors, and certain
   * pseudo-classes. The method enforces name constraints, rejects unsupported selectors, and
   * signals banned-but-valid selectors separately from invalid syntax.
   *
   * @param elementString selector string to validate; may include an element and simple selectors.
   * @param isIDSelector when {@code true}, the selector must include an ID and contain no other
   *     constructs beyond an optional element name or {@code *}.
   * @return the normalized selector when acceptable; an empty string for banned-but-otherwise-valid
   *     selectors; or {@code null} if the selector is syntactically invalid.
   */
  public static String htmlElementVerifier(String elementString, boolean isIDSelector) {
    if (LOG.isTraceEnabled()) LOG.trace("varifying element/selector: \"{}\"", elementString);
    SelectorParts parts = new SelectorParts();
    parts.remaining = elementString;
    // 1) Attribute selectors
    if (!collectAttributeSelections(parts, isIDSelector)) return null;
    // 2) Pseudo class
    if (!extractPseudoClass(parts, isIDSelector)) return null;
    // 3) Class or ID
    if (!extractClassOrId(parts, isIDSelector)) return null;
    if (isIDSelector && parts.id.isEmpty()) return null; // require an ID
    // 4) Validate the element and names
    if (!isElementValid(parts)) return null;
    if (!validateNames(parts)) return null;
    // 5) Validate pseudo class semantics
    int pseudo = validatePseudoClass(parts.pseudoClass);
    if (pseudo < 0) return null; // invalid
    if (pseudo > 0) return ""; // banned
    // 6) Validate attribute selections
    if (!validateAttributeSelections(parts.attSelections)) return null;
    // 7) Build normalized selector
    return buildSelector(parts);
  }

  private static final class SelectorParts {
    String remaining;
    String element = "";
    String pseudoClass = "";
    String className = "";
    String id = "";
    ArrayList<String> attSelections = null;
  }

  private static boolean collectAttributeSelections(SelectorParts parts, boolean isIDSelector) {
    String s = parts.remaining;
    while (s.indexOf('[') != -1 && s.indexOf(']') != -1 && s.indexOf('[') < s.indexOf(']')) {
      if (isIDSelector) return false;
      String attSelection = s.substring(s.indexOf('[') + 1, s.indexOf(']')).trim();
      StringBuilder buf = new StringBuilder(s);
      buf.delete(s.indexOf('['), s.indexOf(']') + 1);
      s = buf.toString();
      if (LOG.isDebugEnabled()) LOG.debug("attSelection={}  elementString={}", attSelection, s);
      if (parts.attSelections == null) parts.attSelections = new ArrayList<>();
      parts.attSelections.add(attSelection);
    }
    parts.remaining = s;
    return true;
  }

  private static boolean extractPseudoClass(SelectorParts parts, boolean isIDSelector) {
    String s = parts.remaining;
    int idx = s.indexOf(':');
    if (idx != -1) {
      if (isIDSelector) return false;
      if (idx != s.length() - 1) {
        parts.pseudoClass = s.substring(idx + 1).trim();
        parts.element = s.substring(0, idx).trim();
        if (LOG.isDebugEnabled())
          LOG.debug("pseudoclass={} HTMLelement={}", parts.pseudoClass, parts.element);
      } else {
        parts.element = s.trim();
      }
    } else {
      parts.element = s.trim();
    }
    return true;
  }

  private static boolean extractClassOrId(SelectorParts parts, boolean isIDSelector) {
    String el = parts.element;
    int dot = el.indexOf('.');
    int hash = el.indexOf('#');

    if (dot != -1) {
      return handleClassSelector(parts, isIDSelector, el, dot);
    }

    if (hash != -1) {
      return handleIdSelector(parts, el, hash);
    }

    return true;
  }

  /** Handles extraction for a ".class" selector. */
  private static boolean handleClassSelector(
      SelectorParts parts, boolean isIDSelector, String el, int dotIndex) {
    if (isIDSelector) return false;
    if (dotIndex != el.length() - 1) {
      parts.className = el.substring(dotIndex + 1).trim();
      parts.element = el.substring(0, dotIndex).trim();
      if (LOG.isDebugEnabled())
        LOG.debug("class={} HTMLelement={}", parts.className, parts.element);
    } else {
      parts.element = el;
    }
    return true;
  }

  /** Handles extraction for a "#id" selector. */
  private static boolean handleIdSelector(SelectorParts parts, String el, int hashIndex) {
    if (hashIndex != el.length() - 1) {
      parts.id = el.substring(hashIndex + 1).trim();
      parts.element = el.substring(0, hashIndex).trim();
      if (LOG.isTraceEnabled()) LOG.trace("id={} element={}", parts.id, parts.element);
    } else {
      parts.element = el;
    }
    return true;
  }

  private static boolean isElementValid(SelectorParts p) {
    return "*".equals(p.element)
        || "~".equals(p.element)
        || ElementInfo.isValidHTMLTag(p.element.toLowerCase(Locale.ROOT))
        || (p.element.trim().isEmpty()
            && (!p.className.isEmpty()
                || !p.id.isEmpty()
                || p.attSelections != null
                || !p.pseudoClass.isEmpty()));
  }

  private static boolean validateNames(SelectorParts p) {
    return !((!p.className.isEmpty() && !ElementInfo.isValidName(p.className))
        || (p.className.isEmpty() && !p.id.isEmpty() && !ElementInfo.isValidName(p.id)));
  }

  // returns -1 invalid, 0 ok, 1 banned
  private static int validatePseudoClass(String pseudo) {
    if (pseudo.isEmpty()) return 0;
    if (!ElementInfo.isValidPseudoClass(pseudo)) return -1;
    if (ElementInfo.isBannedPseudoClass(pseudo)) return 1;
    return 0;
  }

  private static boolean validateAttributeSelections(List<String> atts) {
    if (atts == null) return true;
    for (String attSelection : atts) {
      String[] parts = splitAttributeSelection(attSelection);
      if (LOG.isDebugEnabled())
        LOG.debug("HTMLelementVerifier length of attSelectionParts={}", parts.length);
      if (!isValidAttributeName(parts[0])) return false;
      if (!validateAttributeRHS(parts)) return false;
    }
    return true;
  }

  /** Splits an attribute selection at the first recognized operator (|=, ~=, ^=, $=, *=, =). */
  private static String[] splitAttributeSelection(String selection) {
    List<String> operators = Arrays.asList("|=", "~=", "^=", "$=", "*=", "=");
    for (String op : operators) {
      int idx = selection.indexOf(op);
      if (idx != -1) {
        return new String[] {selection.substring(0, idx), selection.substring(idx + op.length())};
      }
    }
    return new String[] {selection};
  }

  /** Validates the RHS of an attribute selection, if present. */
  private static boolean validateAttributeRHS(String[] parts) {
    if (parts.length <= 1) return true;
    if (LOG.isTraceEnabled()) LOG.trace("RHS is \"{}\"", parts[1]);
    return ElementInfo.isValidIdentifier(parts[1]) || ElementInfo.isValidStringWithQuotes(parts[1]);
  }

  private static boolean isValidAttributeName(String name) {
    if (name == null || name.isEmpty()) return false;
    char c = name.charAt(0);
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))) return false;
    for (int i = 1; i < name.length(); i++) {
      c = name.charAt(i);
      if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '-')) return false;
    }
    return true;
  }

  private static String buildSelector(SelectorParts p) {
    StringBuilder out = new StringBuilder();
    out.append(p.element);
    if (!p.className.isEmpty()) {
      out.append('.').append(p.className);
    } else if (!p.id.isEmpty()) {
      out.append('#').append(p.id);
    }
    if (!p.pseudoClass.isEmpty()) {
      out.append(':').append(p.pseudoClass);
    }
    if (p.attSelections != null) {
      for (String a : p.attSelections) {
        out.append('[').append(a).append(']');
      }
    }
    return out.toString();
  }

  /*
   * This function works with different operators, +, >, " " and verifies each HTML element with htmlElementVerifier(String elementString)
   * e.g., div > p:first-child
   * This would call HTMLelementVerifier with div and p:first-child
   * Returns null on failure (selectors invalid), empty string on banned but otherwise valid selector.
   */
  /**
   * Parses and validates a full selector list or a single selector and returns a sanitized form.
   *
   * <p>Callers pass either a single selector or a comma-delimited list; invalid or banned selectors
   * are removed according to policy. The returned string is suitable for re-serialization.
   *
   * @param selectorString selector or comma-separated list to validate and normalize.
   * @return a non-null string representing the sanitized selector(s); may be empty when nothing
   *     remains after filtering.
   */
  public String recursiveSelectorVerifier(String selectorString) {
    if (LOG.isTraceEnabled()) LOG.trace("selector: \"{}\"", selectorString);
    selectorString = selectorString.trim();
    // Parse but don't tokenize.
    SelectorSplitResult res = scanTopLevelSelector(selectorString);
    if (res.invalid) return null;
    if (LOG.isDebugEnabled())
      LOG.debug(
          "index={} quoting={} selector={} for \"{}\"",
          res.index,
          res.quoting,
          res.selector,
          selectorString);
    if (res.quoting != 0) return null; // Mismatched quotes
    if (res.bracketing != 0) return null; // Mismatched brackets
    if (res.index == -1) return htmlElementVerifier(selectorString, false);
    String left = selectorString.substring(0, res.index).trim();
    String right = selectorString.substring(res.index + 1).trim();
    if (LOG.isDebugEnabled())
      LOG.debug("recursiveSelectorVerifier parts[0]={} parts[1]={}", left, right);
    left = htmlElementVerifier(left, false);
    String verifiedRight = recursiveSelectorVerifier(right);
    if (left != null && verifiedRight != null) return left + res.selector + verifiedRight;
    return null;
  }

  private record SelectorSplitResult(
      int index, char selector, char quoting, int bracketing, boolean invalid) {}

  private static SelectorSplitResult scanTopLevelSelector(String selectorString) {
    ScanState st = new ScanState();
    for (int i = 0; i < selectorString.length(); i++) {
      st.process(selectorString.charAt(i), i);
      if (st.invalid) break;
    }
    return new SelectorSplitResult(st.index, st.selector, st.quoting, st.bracketing, st.invalid);
  }

  private static final class ScanState {
    int index = -1;
    char selector = 0;
    char quoting = 0;
    boolean escaping = false;
    int bracketing = 0;
    int escapedDigits = 0;
    boolean invalid = false;

    void process(char c, int i) {
      if (trySelectTopLevelCombinator(c, i)) return;
      if (tryHandleParentheses(c)) return;
      if (tryHandleQuotes(c)) return;
      if (tryInvalidateOnNewline(c, i)) return;
      if (tryHandleCR(c)) return;
      if (tryHandleLFOrFF(c, i)) return;
      if (tryHandleHexEscapeDigit(c)) return;
      if (tryHandleEscapeTerminatorWhitespace(c)) return;
      if (tryHandleBackslash(c, i)) return;
      finalizeGenericEscaping();
    }

    private boolean trySelectTopLevelCombinator(char c, int i) {
      if (quoting != 0 || escaping) return false;
      if (c == '+') {
        if (bracketing == 0 && shouldSetSelector(i)) {
          index = i;
          selector = c;
          return true;
        }
        return false;
      }
      if ((c == '>' || c == ' ') && shouldSetSelector(i)) {
        index = i;
        selector = c;
        return true;
      }
      return false;
    }

    private boolean shouldSetSelector(int i) {
      return index == -1 || (index == i - 1 && selector == ' ');
    }

    private boolean tryHandleParentheses(char c) {
      if (quoting != 0 || escaping) return false;
      if (c == '(') {
        bracketing += 1;
        return true;
      }
      if (c == ')') {
        bracketing -= 1;
        return true;
      }
      return false;
    }

    private boolean tryHandleQuotes(char c) {
      if (escaping) return false;
      if (quoting == 0) {
        if (c == '\'' || c == '"') {
          quoting = c;
          return true;
        }
        return false;
      }
      if (c == quoting) {
        quoting = 0;
        return true;
      }
      return false;
    }

    private boolean tryInvalidateOnNewline(char c, int i) {
      if ((c == '\r' || c == '\n' || c == '\f') && !(quoting != 0 && escaping)) {
        if (LOG.isTraceEnabled())
          LOG.trace("no newlines unless in a string *and* quoted at index {}", i);
        invalid = true;
        return true;
      }
      return false;
    }

    private boolean tryHandleCR(char c) {
      if (c == '\r' && escapedDigits == 0) {
        escaping = false;
        return true;
      }
      return false;
    }

    private boolean tryHandleLFOrFF(char c, int i) {
      if (c == '\n' || c == '\f') {
        if (escapedDigits == 0) {
          escaping = false;
        } else {
          if (LOG.isTraceEnabled()) LOG.trace("invalid newline escaping at char {}", i);
          invalid = true;
        }
        return true;
      }
      return false;
    }

    private boolean isHexDigit(char c) {
      return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private boolean tryHandleHexEscapeDigit(char c) {
      if (escaping && isHexDigit(c)) {
        escapedDigits++;
        if (escapedDigits == 6) escaping = false;
        return true;
      }
      return false;
    }

    private boolean tryHandleEscapeTerminatorWhitespace(char c) {
      if (escaping && escapedDigits > 0 && WS_T_R_N_F.indexOf(c) != -1) {
        escaping = false;
        return true;
      }
      return false;
    }

    private boolean tryHandleBackslash(char c, int i) {
      if (c != '\\') return false;
      if (!escaping) {
        escaping = true;
        escapedDigits = 0;
        return true;
      }
      if (escapedDigits > 0) {
        if (LOG.isTraceEnabled())
          LOG.trace("backslash but already escaping with digits at char {}", i);
        invalid = true;
        return true;
      }
      escaping = false;
      escapedDigits = 0;
      return true;
    }

    private void finalizeGenericEscaping() {
      if (escaping) {
        // Any other character can be escaped.
        escaping = false;
        escapedDigits = 0;
      }
    }
  }

  // main function
  /**
   * Runs the tokenizer and writes the sanitized CSS to the configured writer.
   *
   * <p>Parsing proceeds as a single pass over the reader. When {@code stopAtDetectedCharset} is
   * set, parsing stops immediately after an {@code @charset} is found, the value is exposed via
   * {@link #detectedCharset()}, and no output is produced. Otherwise, validated tokens and rules
   * are emitted to the writer.
   *
   * @throws IOException when an I/O error occurs while reading from the input or writing the
   *     output.
   */
  public void parse() throws IOException {
    new Parser().run();
  }

  // Parser implementation extracted from the former parse() body to enable
  // further decomposition and reduce the complexity of this entrypoint.
  private final class Parser {
    // Parser state (formerly locals) — kept as fields to minimize run() complexity
    static final int STATE1 = 1;
    static final int STATE2 = 2;
    static final int STATE3 = 3;
    static final int STATECOMMENT = 4;
    static final int STATE1INQUOTE = 5;
    static final int STATE2INQUOTE = 6;
    static final int STATE3INQUOTE = 7;

    char currentQuote = '"';
    int stateBeforeComment = 0;
    int currentState = STATE1;
    boolean isState1Present = false;
    StringBuilder filteredTokens = new StringBuilder();
    StringBuilder buffer = new StringBuilder();
    int openBraces = 0;
    String defaultMedia = V_SCREEN;
    String[] currentMedia = new String[] {defaultMedia};
    String propertyName = "";
    String propertyValue = "";
    boolean ignoreElementsS1 = false;
    boolean ignoreElementsS2 = false;
    boolean ignoreElementsS3 = false;
    boolean closeIgnoredS2 = false;
    int x;
    char c = 0;
    char prevc = 0;
    boolean s2Comma = false;
    boolean canImport = true;
    String whitespaceAfterColon = "";
    String whitespaceBeforeProperty = "";
    boolean charsetPossible = true;
    boolean bomPossible = true;
    int openBracesStartingS3 = 0;
    boolean forPage = false;

    // Early-exit coordination: set to true when helpers need to abort the full parse
    boolean stopRequested = false;

    // Thin entrypoint to keep complexity minimal at the callsite
    void run() throws IOException {
      runCore();
    }

    // Minimal coordinator: initialize, stream, dispatch, finalize
    void runCore() throws IOException {
      initParserState();
      if (isInline) currentState = STATE3;
      while (!stopRequested && nextChar()) {
        detectCommentStart();
        if (!stopRequested && c != 0) {
          handleCurrentStateChar();
        }
      }
      if (!stopRequested) finalizeOutput();
    }

    void requestStop() {
      stopRequested = true;
    }

    void initParserState() {
      currentQuote = '"';
      stateBeforeComment = 0;
      currentState = STATE1;
      isState1Present = false;
      filteredTokens.setLength(0);
      buffer.setLength(0);
      openBraces = 0;
      defaultMedia = V_SCREEN;
      currentMedia = new String[] {defaultMedia};
      propertyName = "";
      propertyValue = "";
      ignoreElementsS1 = ignoreElementsS2 = ignoreElementsS3 = closeIgnoredS2 = false;
      x = 0;
      c = 0;
      prevc = 0;
      s2Comma = false;
      canImport = true;
      whitespaceAfterColon = "";
      whitespaceBeforeProperty = "";
      charsetPossible = true;
      bomPossible = true;
      openBracesStartingS3 = 0;
      forPage = false;
    }

    boolean nextChar() throws IOException {
      while (true) {
        x = r.read();
        if (x == -1 && !synthesizeSemicolonIfNeeded()) return false;
        if (handlePossibleBom()) continue;
        bomPossible = false;
        prevc = c;
        c = (char) x;
        if (LOG.isTraceEnabled()) LOG.trace("Read: {} 0x{}", c, Integer.toHexString(c));
        return true;
      }
    }

    /** True when we synthesize a ';' to complete a pending property at EOF. */
    private boolean synthesizeSemicolonIfNeeded() {
      if (currentState == STATE3
          && c != ';'
          && !propertyName.isEmpty()
          && propertyValue.isEmpty()) {
        x = ';';
        return true;
      }
      return false;
    }

    /** Handles BOM at the current character; returns true if the caller should continue loop. */
    private boolean handlePossibleBom() throws IOException {
      if (x != (char) 0xFEFF) return false;
      if (bomPossible) {
        if (LOG.isTraceEnabled()) LOG.trace("Ignoring BOM");
        w.write(x);
      }
      return true;
    }

    void detectCommentStart() {
      if (prevc == '/'
          && c == '*'
          && currentState != STATE1INQUOTE
          && currentState != STATE2INQUOTE
          && currentState != STATE3INQUOTE
          && currentState != STATECOMMENT) {
        stateBeforeComment = currentState;
        currentState = STATECOMMENT;
        if (!buffer.isEmpty() && buffer.charAt(buffer.length() - 1) == '/')
          buffer.deleteCharAt(buffer.length() - 1);
        if (LOG.isTraceEnabled()) LOG.trace("Comment detected: buffer={}", buffer);
        prevc = 0;
      }
    }

    void handleCurrentStateChar() throws IOException {
      switch (currentState) {
        case STATE1 -> handleState1();
        case STATE1INQUOTE -> handleState1InQuote();
        case STATE2 -> handleState2();
        case STATE2INQUOTE -> handleState2InQuote();
        case STATE3 -> handleState3();
        case STATE3INQUOTE -> handleState3InQuote();
        case STATECOMMENT -> handleStateComment();
        default -> {
          // Intentionally ignore unknown state.
        }
      }
    }

    // Extracted handlers to reduce the complexity/LOC of handleCurrentStateChar()
    /**
     * Handle characters in STATE1 by delegating complex branches to focused helpers. This keeps the
     * top-level switch small, reducing cyclomatic and cognitive complexity while preserving
     * behavior.
     */
    void handleState1() throws IOException {
      switch (c) {
        case '}' -> handleState1RightBrace();
        case '\n', ' ', '\t' -> handleState1Whitespace();
        case '@' -> handleState1At();
        case '{' -> handleState1OpenBrace();
        case ';' -> handleState1Semicolon();
        case '"', '\'' -> handleState1EnterQuote();
        default -> handleState1Default();
      }
    }

    private void handleState1RightBrace() throws IOException {
      if (prevc == '\\') {
        buffer.append(c);
        return;
      }
      if (openBraces > 0) {
        openBraces--;
        if (!ignoreElementsS1) w.write('}');
      }
      buffer.setLength(0);
    }

    private void handleState1Whitespace() {
      buffer.append(c);
      if (LOG.isTraceEnabled()) LOG.trace("STATE1 CASE whitespace: {}", c);
    }

    private void handleState1At() {
      if (prevc != '\\') {
        isState1Present = true;
        if (LOG.isTraceEnabled()) LOG.trace("STATE1 CASE @: {}", c);
      }
      buffer.append(c);
    }

    private void handleState1EnterQuote() {
      if (prevc == '\\') {
        buffer.append(c); // Leave in buffer, encoded.
        return;
      }
      buffer.append(c);
      currentState = STATE1INQUOTE;
      currentQuote = c;
    }

    private void handleState1Default() {
      buffer.append(c);
      if (!isState1Present) {
        String s = buffer.toString().trim();
        if (!(s.isEmpty()
            || s.equals("/")
            || s.equals("<")
            || s.equals("<!")
            || s.equals("<!-")
            || s.equals("<!--"))) currentState = STATE2;
      }
      if (LOG.isTraceEnabled()) LOG.trace("STATE1 default CASE: {}", c);
    }

    // ===== STATE1 helpers =====
    /** Handles the '{' branch while in STATE1. */
    private void handleState1OpenBrace() throws IOException {
      charsetPossible = false;
      if (stopAtDetectedCharset) {
        requestStop();
        return;
      }
      if (prevc == '\\') {
        buffer.append(c); // Leave in buffer, encoded.
        return;
      }
      openBraces++;
      isState1Present = false;

      String braceSpace = extractLeadingWhitespaceAndOptionalHtmlComment();
      if (braceSpace == null) return; // Logged already

      String postSpace = extractTrailingWhitespaceAndTrim();
      String orig = buffer.toString().trim();
      ParsedWord[] parts = split(orig, false);
      if (LOG.isTraceEnabled())
        LOG.trace(MSG_SPLIT_STATE1_OPEN_BRACE, CSSPropertyVerifier.toString(parts));
      buffer.setLength(0);
      boolean valid = processState1OpenBraceParts(parts, braceSpace, postSpace, orig);

      if (!valid) {
        ignoreElementsS1 = true; // No valid media types.
        if (LOG.isDebugEnabled())
          LOG.debug("STATE1 CASE {: Failed verification test. ignoring {}", buffer);
      } else {
        w.write(filteredTokens.toString());
        filteredTokens.setLength(0);
      }

      buffer.setLength(0);
      s2Comma = false;
      if (forPage) {
        currentState = STATE3;
        openBracesStartingS3 = openBraces;
      } else {
        currentState = STATE2;
      }
      buffer.setLength(0);
    }

    private boolean processState1OpenBraceParts(
        ParsedWord[] parts, String braceSpace, String postSpace, String orig) {
      if (parts == null || parts.length < 1) {
        ignoreElementsS1 = true;
        if (LOG.isDebugEnabled())
          LOG.debug("STATE1 CASE {: Does not have one part. ignoring {}", buffer);
        return false;
      }
      if (parts[0] instanceof SimpleParsedWord spw) {
        String head = spw.original;
        if ("@media".equalsIgnoreCase(head)) {
          return processAtMedia(parts, braceSpace, postSpace);
        }
        if ("@page".equalsIgnoreCase(head)) {
          return processAtPage(parts, braceSpace, postSpace, orig);
        }
      }
      return false;
    }

    /** Processes the ';' branch while in STATE1 (e.g., @import or @charset). */
    private void handleState1Semicolon() throws IOException {
      if (prevc == '\\') {
        buffer.append(c); // Leave in buffer, encoded.
        return;
      }
      if (LOG.isTraceEnabled()) LOG.trace("buffer in state 1 ; : \"{}\"", buffer);

      writeLeadingWhitespaceAndOptionalHtmlComment();

      // Handle either @import or @charset; short-circuit to avoid double handling
      if (!tryHandleImport()) {
        tryHandleCharset();
      }

      isState1Present = false;
      ignoreElementsS1 = false;
      buffer.setLength(0);
      charsetPossible = false;
    }

    private void writeLeadingWhitespaceAndOptionalHtmlComment() throws IOException {
      int i = 0;
      while (i < buffer.length() && WS_T_R_N_F.indexOf(buffer.charAt(i)) != -1) {
        i++;
      }
      w.write(buffer.substring(0, i));
      buffer.delete(0, i);

      if (buffer.length() > 4 && buffer.substring(0, 4).equals("<!--")) {
        w.write(buffer.substring(0, 4));
        if (WS_T_R_N.indexOf(buffer.charAt(4)) == -1) {
          LOG.error(MSG_HTML_COMMENT_WS_LEADING);
          return;
        }
        buffer.delete(0, 4);
        // Restart the whitespace scan after the comment from the new buffer start.
        i = 0;
        while (i < buffer.length() && WS_T_R_N_F.indexOf(buffer.charAt(i)) != -1) {
          i++;
        }
        w.write(buffer.substring(0, i));
        buffer.delete(0, i);
      }
    }

    private boolean tryHandleImport() throws IOException {
      if (!(canImport && !ignoreElementsS1 && buffer.toString().contains("@import"))) return false;
      writeFilteredImportIfValid();
      return true;
    }

    private void tryHandleCharset() throws IOException {
      if (!(charsetPossible && buffer.toString().startsWith("@charset "))) return;
      String s = buffer.delete(0, "@charset ".length()).toString();
      s = removeOuterQuotes(s);
      detectedCharset = s;
      if (LOG.isTraceEnabled()) LOG.trace("Detected charset: \"{}\"", detectedCharset);
      if (!Charset.isSupported(detectedCharset)) {
        LOG.info("Charset not supported: {}", detectedCharset);
        throw new UnsupportedCharsetInFilterException("Charset not supported: " + detectedCharset);
      }
      if (stopAtDetectedCharset) {
        requestStop();
        return;
      }
      if (passedCharset != null && !detectedCharset.equalsIgnoreCase(passedCharset)) {
        LOG.info(
            "Detected charset \"{}\" differs from passed in charset \"{}\"",
            detectedCharset,
            passedCharset);
        throw new IOException("Detected charset differs from passed in charset");
      }
      w.write("@charset \"" + detectedCharset + "\";");
    }

    /**
     * Returns prefix whitespace plus an optional HTML comment marker; null on an invalid pattern.
     */
    private String extractLeadingWhitespaceAndOptionalHtmlComment() {
      int i = 0;
      while (i < buffer.length() && WS_T_R_N_F.indexOf(buffer.charAt(i)) != -1) {
        i++;
      }
      String prefix = buffer.substring(0, i);
      buffer.delete(0, i);
      if (buffer.length() > 4 && buffer.substring(0, 4).equals("<!--")) {
        prefix += buffer.substring(0, 4);
        if (WS_T_R_N.indexOf(buffer.charAt(4)) == -1) {
          LOG.error(MSG_HTML_COMMENT_WS_PREFIX);
          return null;
        }
        buffer.delete(0, 4);
        // Restart the whitespace scan after the comment from the new buffer start.
        i = 0;
        while (i < buffer.length() && WS_T_R_N_F.indexOf(buffer.charAt(i)) != -1) {
          i++;
        }
        prefix += buffer.substring(0, i);
        buffer.delete(0, i);
      }
      return prefix;
    }

    /** Trims trailing whitespace from buffer and returns that whitespace. */
    private String extractTrailingWhitespaceAndTrim() {
      int i;
      i = buffer.length() - 1;
      while (i >= 0 && WS_T_R_N_F.indexOf(buffer.charAt(i)) != -1) {
        i--;
      }
      i++;
      String postSpace = buffer.substring(i);
      buffer.setLength(i);
      return postSpace;
    }

    /** Handles @media parts assembly and filtering. Returns true when valid. */
    private boolean processAtMedia(ParsedWord[] parts, String braceSpace, String postSpace) {
      List<String> medias = commaListFromIdentifiers(parts);
      if (!medias.isEmpty()) {
        for (int i = medias.size() - 1; i >= 0; i--) {
          if (!FilterUtils.isMedia(medias.get(i))) {
            medias.remove(i);
          }
        }
      }
      if (!medias.isEmpty()) {
        filteredTokens.append(braceSpace);
        filteredTokens.append("@media ");
        boolean first = true;
        for (String media : medias) {
          if (!first) filteredTokens.append(", ");
          first = false;
          filteredTokens.append(media);
        }
        filteredTokens.append(postSpace);
        filteredTokens.append("{");
        currentMedia = medias.toArray(new String[0]);
        return true;
      }
      return false;
    }

    /** Handles @page validation/assembly and returns true when valid. */
    private boolean processAtPage(
        ParsedWord[] parts, String braceSpace, String postSpace, String orig) {
      boolean valid = parts.length == 0;
      if (!valid) {
        valid = true;
        for (int j = 1; j < parts.length && valid; j++) {
          if (!(parts[j] instanceof SimpleParsedWord)) {
            valid = false;
          } else {
            String s = parts[j].original;
            if (!(s.equalsIgnoreCase(":left")
                || s.equalsIgnoreCase(":right")
                || s.equals(":first"))) {
              valid = false;
            }
          }
        }
      }
      if (valid) {
        forPage = true;
        filteredTokens.append(braceSpace);
        filteredTokens.append(orig);
        filteredTokens.append(postSpace);
        filteredTokens.append("{");
      }
      return valid;
    }

    /** Writes a sanitized @import if valid; no-op when invalid. */
    private void writeFilteredImportIfValid() throws IOException {
      if (LOG.isTraceEnabled()) LOG.trace("STATE1 CASE ;statement={}", buffer);
      String strbuffer = buffer.toString().trim();
      int importIndex = strbuffer.toLowerCase(Locale.ROOT).indexOf("@import");
      if (!isImportAtStart(strbuffer, importIndex)) return;
      ParsedWord[] strparts = split(strbuffer.substring(importIndex + 7), false);
      if (!isValidImportHead(strparts)) return;

      String uri = extractImportUri(strparts[0]);
      List<String> medias = commaListFromIdentifiers(strparts);
      // If extra tokens exist but parsing yielded no valid media, treat as broken and skip
      if (strparts.length > 1 && medias.isEmpty()) return;

      try {
        String output = buildImportOutput(uri, medias);
        w.write(output);
      } catch (CommentException _) {
        // Don't write anything
      }
    }

    private boolean isImportAtStart(String strbuffer, int importIndex) {
      return importIndex >= 0 && strbuffer.substring(0, importIndex).trim().isEmpty();
    }

    private boolean isValidImportHead(ParsedWord[] strparts) {
      return !(strparts == null
          || strparts.length == 0
          || !(strparts[0] instanceof ParsedURL || strparts[0] instanceof ParsedString));
    }

    private String extractImportUri(ParsedWord head) {
      if (head instanceof ParsedURL url) return url.getDecoded();
      // Fallback: the head must be a ParsedString per isValidImportHead()
      if (head instanceof ParsedString string) return string.getDecoded();
      // Defensive: should not happen; return original encoding
      return head == null ? null : head.original;
    }

    private String buildImportOutput(String uri, List<String> medias) throws CommentException {
      StringBuilder output = new StringBuilder();
      output.append("@import url(\"");
      String s = cb.processURI(uri, "text/css");
      if (passedCharset != null) {
        if (s.indexOf('?') == -1) s += "?maybecharset=" + passedCharset;
        else s += "&maybecharset=" + passedCharset;
      }
      output.append(s);
      output.append("\")");
      boolean first = true;
      for (String media : medias) {
        if (FilterUtils.isMedia(media)) {
          if (!first) output.append(", ");
          else output.append(' ');
          first = false;
          output.append(media);
        }
      }
      output.append(";");
      return output.toString();
    }

    void handleState1InQuote() {
      if (LOG.isTraceEnabled()) LOG.trace("STATE1INQUOTE: {}", c);
      switch (c) {
        case '"' -> {
          if (currentQuote == '"' && prevc != '\\') currentState = STATE1;
          buffer.append(c);
        }
        case '\'' -> {
          if (currentQuote == '\'' && prevc != '\\') currentState = STATE1;
          buffer.append(c);
        }
        case '\n', '\f', '\r' -> {
          if (c == '\n' && prevc == '\r') {
            return;
          }
          if (prevc != '\\') {
            ignoreElementsS1 = true;
            currentState = STATE1;
          } else {
            // Wipe out the \\ as well.
            buffer.setLength(buffer.length() - 1);
          }
        }
        default -> buffer.append(c);
      }
    }

    void handleState2() throws IOException {
      canImport = false;
      charsetPossible = false;
      if (stopAtDetectedCharset) {
        requestStop();
        return;
      }
      switch (c) {
        case '{' -> handleState2OpenBrace();
        case ',' -> handleState2Comma();
        case '}' -> handleState2RightBrace();
        case '"', '\'' -> handleState2EnterQuote();
        default -> {
          buffer.append(c);
          if (LOG.isTraceEnabled()) LOG.trace("STATE2 default CASE: {}", c);
        }
      }
    }

    // ===== STATE2 helpers =====
    private void handleState2OpenBrace() {
      if (prevc == '\\') {
        buffer.append(c);
        return;
      }
      String ws = extractLeadingWhitespaceAndOptionalHtmlComment();
      if (ws == null) return;
      openBraces++;
      processSelectorAfterOpenBrace(ws);
      currentState = STATE3;
      openBracesStartingS3 = openBraces;
      if (LOG.isDebugEnabled())
        LOG.debug("STATE2 -> STATE3, openBracesStartingS3 = {}", openBracesStartingS3);
      buffer.setLength(0);
    }

    private void processSelectorAfterOpenBrace(String ws) {
      if (buffer.toString().trim().isEmpty()) {
        handleInvalidSelector();
        return;
      }
      String filtered = recursiveSelectorVerifier(buffer.toString());
      if (filtered != null && !filtered.isEmpty()) {
        appendFilteredSelectorOpenBrace(ws, filtered);
      } else if (s2Comma && "".equals(filtered)) {
        handleCommaEmptyFiltered(ws);
      } else {
        handleInvalidSelector();
      }
      if (LOG.isTraceEnabled()) LOG.trace("STATE2 CASE { filtered elements{}", filtered);
    }

    private void appendFilteredSelectorOpenBrace(String ws, String filtered) {
      if (s2Comma) {
        if (!filteredTokens.isEmpty()) filteredTokens.append(",");
        s2Comma = false;
      }
      filteredTokens.append(ws);
      filteredTokens.append(filtered);
      filteredTokens.append(" {");
    }

    private void handleCommaEmptyFiltered(String ws) {
      String sofar = filteredTokens.toString().trim();
      if (sofar.isEmpty()) {
        // All selectors were banned; ignore this whole rule
        ignoreElementsS2 = true;
        filteredTokens.setLength(0);
      } else {
        s2Comma = false;
        filteredTokens.append(ws);
        filteredTokens.append(" {");
      }
    }

    private void handleInvalidSelector() {
      ignoreElementsS2 = true;
      filteredTokens.setLength(0);
    }

    private void handleState2Comma() {
      if (prevc == '\\') {
        buffer.append(c);
        return;
      }
      String ws = extractLeadingWhitespace();
      applyFilteredSelectorOnComma(ws);
      buffer.setLength(0);
    }

    private String extractLeadingWhitespace() {
      int i = 0;
      while (i < buffer.length() && WS_T_R_N_F.indexOf(buffer.charAt(i)) != -1) {
        i++;
      }
      if (LOG.isDebugEnabled()) LOG.debug(MSG_APPEND_WS_STATE2, buffer.substring(0, i));
      String ws = buffer.substring(0, i);
      buffer.delete(0, i);
      return ws;
    }

    private void applyFilteredSelectorOnComma(String ws) {
      if (!buffer.toString().trim().isEmpty()) {
        String filtered = recursiveSelectorVerifier(buffer.toString());
        if (LOG.isTraceEnabled()) LOG.trace("STATE2 CASE , filtered elements{}", filtered);
        if (filtered != null && !filtered.isEmpty()) {
          if (s2Comma) filteredTokens.append(",");
          else s2Comma = true;
          filteredTokens.append(ws);
          filteredTokens.append(filtered);
        } else if ("".equals(filtered)) {
          // Valid but banned. Only proceed later if we had at least one previously accepted
          // selector. Otherwise, ignore the whole rule.
          filteredTokens.append(ws);
          s2Comma = true;
        }
      } else {
        s2Comma = true;
      }
    }

    private void handleState2RightBrace() throws IOException {
      if (LOG.isTraceEnabled()) LOG.trace("STATE2 CASE }: {}", c);
      if (prevc == '\\') {
        buffer.append(c);
        return;
      }
      if (openBraces > 0 && !ignoreElementsS1) {
        openBraces--;
        // openBraces was > 0, so after decrement it's >= 0
        filteredTokens.append('}');
        if (LOG.isTraceEnabled()) LOG.trace("Writing \"{}\"", filteredTokens);
        w.write(filteredTokens.toString());
      } else {
        if (openBraces > 0) openBraces--;
        // Ignore (closing an ignored block or when S1 was ignored)
      }
      filteredTokens.setLength(0);
      buffer.setLength(0);
      currentMedia = new String[] {defaultMedia};
      isState1Present = false;
      currentState = STATE1;
      // We are going back to STATE1, so reset ignoreElementsS1
      ignoreElementsS1 = false;
    }

    private void handleState2EnterQuote() {
      if (prevc == '\\') {
        buffer.append(c);
        return;
      }
      buffer.append(c);
      currentState = STATE2INQUOTE;
      currentQuote = c;
    }

    void handleState2InQuote() {
      if (LOG.isTraceEnabled()) LOG.trace("STATE2INQUOTE: {}", c);
      charsetPossible = false;
      switch (c) {
        case '"' -> {
          if (currentQuote == '"' && prevc != '\\') currentState = STATE2;
          buffer.append(c);
        }
        case '\'' -> {
          if (currentQuote == '\'' && prevc != '\\') currentState = STATE2;
          buffer.append(c);
        }
        case '\n', '\f', '\r' -> {
          if (c == '\n' && prevc == '\r') {
            return;
          }
          if (prevc != '\\') {
            ignoreElementsS2 = true;
            closeIgnoredS2 = true;
            currentState = STATE2;
          } else {
            buffer.setLength(buffer.length() - 1);
          }
        }
        default -> buffer.append(c);
      }
    }

    void handleState3() throws IOException {
      charsetPossible = false;
      if (stopAtDetectedCharset) {
        requestStop();
        return;
      }
      switch (c) {
        case ':' -> handleState3Colon();
        case ';' -> handleState3Semicolon();
        case '}' -> handleState3RightBrace();
        case '{' -> handleState3LeftBrace();
        case '"', '\'' -> handleState3EnterQuote();
        default -> {
          buffer.append(c);
          if (LOG.isTraceEnabled()) LOG.trace("STATE3 default CASE : {}", c);
        }
      }
    }

    // ===== STATE3 helpers =====
    private void handleState3Colon() {
      if (prevc == '\\') {
        buffer.append(c);
        return;
      }
      if (openBraces > openBracesStartingS3) {
        buffer.append(c);
        if (LOG.isDebugEnabled())
          LOG.debug(MSG_OPEN_BRACES_S3_COLON, openBraces, openBracesStartingS3);
        return;
      }
      int i = 0;
      while (i < buffer.length() && WS_T_R_N_F.indexOf(buffer.charAt(i)) != -1) {
        i++;
      }
      if (LOG.isTraceEnabled()) LOG.trace("Appending whitespace: {}", buffer.substring(0, i));
      whitespaceBeforeProperty = buffer.substring(0, i);
      propertyName = buffer.delete(0, i).toString().trim();
      if (LOG.isTraceEnabled()) LOG.trace("Property name: {}", propertyName);
      buffer.setLength(0);
      if (LOG.isTraceEnabled()) LOG.trace("STATE3 CASE :: {}", c);
    }

    private void handleState3Semicolon() {
      if (prevc == '\\') {
        buffer.append(c);
        return;
      }
      if (openBraces > openBracesStartingS3) {
        buffer.append(c);
        if (LOG.isDebugEnabled())
          LOG.debug(MSG_OPEN_BRACES_S3_SEMI, openBraces, openBracesStartingS3);
        return;
      }
      preparePropertyValueFromBuffer();
      CSSPropertyVerifier obj = getVerifier(propertyName);
      if (obj != null) {
        ParsedWord[] words = split(propertyValue, obj.allowCommaDelimiters);
        if (LOG.isTraceEnabled())
          LOG.trace(MSG_SPLIT_STATE3_SEMI, CSSPropertyVerifier.toString(words));
        appendPropertyIfValid(words, obj, true);
      } else if (LOG.isTraceEnabled()) {
        LOG.trace(MSG_NO_SUCH_PROPERTY_NAME_SEMI, propertyName);
      }
      ignoreElementsS3 = false;
      propertyName = "";
      propertyValue = "";
    }

    private void preparePropertyValueFromBuffer() {
      int i = 0;
      while (i < buffer.length() && WS_T_R_N_F.indexOf(buffer.charAt(i)) != -1) {
        i++;
      }
      if (LOG.isDebugEnabled())
        LOG.debug("STATE3 after-colon whitespace before ';': \"{}\"", buffer.substring(0, i));
      whitespaceAfterColon = buffer.substring(0, i);
      propertyValue = buffer.delete(0, i).toString().trim();
      if (LOG.isTraceEnabled()) LOG.trace(MSG_PROPERTY_VALUE_SEMI, propertyValue);
      buffer.setLength(0);
    }

    /**
     * Determines whether a CSS property/value is valid for the given media and elements.
     *
     * <p>Example usage context: inside a media block, for a set of elements and a given
     * property/value pair, validate and optionally transform tokens before appending to the
     * filtered output.
     */
    @SuppressWarnings("SameParameterValue")
    private boolean verifyToken(
        String[] media, String[] elements, CSSPropertyVerifier obj, ParsedWord[] words) {
      if (words == null) return false;
      if (LOG.isTraceEnabled())
        LOG.trace("verifyToken for {}", CSSPropertyVerifier.toString(words));
      if (obj == null) {
        return false;
      }
      int important = checkImportant(words);
      if (important > 0) {
        if (words.length == important) return true; // Eh? !important on its own!
        words = Arrays.copyOf(words, words.length - important);
      }
      return obj.checkValidity(media, elements, words, cb);
    }

    // CSS minimizer often removes space between token and !important
    private int checkImportant(ParsedWord[] words) {
      if (words.length == 0) return 0;
      if (words[words.length - 1] instanceof SimpleParsedWord
          && words[words.length - 1].original.equalsIgnoreCase("!important")) return 1;
      if (words.length >= 2
          && words[words.length - 1] instanceof ParsedIdentifier
          && words[words.length - 2] instanceof SimpleParsedWord
          && words[words.length - 2].original.equals("!")
          && words[words.length - 1].original.equalsIgnoreCase("important")) return 2;
      return 0;
    }

    private void appendPropertyIfValid(
        ParsedWord[] words, CSSPropertyVerifier obj, boolean addSemicolon) {
      if (!ignoreElementsS2 && !ignoreElementsS3 && verifyToken(currentMedia, null, obj, words)) {
        if (changedAnything(words)) propertyValue = reconstruct(words);
        filteredTokens.append(whitespaceBeforeProperty);
        whitespaceBeforeProperty = "";
        filteredTokens.append(propertyName);
        filteredTokens.append(':');
        filteredTokens.append(whitespaceAfterColon);
        filteredTokens.append(propertyValue);
        if (addSemicolon) filteredTokens.append(';');
        if (LOG.isDebugEnabled())
          LOG.debug("STATE3 CASE ;: appending {}:{}", propertyName, propertyValue);
        if (LOG.isDebugEnabled()) LOG.debug("filtered tokens now: \"{}\"", filteredTokens);
      } else if (LOG.isDebugEnabled()) {
        LOG.debug(
            "filtered tokens now (ignored): \"{}\" words={} ignoreS1={} ignoreS2={} ignoreS3={}",
            filteredTokens,
            CSSPropertyVerifier.toString(words),
            ignoreElementsS1,
            ignoreElementsS2,
            ignoreElementsS3);
      }
    }

    private void handleState3RightBrace() throws IOException {
      if (prevc == '\\') {
        buffer.append(c);
        return;
      }
      openBraces--;
      if (openBraces > openBracesStartingS3 - 1) {
        buffer.append(c);
        if (LOG.isDebugEnabled())
          LOG.debug(MSG_OPEN_BRACES_S3_RBRACE, openBraces, openBracesStartingS3);
        if (openBraces < 0) openBraces = 0;
        return;
      }
      if (openBraces < 0) openBraces = 0;
      String postSpace = extractTrailingWhitespaceAndTrim();
      if (!propertyName.isEmpty()) processRightBracePendingProperty();
      else appendPrefixWhitespaceFromBuffer();
      finalizeAfterRightBrace(postSpace);
    }

    private void processRightBracePendingProperty() {
      int i = 0;
      while (i < buffer.length() && WS_T_R_N_F.indexOf(buffer.charAt(i)) != -1) {
        i++;
      }
      if (LOG.isDebugEnabled()) LOG.debug(MSG_APPEND_WS_AFTER_COLON_RBRACE, buffer.substring(0, i));
      whitespaceAfterColon = buffer.substring(0, i);
      buffer.delete(0, i);
      propertyValue = buffer.toString().trim();
      if (LOG.isTraceEnabled()) LOG.trace(MSG_PROPERTY_VALUE_RBRACE, propertyValue);
      buffer.setLength(0);
      CSSPropertyVerifier obj = getVerifier(propertyName);
      if (LOG.isDebugEnabled())
        LOG.debug("Found PropertyName:{} propertyValue:{}", propertyName, propertyValue);
      if (obj != null) {
        ParsedWord[] words = split(propertyValue, obj.allowCommaDelimiters);
        if (LOG.isTraceEnabled())
          LOG.trace(MSG_SPLIT_STATE3_RBRACE, CSSPropertyVerifier.toString(words));
        appendPropertyIfValid(words, obj, false);
      } else {
        if (LOG.isTraceEnabled()) LOG.trace(MSG_NO_SUCH_PROPERTY_NAME_RBRACE, propertyName);
      }
      propertyName = "";
    }

    private void appendPrefixWhitespaceFromBuffer() {
      int i = 0;
      while (i < buffer.length() && WS_T_R_N_F.indexOf(buffer.charAt(i)) != -1) {
        i++;
      }
      if (LOG.isDebugEnabled()) LOG.debug(MSG_APPEND_WS_PREFIX_RBRACE, buffer.substring(0, i));
      filteredTokens.append(buffer, 0, i);
      buffer.delete(0, i);
    }

    private void finalizeAfterRightBrace(String postSpace) throws IOException {
      ignoreElementsS3 = false;
      if (!ignoreElementsS2 || closeIgnoredS2) {
        filteredTokens.append(postSpace);
        filteredTokens.append("}");
        closeIgnoredS2 = false;
      }
      ignoreElementsS2 = false;
      if (!ignoreElementsS1) {
        w.write(filteredTokens.toString());
        if (LOG.isDebugEnabled()) LOG.debug("writing filtered tokens: \"{}\"", filteredTokens);
      }
      filteredTokens.setLength(0);
      whitespaceAfterColon = "";
      if (forPage) {
        forPage = false;
        currentState = STATE1;
      } else {
        currentState = STATE2;
      }
      if (isInline) {
        requestStop();
        return;
      }
      buffer.setLength(0);
      s2Comma = false;
      if (LOG.isTraceEnabled()) LOG.trace("STATE3 CASE }: {}", c);
    }

    private void handleState3LeftBrace() {
      openBraces++;
      buffer.append(c);
      if (LOG.isTraceEnabled()) LOG.trace("openBraces now {} in S3", openBraces);
    }

    private void handleState3EnterQuote() {
      if (prevc == '\\') {
        buffer.append(c);
        return;
      }
      buffer.append(c);
      currentState = STATE3INQUOTE;
      currentQuote = c;
    }

    void handleState3InQuote() {
      charsetPossible = false;
      if (stopAtDetectedCharset) {
        requestStop();
        return;
      }
      if (LOG.isTraceEnabled()) LOG.trace("STATE3INQUOTE: {}", c);
      switch (c) {
        case '"' -> {
          if (currentQuote == '"' && prevc != '\\') currentState = STATE3;
          buffer.append(c);
        }
        case '\'' -> {
          if (currentQuote == '\'' && prevc != '\\') currentState = STATE3;
          buffer.append(c);
        }
        case '\n', '\r', '\f' -> {
          if (c == '\n' && prevc == '\r') {
            return;
          }
          if (prevc != '\\') {
            ignoreElementsS3 = true;
            currentState = STATE3;
          } else {
            buffer.setLength(buffer.length() - 1);
          }
        }
        default -> buffer.append(c);
      }
    }

    void handleStateComment() {
      charsetPossible = false;
      if (stopAtDetectedCharset) {
        requestStop();
        return;
      }
      if (c == '/' && prevc == '*') {
        currentState = stateBeforeComment;
        c = 0;
        if (LOG.isTraceEnabled()) LOG.trace("Exiting the comment state {}", currentState);
      }
    }

    // legacy inline state blocks removed; handled by helper methods above
    void finalizeOutput() throws java.io.IOException {
      if (LOG.isTraceEnabled()) LOG.trace("Filtered tokens: \"{}\"", filteredTokens);
      w.write(filteredTokens.toString());
      for (int i = 0; i < openBraces; i++) w.write('}');
      if (LOG.isTraceEnabled()) LOG.trace("Remaining buffer: \"{}\"", buffer);
      int i = 0;
      while (i < buffer.length() && WS_T_R_N_F.indexOf(buffer.charAt(i)) != -1) {
        i++;
      }
      w.write(buffer.substring(0, i));
      buffer.delete(0, i);
      while (buffer.toString().trim().equals("-->")) {
        w.write("-->");
        buffer.delete(0, 3);
        // Reset index before scanning leading whitespace for the new buffer state
        int j = 0;
        while (j < buffer.length() && WS_T_R_N_F.indexOf(buffer.charAt(j)) != -1) {
          j++;
        }
        if (j > 0) {
          w.write(buffer.substring(0, j));
          buffer.delete(0, j);
        }
      }
      // CSS2.1 section 4.2 "Unexpected end of style sheet".
      // We do NOT auto-close at the end.
      // It might be worth implementing this one day.
    }

    // -- Reconstruction helpers (moved into Parser) --
    private String reconstruct(ParsedWord[] words) {
      StringBuilder sb = new StringBuilder();
      boolean first = true;
      ParsedWord lastWord = null;
      for (ParsedWord word : words) {
        appendCommaIfNeeded(sb, lastWord);
        lastWord = word;
        if (!first) sb.append(' ');
        appendWord(sb, word);
        first = false;
      }
      if (LOG.isTraceEnabled()) LOG.trace("Reconstructed: \"{}\"", sb);
      return sb.toString();
    }

    private void appendWord(StringBuilder sb, ParsedWord word) {
      if (!word.changed) {
        sb.append(word.original);
        if (LOG.isTraceEnabled()) LOG.trace("Adding word (original): \"{}\"", word.original);
      } else {
        String enc = word.encode(false); // pass true if charset is full Unicode
        sb.append(enc);
        if (LOG.isTraceEnabled()) LOG.trace("Adding word (new): \"{}\"", enc);
      }
    }

    private static void appendCommaIfNeeded(StringBuilder sb, ParsedWord lastWord) {
      if (lastWord != null && lastWord.postComma) sb.append(',');
    }

    private boolean changedAnything(ParsedWord[] words) {
      for (ParsedWord word : words) {
        if (word.changed) return true;
      }
      return false;
    }

    private List<String> commaListFromIdentifiers(ParsedWord[] parts) {
      ArrayList<String> out = new ArrayList<>(Math.max(0, parts.length - 1));
      if (parts.length <= 1) return out;

      if (parts.length == 2 && parts[1] instanceof ParsedIdentifier id) {
        out.add(id.getDecoded());
        return out;
      }

      boolean first = true;
      for (ParsedWord word : parts) {
        if (first) {
          first = false;
          continue;
        }
        if (!appendFromWord(out, word)) return new ArrayList<>(); // broken: signal to caller
      }
      return out;
    }

    /** Adds identifier(s) represented by the word to the output list. */
    private static boolean appendFromWord(List<String> out, ParsedWord word) {
      if (word instanceof ParsedIdentifier id) {
        out.add(id.getDecoded());
        return true;
      }
      if (word instanceof SimpleParsedWord) {
        String data = word.original;
        String[] split = FilterUtils.removeWhiteSpace(FilterUtils.splitOnChar(data, ','), false);
        out.addAll(Arrays.asList(split));
        return true;
      }
      return false;
    }
  }

  /**
   * Base token produced by the tokenizer. Subclasses represent concrete token kinds used by
   * property verifiers (identifiers, strings, URLs, counters, etc.).
   */
  abstract static class ParsedWord {
    /** Original source lexeme preserved for re-encoding when unchanged. */
    final String original;

    /** Has decoded changed? If not, we can use the original. */
    protected boolean changed;

    /** Whether this token immediately follows a comma in the source (affects list parsing). */
    boolean postComma;

    /**
     * Constructs a parsed token.
     *
     * @param original original lexeme as extracted from the source.
     * @param changed when {@code true}, forces re-encoding from the decoded representation.
     */
    protected ParsedWord(String original, boolean changed) {
      this.original = original;
      this.changed = changed;
    }

    /**
     * Returns the encoded representation of this token suitable for output.
     *
     * @param unicode when {@code true}, emits certain non-ASCII characters without escaping.
     * @return encoded token text using either the original lexeme or the decoded value.
     */
    public String encode(boolean unicode) {
      if (!changed) return original;
      else {
        StringBuilder out = new StringBuilder();
        innerEncode(unicode, out);
        return out.toString();
      }
    }

    @Override
    public String toString() {
      return super.toString() + ":\"" + original + "\"";
    }

    /**
     * Encodes this token back to CSS, appending characters to {@code out} using the provided {@code
     * unicode} policy.
     *
     * @param unicode when {@code true}, non-ASCII characters may be emitted as-is; otherwise they
     *     are escaped using CSS hexadecimal escapes.
     * @param out destination buffer that receives the encoded token content; never {@code null}.
     */
    protected abstract void innerEncode(boolean unicode, StringBuilder out);
  }

  /**
   * Base implementation for tokens that encode from a decoded form and decide per-character whether
   * an escape is required. Does not represent function-like constructs ({@code counter()}, etc.).
   * Only keywords and strings are handled here.
   */
  abstract static class BaseParsedWord extends ParsedWord {
    private String decoded;

    /**
     * Creates a token with both the original lexeme and its decoded form.
     *
     * @param original the original source lexeme as it appeared in the stylesheet; retained for
     *     reuse when no transformation is necessary.
     * @param decoded normalized value used for validation and re-encoding decisions.
     * @param changed set {@code true} when the original encoding was unsuitable and the decoded
     *     value should be used when re-serializing.
     */
    BaseParsedWord(String original, String decoded, boolean changed) {
      super(original, changed);
      this.decoded = decoded;
    }

    @Override
    protected void innerEncode(boolean unicode, StringBuilder out) {
      char prevc;
      char c = 0;
      for (int i = 0; i < decoded.length(); i++) {
        prevc = c;
        c = decoded.charAt(i);
        if (!mustEncode(c, i, prevc, unicode)) {
          out.append(c);
        } else {
          encodeChar(c, out);
        }
      }
    }

    /**
     * Determines whether a character must be escaped in CSS output at the given position.
     *
     * @param c character under consideration for encoding.
     * @param i zero-based index of {@code c} in the decoded string.
     * @param prevc previous character, or undefined when {@code i == 0}.
     * @param unicode when {@code true}, permits emitting certain non-ASCII characters directly.
     * @return {@code true} when {@code c} must be escaped; {@code false} otherwise.
     */
    protected abstract boolean mustEncode(char c, int i, char prevc, boolean unicode);

    private void encodeChar(char c, StringBuilder sb) {
      String s = Integer.toHexString(c);
      sb.append('\\');
      int x = 6 - s.length();
      sb.repeat("0", x);
      sb.append(s);
    }

    /**
     * Returns the decoded value for this token used by verifiers and for re-serialization.
     *
     * @return an immutable snapshot of the decoded value held by this token.
     */
    public String getDecoded() {
      return decoded;
    }

    /**
     * Replaces the decoded value and marks this token as changed so that re-encoding uses the new
     * value instead of the original lexeme.
     *
     * @param s new decoded value to adopt; should be a verifier-sanitized string.
     */
    public void setNewValue(String s) {
      this.changed = true;
      this.decoded = s;
    }
  }

  /** Token representing an identifier (e.g., property value keywords or selectors). */
  static class ParsedIdentifier extends BaseParsedWord {
    /**
     * Creates an identifier token.
     *
     * @param original original lexeme as it appeared in the stylesheet.
     * @param decoded normalized identifier, typically lower-cased when applicable.
     * @param changed whether {@code decoded} should be used when re-encoding.
     */
    ParsedIdentifier(String original, String decoded, boolean changed) {
      super(original, decoded, changed);
    }

    @Override
    protected boolean mustEncode(char c, int i, char prevc, boolean unicode) {
      // It is an identifier.
      if ((c >= 'a' && c <= 'z')
          || (c >= 'A' && c <= 'Z')
          || (c >= '0' && c <= '9')
          || c == '-'
          || c == '_'
          || (c >= (char) 0x00A1 && unicode)) {
        // Cannot start with a digit or a hyphen followed by a digit.
        return (i == 0 && c >= '0' && c <= '9') || (i == 1 && prevc == '-' && c >= '0' && c <= '9');
      }
      return true;
    }
  }

  /** Token representing a quoted string value. */
  static class ParsedString extends BaseParsedWord {
    /**
     * Creates a string token, retaining the quote character to use for re-encoding.
     *
     * @param original original quoted lexeme.
     * @param decoded unquoted string contents.
     * @param changed whether the decoded form differs materially from {@code original}.
     * @param stringChar the quote character ({@code '"'} or {@code '\''}).
     */
    ParsedString(String original, String decoded, boolean changed, char stringChar) {
      super(original, decoded, changed);
      this.stringChar = stringChar;
    }

    /**
     * Is the word quoted? If true, the word is completely enclosed by the given string character
     * (either ' or "), which is not included in the decoded string.
     */
    final char stringChar;

    @Override
    protected boolean mustEncode(char c, int i, char prevc, boolean unicode) {
      // It is a string.
      // Anything is allowed in a string...
      if (c == '\r' || c == '\n' || c == '\f')
        // Except newlines.
        return true;
      else // And control chars and anything outside Basic Latin (unless we know the output charset
      // is unicode-complete).
      if (c == stringChar)
        // And the quote itself.
        return true;
      else return c < 32 || (c >= (char) 0x0080 && !unicode);
    }

    @Override
    protected void innerEncode(boolean unicode, StringBuilder out) {
      out.append(stringChar);
      super.innerEncode(unicode, out);
      out.append(stringChar);
    }
  }

  /** Token representing a {@code url("...")} value with a decoded URL string. */
  static class ParsedURL extends ParsedString {
    /**
     * Creates a URL token from the decoded URL string and original form.
     *
     * @param original original {@code url(...)} lexeme including quotes where present.
     * @param decoded decoded URL string without surrounding {@code url(...)}.
     * @param changed whether the decoded URL should be used when re-encoding.
     * @param stringChar the quote character ({@code '"'} or {@code '\''}); {@code 0} to
     *     auto-select.
     */
    ParsedURL(String original, String decoded, boolean changed, char stringChar) {
      super(original, decoded, changed || stringChar == 0, stringChar == 0 ? '"' : stringChar);
    }

    @Override
    protected void innerEncode(boolean unicode, StringBuilder out) {
      out.append("url(");
      super.innerEncode(unicode, out);
      out.append(')');
    }

    /**
     * Replaces the decoded URL string and marks this token as changed so that the new URL is used
     * when re-encoding.
     *
     * @param s sanitized, absolute or relative URL as produced by the callback.
     */
    public void setNewURL(String s) {
      super.setNewValue(s);
    }
  }

  /** Token representing an attribute name or attribute-like identifier. */
  static class ParsedAttr extends ParsedIdentifier {
    /**
     * Creates an attribute token from the given decoded representation.
     *
     * @param original original lexeme found in the stylesheet.
     * @param decoded normalized attribute name.
     * @param changed whether {@code decoded} should be preferred when re-encoding this token.
     */
    ParsedAttr(String original, String decoded, boolean changed) {
      super(original, decoded, changed);
    }

    @Override
    protected void innerEncode(boolean unicode, StringBuilder out) {
      out.append("attr(");
      super.innerEncode(unicode, out);
      out.append(')');
    }
  }

  /**
   * Simple parsed word, doesn't need encoding, won't be changed. Used for lengths, percentages,
   * angles, etc. All characters must be safe and non-problematic. This is used for everything from
   * lengths and percentages to rgb(...) with spaces in it. Anything we don't understand gets a
   * SimpleParsedWord.
   */
  static class SimpleParsedWord extends ParsedWord {
    /**
     * Creates a simple token that will be written back verbatim without additional escaping.
     *
     * @param original original lexeme to preserve.
     */
    public SimpleParsedWord(String original) {
      super(original, false);
    }

    @Override
    protected void innerEncode(boolean unicode, StringBuilder out) {
      out.append(original);
    }
  }

  /** Counters need special handling, partly because they contain attributes and strings. */
  static class ParsedCounter extends ParsedWord {
    /**
     * Creates a {@code counter(...)} or {@code counters(...)} token.
     *
     * @param original original lexeme for preservation purposes.
     * @param identifier name of the counter; must be a valid identifier.
     * @param listType optional list-style-type identifier when present.
     * @param separatorString optional separator string for {@code counters(...)}.
     */
    public ParsedCounter(
        String original,
        ParsedIdentifier identifier,
        ParsedIdentifier listType,
        ParsedString separatorString) {
      super(original, true);
      this.identifier = identifier;
      this.listType = listType;
      this.separatorString = separatorString;
    }

    private final ParsedIdentifier identifier;
    private final ParsedIdentifier listType;
    private final ParsedString separatorString;

    @Override
    protected void innerEncode(boolean unicode, StringBuilder out) {
      if (separatorString != null) out.append(TOK_COUNTERS);
      else out.append(TOK_COUNTER);
      identifier.innerEncode(unicode, out);
      if (separatorString != null) {
        out.append(", ");
        separatorString.innerEncode(unicode, out);
      }
      if (listType != null) {
        out.append(", ");
        listType.innerEncode(unicode, out);
      }
      out.append(')');
      if (postComma) out.append(',');
    }
  }

  /** Split up a string, taking into account CSS rules for escaping, strings, identifiers. */
  private static ParsedWord[] split(String input, boolean allowCommaDelimiters) {
    if (LOG.isDebugEnabled())
      LOG.debug("Splitting \"{}\" allowCommaDelimiters={}", input, allowCommaDelimiters);
    return new SplitRunner(input, allowCommaDelimiters).run();
  }

  /**
   * Stateful splitter to keep the public split(...) method small and focused. Encapsulates the
   * tokenization state and mirrors the prior behavior exactly.
   */
  private static final class SplitRunner {
    final String input;
    final boolean allowCommaDelimiters;
    final ArrayList<ParsedWord> words = new ArrayList<>();
    ParsedWord lastWord = null;
    char c = 0;
    char stringchar = 0; // '"', '\'' or 0 when not in a string
    boolean escaping = false;
    boolean eatLF = false; // eat the next linefeed due to an escape closing
    final StringBuilder origToken;
    final StringBuilder decodedToken;
    boolean dontLikeOrigToken = false; // the original token bends the spec in unacceptable ways
    final StringBuilder escape = new StringBuilder(6);
    boolean couldBeIdentifier = true;
    boolean addComma = false;
    int bracketCount = 0; // brackets prevent tokenisation (e.g. rgb())
    boolean invalid = false;

    SplitRunner(String input, boolean allowCommaDelimiters) {
      this.input = input;
      this.allowCommaDelimiters = allowCommaDelimiters;
      this.origToken = new StringBuilder(input.length());
      this.decodedToken = new StringBuilder(input.length());
    }

    ParsedWord[] run() {
      for (int i = 0; i < input.length(); i++) {
        c = input.charAt(i);
        if (stringchar == 0) handleNotInString(i);
        else handleInString();
        if (invalid || c == 0) break; // single break for loop termination
      }
      if (!invalid) finalizeTrailingEscapeOrToken();
      return invalid ? null : words.toArray(new ParsedWord[0]);
    }

    void handleNotInString(int index) {
      if (handleEatLFGate()) return;
      if (!escaping) {
        handleNotEscaping(index);
        return;
      }
      handleEscaping();
    }

    /** Handles the non-escaping branch when not inside a string. */
    private void handleNotEscaping(int index) {
      if (isDelimiterOutsideBrackets()) {
        handleDelimiter(index);
        return;
      }
      if (isQuote(c)) {
        startString();
        return;
      }
      if (isBackslash(c)) {
        beginEscape();
        return;
      }
      if (isOpenParen(c)) {
        openBracket();
        return;
      }
      if (isCloseParen(c)) {
        if (closeBracketMakesInvalid()) return;
        closeBracket();
        return;
      }
      appendIdentifierOrLiteral();
    }

    /** Handles the escaping branch when not inside a string. */
    private void handleEscaping() {
      if (escape.isEmpty()) {
        if (isHexDigit(c)) {
          escape.append(c);
          return;
        }
        if (isLineBreak(c)) {
          invalid = true;
          return;
        }
        endEscapeAndAppendLiteral();
        return;
      }
      if (isHexDigit(c)) {
        appendHexAndMaybeFinish();
        return;
      }
      if (WS_T_R_N_F.indexOf(c) != -1) {
        finishEscapeWithWhitespace();
        return;
      }
      invalid = true;
    }

    private boolean handleEatLFGate() {
      if (eatLF && c == '\n') {
        eatLF = false;
        return true;
      }
      eatLF = false;
      return false;
    }

    private boolean isDelimiterOutsideBrackets() {
      return (WS_T_R_N_F.indexOf(c) != -1 || (allowCommaDelimiters && c == ','))
          && bracketCount == 0;
    }

    private void handleDelimiter(int index) {
      if (c == ',') handleComma(index);
      flushTokenOnWhitespace();
    }

    private static boolean isQuote(char ch) {
      return ch == '\"' || ch == '\'';
    }

    private static boolean isBackslash(char ch) {
      return ch == '\\';
    }

    private static boolean isOpenParen(char ch) {
      return ch == '(';
    }

    private static boolean isCloseParen(char ch) {
      return ch == ')';
    }

    private void startString() {
      stringchar = c;
      origToken.append(c);
      decodedToken.append(c);
      couldBeIdentifier = false;
    }

    private void beginEscape() {
      origToken.append(c);
      escape.setLength(0);
      escaping = true;
    }

    private void openBracket() {
      bracketCount++;
      origToken.append(c);
      decodedToken.append(c);
      couldBeIdentifier = false;
    }

    private boolean closeBracketMakesInvalid() {
      int next = bracketCount - 1;
      if (next < 0) {
        invalid = true;
        return true;
      }
      return false;
    }

    private void closeBracket() {
      bracketCount--;
      origToken.append(c);
      decodedToken.append(c);
      couldBeIdentifier = false;
    }

    private void appendIdentifierOrLiteral() {
      if (couldBeIdentifier) updateIdentifierFlagForChar();
      origToken.append(c);
      decodedToken.append(c);
    }

    private void updateIdentifierFlagForChar() {
      boolean isDigit = c >= '0' && c <= '9';
      boolean isAlphaLower = c >= 'a' && c <= 'z';
      boolean isAlphaUpper = c >= 'A' && c <= 'Z';
      boolean allowed =
          (isDigit && !origToken.isEmpty())
              || isAlphaLower
              || isAlphaUpper
              || c == '-'
              || c == '_'
              || c >= 0xA1;
      if (!allowed) {
        couldBeIdentifier = false;
        return;
      }
      if (origToken.length() == 1 && origToken.charAt(0) == '-' && isDigit) {
        couldBeIdentifier = false;
      }
    }

    private static boolean isHexDigit(char ch) {
      return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
    }

    private static boolean isLineBreak(char ch) {
      return ch == '\n' || ch == '\r' || ch == '\f';
    }

    private void endEscapeAndAppendLiteral() {
      escaping = false;
      origToken.append(c);
      decodedToken.append(c);
    }

    private void appendHexAndMaybeFinish() {
      escape.append(c);
      if (escape.length() == 6) {
        origToken.append(escape);
        decodedToken.append((char) Integer.parseInt(escape.toString(), 16));
        escape.setLength(0);
        escaping = false;
      }
    }

    private void finishEscapeWithWhitespace() {
      origToken.append(escape);
      decodedToken.append((char) Integer.parseInt(escape.toString(), 16));
      origToken.append(" ");
      escape.setLength(0);
      escaping = false;
      if (c == '\r') eatLF = true;
    }

    void handleInString() {
      if (handleEatLFInString()) return;
      if (c == stringchar && !escaping) {
        closeString();
        return;
      }
      if (isStringLineBreak() && !escaping) {
        invalid = true;
        return;
      }
      if (c == '\\' && !escaping) {
        startStringEscape();
        return;
      }
      if (escaping && escape.isEmpty()) {
        handleStringEscapingStart();
        return;
      }
      if (escaping) {
        handleStringEscapingContinue();
        return;
      }
      appendToString();
    }

    private boolean handleEatLFInString() {
      if (eatLF && c == '\n') {
        eatLF = false;
        origToken.append(c);
        return true; // do not add to decodedToken
      }
      eatLF = false;
      return false;
    }

    private void closeString() {
      origToken.append(c);
      decodedToken.append(c);
      stringchar = 0;
    }

    private boolean isStringLineBreak() {
      return c == '\f' || c == '\r' || c == '\n';
    }

    private void startStringEscape() {
      escaping = true;
      escape.setLength(0);
      origToken.append(c);
    }

    private void handleStringEscapingStart() {
      if (c == '\"' || c == '\'') {
        escaping = false;
        origToken.append(c);
        decodedToken.append(c);
        return;
      }
      if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
        escape.append(c);
        return;
      }
      if (c == '\n') {
        origToken.append(c); // escaped newline equals nothing in decoded
        return;
      }
      origToken.append(c);
      decodedToken.append(c);
      escaping = false;
    }

    private void handleStringEscapingContinue() {
      if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
        escape.append(c);
        if (escape.length() == 6) {
          origToken.append(escape);
          decodedToken.append((char) Integer.parseInt(escape.toString(), 16));
          escape.setLength(0);
          escaping = false;
        }
        return;
      }
      if (WS_T_R_N_F.indexOf(c) != -1) {
        origToken.append(escape);
        decodedToken.append((char) Integer.parseInt(escape.toString(), 16));
        escape.setLength(0);
        escaping = false;
        return;
      }
      invalid = true;
    }

    private void appendToString() {
      origToken.append(c);
      decodedToken.append(c);
    }

    void handleComma(int index) {
      if (decodedToken.isEmpty()) {
        handleCommaWithEmptyToken(index);
        return;
      }
      consumeTokenBeforeComma();
    }

    private void handleCommaWithEmptyToken(int index) {
      if (lastWord == null) {
        if (LOG.isDebugEnabled())
          LOG.debug("Extra comma before first element in \"{}\" i={}", input, index);
        words.clear();
        words.add(null);
        return;
      }
      if (lastWord.postComma) {
        if (LOG.isDebugEnabled())
          LOG.debug("Extra comma after element {} in \"{}\" i={}", lastWord, input, index);
        lastWord.changed = true; // allow it, delete it
        return;
      }
      lastWord.postComma = true;
    }

    private void consumeTokenBeforeComma() {
      ParsedWord word = parseToken(origToken, decodedToken, dontLikeOrigToken, couldBeIdentifier);
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Token before comma: orig: \"{}\" decoded: \"{}\" dontLike={} couldBeIdentifier={}"
                + " parsed {}",
            origToken,
            decodedToken,
            dontLikeOrigToken,
            couldBeIdentifier,
            word);
      if (word == null) {
        invalid = true;
        return;
      }
      if (addComma) word.postComma = true; // two commas with a token between them
      words.add(word);
      origToken.setLength(0);
      decodedToken.setLength(0);
      dontLikeOrigToken = false;
      couldBeIdentifier = true;
      lastWord = word;
      addComma = true; // mark that a comma follows this token
    }

    void flushTokenOnWhitespace() {
      if (decodedToken.isEmpty()) return;
      ParsedWord word = parseToken(origToken, decodedToken, dontLikeOrigToken, couldBeIdentifier);
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Token: orig: \"{}\" decoded: \"{}\" dontLike={} couldBeIdentifier={} parsed {}",
            origToken,
            decodedToken,
            dontLikeOrigToken,
            couldBeIdentifier,
            word);
      if (word == null) {
        invalid = true;
        return;
      }
      if (addComma) {
        word.postComma = true;
        addComma = false;
      }
      words.add(word);
      origToken.setLength(0);
      decodedToken.setLength(0);
      dontLikeOrigToken = false;
      couldBeIdentifier = true;
      lastWord = word;
    }

    void finalizeTrailingEscapeOrToken() {
      if (escaping && !escape.isEmpty()) {
        origToken.append(escape);
        decodedToken.append((char) Integer.parseInt(escape.toString(), 16));
      } else if (escaping) {
        // Newline rule?
        dontLikeOrigToken = true;
      }
      if (!origToken.isEmpty()) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Token: orig: \"{}\" decoded: \"{}\" dontLike={} couldBeIdentifier={}",
              origToken,
              decodedToken,
              dontLikeOrigToken,
              couldBeIdentifier);
        ParsedWord word = parseToken(origToken, decodedToken, dontLikeOrigToken, couldBeIdentifier);
        if (word == null) {
          words.clear();
          words.add(null);
          return;
        }
        words.add(word);
      }
      // No-op: invalid cases are handled via the 'invalid' flag.
    }

    // -- Token parsing helpers (moved from outer class to reduce clutter) --
    private ParsedWord parseToken(
        StringBuilder origToken,
        StringBuilder decodedToken,
        boolean dontLikeOrigToken,
        boolean couldBeIdentifier) {
      if (origToken.length() > 2) {
        char c0 = origToken.charAt(0);
        if (c0 == '\'' || c0 == '\"') {
          return handleQuotedToken(origToken, decodedToken, dontLikeOrigToken);
        }
      }
      String s = origToken.toString();
      if (couldBeIdentifier)
        return new ParsedIdentifier(s, decodedToken.toString(), dontLikeOrigToken);
      String sl = s.toLowerCase(Locale.ROOT);
      if (sl.startsWith("url("))
        return parseUrlToken(s, origToken, decodedToken, dontLikeOrigToken);
      if (sl.startsWith("attr("))
        return parseAttrToken(s, origToken, decodedToken, dontLikeOrigToken);
      if (sl.startsWith(TOK_COUNTER) || sl.startsWith(TOK_COUNTERS))
        return parseCounterToken(s, sl, origToken, decodedToken);
      return new SimpleParsedWord(origToken.toString());
    }

    private ParsedWord handleQuotedToken(
        StringBuilder origToken, StringBuilder decodedToken, boolean dontLikeOrigToken) {
      char q0 = origToken.charAt(0);
      char d = origToken.charAt(origToken.length() - 1);
      if (q0 == d) {
        decodedToken.setLength(decodedToken.length() - 1);
        decodedToken.deleteCharAt(0);
        return new ParsedString(
            origToken.toString(), decodedToken.toString(), dontLikeOrigToken, q0);
      } else {
        if (d != ',') return null; // No whitespace after a string
        return new SimpleParsedWord(origToken.toString());
      }
    }

    private ParsedWord parseUrlToken(
        String s, StringBuilder origToken, StringBuilder decodedToken, boolean dontLikeOrigToken) {
      if (!s.endsWith(")")) return null;
      // remove leading 'url(' and trailing ')'
      decodedToken.delete(0, 4);
      decodedToken.setLength(decodedToken.length() - 1);
      if (LOG.isTraceEnabled()) LOG.trace("stripped: {}", decodedToken);
      String strippedOrig = s.substring(4, s.length() - 1);

      int leading = countLeadingSpaces(strippedOrig);
      decodedToken.delete(0, leading);
      strippedOrig = strippedOrig.substring(leading);

      int trailing = countTrailingSpacesIgnoringEscaped(strippedOrig);
      decodedToken.setLength(decodedToken.length() - trailing);
      strippedOrig = strippedOrig.substring(0, strippedOrig.length() - trailing);

      if (LOG.isTraceEnabled())
        LOG.trace("whitespace stripped: {} decoded {}", strippedOrig, decodedToken);
      if (strippedOrig.isEmpty()) return null;

      if (hasBalancedQuotes(strippedOrig)) {
        char q = strippedOrig.charAt(0);
        decodedToken.setLength(decodedToken.length() - 1);
        decodedToken.deleteCharAt(0);
        if (LOG.isDebugEnabled())
          LOG.debug("creating url(): orig=\"{}\" decoded=\"{}\"", origToken, decodedToken);
        return new ParsedURL(origToken.toString(), decodedToken.toString(), dontLikeOrigToken, q);
      }
      return new ParsedURL(
          origToken.toString(), decodedToken.toString(), dontLikeOrigToken, (char) 0);
    }

    private static int countLeadingSpaces(String s) {
      int i = 0;
      while (i < s.length()) {
        char ch = s.charAt(i);
        if (ch == ' ' || ch == '\t') i++;
        else break;
      }
      return i;
    }

    private static int countTrailingSpacesIgnoringEscaped(String s) {
      int i = s.length() - 1;
      while (i >= 0) {
        char ch = s.charAt(i);
        if ((ch == ' ' || ch == '\t') && !(i > 0 && s.charAt(i - 1) == '\\')) i--;
        else break;
      }
      return s.length() - i - 1;
    }

    private static boolean hasBalancedQuotes(String s) {
      if (s.length() <= 2) return false;
      char q = s.charAt(0);
      if (q != '\'' && q != '"') return false;
      return s.charAt(s.length() - 1) == q;
    }

    private ParsedWord parseAttrToken(
        String s, StringBuilder origToken, StringBuilder decodedToken, boolean dontLikeOrigToken) {
      if (!s.endsWith(")")) return null;
      // remove leading 'attr(' and trailing ')'
      decodedToken.delete(0, 5);
      decodedToken.setLength(decodedToken.length() - 1);
      String strippedOrig = s.substring(4, s.length() - 1);

      int leading = countLeadingSpaces(strippedOrig);
      decodedToken.delete(0, leading);
      strippedOrig = strippedOrig.substring(leading);

      int trailing = countTrailingSpacesIgnoringEscaped(strippedOrig);
      decodedToken.setLength(decodedToken.length() - trailing);
      strippedOrig = strippedOrig.substring(0, strippedOrig.length() - trailing);
      if (strippedOrig.isEmpty()) return null;
      return new ParsedAttr(origToken.toString(), decodedToken.toString(), dontLikeOrigToken);
    }

    private ParsedWord parseCounterToken(
        String s, String sl, StringBuilder origToken, StringBuilder decodedToken) {
      boolean plural = sl.startsWith(TOK_COUNTERS);
      if (!s.endsWith(")")) return null;
      int len = plural ? TOK_COUNTERS.length() : TOK_COUNTER.length();
      decodedToken.delete(0, len);
      decodedToken.setLength(decodedToken.length() - 1);
      String strippedOrig = s.substring(len, s.length() - 1);

      // trim spaces taking escapes into account and keep decodedToken in sync
      int leading = countLeadingSpaces(strippedOrig);
      decodedToken.delete(0, leading);
      strippedOrig = strippedOrig.substring(leading);
      int trailing = countTrailingSpacesIgnoringEscaped(strippedOrig);
      decodedToken.setLength(decodedToken.length() - trailing);
      strippedOrig = strippedOrig.substring(0, strippedOrig.length() - trailing);
      if (strippedOrig.isEmpty()) return null;

      String[] split =
          FilterUtils.removeWhiteSpace(FilterUtils.splitOnChar(strippedOrig, ','), false);
      if (!isValidCounterPartsCount(split.length, plural)) return null;

      ParsedIdentifier ident = makeParsedIdentifier(split[0]);
      if (ident == null) return null;

      ParsedString separator = parseCounterSeparator(plural, split);
      if (plural && separator == null) return null;

      ParsedIdentifier listType = parseCounterListType(plural, split);
      if (((plural && split.length == 3) || (!plural && split.length == 2)) && listType == null)
        return null;
      return new ParsedCounter(origToken.toString(), ident, listType, separator);
    }

    private static boolean isValidCounterPartsCount(int len, boolean plural) {
      if (len == 0) return false;
      if (plural) return len >= 2 && len <= 3;
      return len <= 2;
    }

    private static ParsedString parseCounterSeparator(boolean plural, String[] split) {
      if (!plural) return null;
      return makeParsedString(split[1]);
    }

    private static ParsedIdentifier parseCounterListType(boolean plural, String[] split) {
      int idx = plural ? 2 : 1;
      if ((plural && split.length == 3) || (!plural && split.length == 2)) {
        return makeParsedIdentifier(split[idx]);
      }
      return null;
    }

    private static ParsedIdentifier makeParsedIdentifier(String string) {
      ParsedWord[] words = split(string, false);
      if (words == null) return null;
      if (words.length != 1) return null;
      if (!(words[0] instanceof ParsedIdentifier)) return null;
      return (ParsedIdentifier) words[0];
    }

    private static ParsedString makeParsedString(String string) {
      ParsedWord[] words = split(string, false);
      if (words == null) return null;
      if (words.length != 1) return null;
      if (!(words[0] instanceof ParsedString)) return null;
      return (ParsedString) words[0];
    }
  }

  /**
   * Verifier for individual CSS properties.
   *
   * <p>This helper encapsulates the per-property rules that determine whether a value is acceptable
   * for a given media context. It supports both primitive categories (integers, lengths, colors,
   * URIs, etc.) and simple expression patterns. Where applicable, it also lists concrete allowed
   * keywords and valid media types.
   */
  static class CSSPropertyVerifier {
    /**
     * When {@code true}, validation is based only on the value and ignores the element/media
     * context; primarily used for properties that have no media scoping.
     */
    public final boolean onlyValueVerifier;

    /**
     * Whether comma-separated value lists are allowed (for properties like {@code font-family}).
     */
    public final boolean allowCommaDelimiters;

    /**
     * Immutable set of allowed literal keywords for the property (e.g., {@code auto}). Defaulting
     * keywords such as {@code initial}, {@code inherit}, {@code unset}, {@code revert}, and {@code
     * revert-layer} are always accepted.
     */
    public final Set<String> allowedValues; // immutable HashSet

    /** Immutable set of allowed media identifiers for which the property is valid. */
    public final Set<String> allowedMedia; // immutable HashSet

    /*
     * Type flags describing which primitive categories are supported by this property’s values.
     * Abbreviations: in (integer), re (real), pe (percentage), le (length), an (angle), co (color or
     * counter), ur (URI), se (ID selector), sh (shape), st (string), id (identifier), ti (time),
     * fr (frequency), tr (transform).
     */
    /** Accepts integer numeric values. */
    public final boolean isInteger; // in

    /** Accepts real (floating point) numeric values. */
    public final boolean isReal; // re

    /** Accepts percentage values, typically with a trailing {@code %}. */
    public final boolean isPercentage; // pe

    /** Accepts length units (e.g., {@code px}, {@code em}, {@code rem}). */
    public final boolean isLength; // le

    /** Accepts angular units (e.g., {@code deg}, {@code rad}). */
    public final boolean isAngle; // an

    /** Accepts color values (keywords, hex, rgb/rgba, hsl/hsla, etc.). */
    public final boolean isColor; // co

    /** Accepts URL values (e.g., {@code url("...")}). */
    public final boolean isURI; // ur

    /** Accepts an ID selector (e.g., {@code #id}). */
    public final boolean isIDSelector; // se

    /** Accepts geometric shapes where defined by the property. */
    public final boolean isShape; // sh

    /** Accepts literal string values. */
    public final boolean isString; // st

    /** Accepts {@code counter(...)} or {@code counters(...)} constructs. */
    public final boolean isCounter; // co

    /** Accepts bare identifiers as values. */
    public final boolean isIdentifier; // id

    /** Accepts time units (e.g., {@code s}, {@code ms}). */
    public final boolean isTime; // ti

    /** Accepts frequency units (e.g., {@code Hz}, {@code kHz}). */
    public final boolean isFrequency; // fr

    /** Accepts transform functions where applicable. */
    public final boolean isTransform; // tr

    private final List<String> parserExpressions;

    /**
     * Creates a verifier limited to type-based checks; concrete keywords and media constraints are
     * not applied.
     *
     * @param allowCommaDelimiters whether comma-separated lists are accepted for this property.
     */
    CSSPropertyVerifier(boolean allowCommaDelimiters) {
      this(null, null, null, null, false, allowCommaDelimiters);
    }

    /**
     * Creates a verifier constrained by the given keywords and media identifiers.
     *
     * @param allowedValues literal keywords that are accepted in addition to defaulting keywords.
     * @param allowedMedia media names for which this property is valid; when {@code null}, media is
     *     not restricted.
     */
    CSSPropertyVerifier(Collection<String> allowedValues, Collection<String> allowedMedia) {
      this(allowedValues, allowedMedia, null, null);
    }

    /**
     * Creates a verifier constrained by keywords and media with an explicit set of possible values.
     *
     * @param allowedValues accepted literal keywords; may be {@code null}.
     * @param allowedMedia accepted media identifiers; may be {@code null}.
     * @param possibleValues additional symbolic values used by expression parsing; may be {@code
     *     null}.
     */
    CSSPropertyVerifier(
        Collection<String> allowedValues,
        Collection<String> allowedMedia,
        Collection<String> possibleValues) {
      this(allowedValues, allowedMedia, possibleValues, null);
    }

    /**
     * Full constructor exposing all verifier knobs, including expression patterns and value-only
     * mode.
     *
     * @param allowedValues accepted literal keywords; may be {@code null}.
     * @param possibleValues auxiliary symbolic values used inside expressions; may be {@code null}.
     * @param parseExpression expression fragments that model complex value patterns; may be {@code
     *     null}.
     * @param allowedMedia accepted media identifiers; may be {@code null}.
     * @param onlyValueVerifier when {@code true}, ignores media/element context during validation.
     */
    CSSPropertyVerifier(
        Collection<String> allowedValues,
        Collection<String> possibleValues,
        Collection<String> parseExpression,
        Collection<String> allowedMedia,
        boolean onlyValueVerifier) {
      this(allowedValues, allowedMedia, possibleValues, parseExpression, onlyValueVerifier, false);
    }

    /**
     * Creates a verifier with explicit parse expressions and media constraints.
     *
     * @param allowedValues accepted literal keywords; may be {@code null}.
     * @param allowedMedia accepted media identifiers; may be {@code null}.
     * @param possibleValues auxiliary symbolic values used inside expressions; may be {@code null}.
     * @param parseExpression expression fragments defining allowed value structures; may be {@code
     *     null}.
     */
    CSSPropertyVerifier(
        Collection<String> allowedValues,
        Collection<String> allowedMedia,
        Collection<String> possibleValues,
        Collection<String> parseExpression) {
      this(allowedValues, allowedMedia, possibleValues, parseExpression, false, false);
    }

    /**
     * Lowest-level constructor used by factory helpers.
     *
     * @param allowedValues accepted literal keywords; may be {@code null}.
     * @param allowedMedia accepted media identifiers; may be {@code null}.
     * @param possibleValues auxiliary symbolic values used inside expressions; may be {@code null}.
     * @param parseExpression expression fragments defining allowed value structures; may be {@code
     *     null}.
     * @param onlyValueVerifier when {@code true}, ignores media/element context.
     * @param allowCommaDelimiters whether comma-separated lists are accepted.
     */
    CSSPropertyVerifier(
        Collection<String> allowedValues,
        Collection<String> allowedMedia,
        Collection<String> possibleValues,
        Collection<String> parseExpression,
        boolean onlyValueVerifier,
        boolean allowCommaDelimiters) {
      this.onlyValueVerifier = onlyValueVerifier;
      this.allowCommaDelimiters = allowCommaDelimiters;

      TypeFlags flags = TypeFlags.fromPossibleValues(possibleValues);
      this.isInteger = flags.integer;
      this.isReal = flags.real;
      this.isPercentage = flags.percentage;
      this.isLength = flags.length;
      this.isAngle = flags.angle;
      this.isColor = flags.color;
      this.isURI = flags.uri;
      this.isIDSelector = flags.idSelector;
      this.isShape = flags.shape;
      this.isString = flags.string;
      this.isCounter = flags.counter; // not set by tokens currently reserved
      this.isIdentifier = flags.identifier;
      this.isTime = flags.time;
      this.isFrequency = flags.frequency;
      this.isTransform = flags.transform;

      this.allowedValues = allowedValues != null ? Set.copyOf(allowedValues) : null;
      this.allowedMedia = allowedMedia != null ? Set.copyOf(allowedMedia) : null;
      this.parserExpressions =
          parseExpression != null ? List.copyOf(parseExpression) : Collections.emptyList();
    }

    private static final class TypeFlags {
      boolean integer;
      boolean real;
      boolean percentage;
      boolean length;
      boolean angle;
      boolean color;
      boolean uri;
      boolean shape;
      boolean string;
      boolean counter;
      boolean identifier;
      boolean time;
      boolean frequency;
      boolean transform;
      boolean idSelector;

      static TypeFlags fromPossibleValues(Collection<String> possibleValues) {
        TypeFlags f = new TypeFlags();
        if (possibleValues == null) return f;
        for (String p : possibleValues) {
          switch (p) {
            case "in" -> f.integer = true;
            case "re" -> f.real = true;
            case "pe" -> f.percentage = true;
            case "le" -> f.length = true;
            case "an" -> f.angle = true;
            case "co" -> f.color = true;
            case "ur" -> f.uri = true;
            case "se" -> f.idSelector = true;
            case "sh" -> f.shape = true;
            case "st" -> f.string = true;
            case "id" -> f.identifier = true;
            case "ti" -> f.time = true;
            case "fr" -> f.frequency = true;
            case "tr" -> f.transform = true;
            default -> {
              // Intentionally ignore unknown type token.
            }
          }
        }
        return f;
      }
    }

    /**
     * Returns whether {@code value} parses as a Java integer.
     *
     * @param value candidate numeric literal; must be non-null.
     * @return {@code true} when an integer can be parsed; {@code false} otherwise.
     */
    public static boolean isIntegerChecker(String value) {
      try {
        Integer.parseInt(value); // CSS Property has a valid integer.
        return true;
      } catch (Exception _) {
        return false;
      }
    }

    /**
     * Returns whether {@code value} parses as a Java floating point number.
     *
     * @param value candidate numeric literal; must be non-null.
     * @return {@code true} when a real number can be parsed; {@code false} otherwise.
     */
    public static boolean isRealChecker(String value) {
      try {
        Float.parseFloat(value); // Valid float
        return true;
      } catch (Exception _) {
        return false;
      }
    }

    /**
     * Validates a URL token via the provided callback and updates it when rewritten.
     *
     * @param word parsed URL token whose decoded value is checked using the callback.
     * @param cb URI validation callback; may return a rewritten value or {@code null} to reject.
     * @return {@code true} when the URL is accepted (possibly rewritten); {@code false} otherwise.
     */
    public static boolean isValidURI(ParsedURL word, FilterCallback cb) {
      String w = CSSTokenizerFilter.removeOuterQuotes(word.getDecoded());
      try {
        String s = cb.processURI(w, null);
        if (s == null || s.isEmpty()) return false;
        if (s.equals(w)) return true;
        if (LOG.isTraceEnabled()) LOG.trace("New url: \"{}\" from \"{}\"", s, w);
        word.setNewURL(s);
        return true;
      } catch (CommentException _) {
        return false;
      }
    }

    /**
     * Checks whether a sequence of tokens forms a valid value for this property.
     *
     * @param words tokenized value to validate; must not be {@code null}.
     * @param cb auxiliary callback for URI checks when URLs are present in {@code words}.
     * @return {@code true} if the entire sequence is accepted under this verifier.
     */
    public boolean checkValidity(ParsedWord[] words, FilterCallback cb) {
      return this.checkValidity(null, null, words, cb);
    }

    /**
     * Convenience overload that validates a single token value.
     *
     * @param word token to validate, according to this property’s rules.
     * @param cb auxiliary callback for URI checks when {@code word} is a URL.
     * @return {@code true} when the token is accepted.
     */
    public boolean checkValidity(ParsedWord word, FilterCallback cb) {
      return this.checkValidity(null, null, new ParsedWord[] {word}, cb);
    }

    /**
     * Verifies whether this property can take the supplied value under the given media and element
     * constraints, applying both keyword and type rules.
     *
     * @param media active media names or {@code null} for none; used when media scoping applies.
     * @param elements HTML element names or {@code null}; reserved for element-specific checks.
     * @param words tokenized value to validate in full; must not be {@code null}.
     * @param cb callback consulted for URL validation when applicable.
     * @return {@code true} if any allowed pattern validates the entire value; otherwise {@code
     *     false}.
     */
    public boolean checkValidity(
        String[] media, String[] elements, ParsedWord[] words, FilterCallback cb) {
      if (LOG.isTraceEnabled()) {
        LOG.trace("checkValidity for {} for {}", toString(words), this);
        LOG.trace("elements: {}", elements == null ? null : Arrays.toString(elements));
      }
      if (!onlyValueVerifier && allowedMedia != null && !isAnyMediaAllowed(media)) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "checkValidity rejected: media not allowed for element. media={} allowedMedia={}",
              Fields.commaList(media),
              allowedMedia);
        return false;
      }
      if (words.length == 1 && validateSingleWord(words[0], cb)) return true;
      for (String parserExpression : parserExpressions) {
        if (recursiveParserExpressionVerifier(parserExpression, words, cb)) return true;
      }
      return false;
    }

    private boolean isAnyMediaAllowed(String[] media) {
      for (String m : media) if (allowedMedia.contains(m)) return true;
      return false;
    }

    private boolean isDefaultingKeyword(String lowerCaseWord) {
      return lowerCaseWord.equals("initial")
          || lowerCaseWord.equals("inherit")
          || lowerCaseWord.equals("unset")
          || lowerCaseWord.equals("revert")
          || lowerCaseWord.equals("revert-layer");
    }

    private boolean validateSingleWord(ParsedWord word, FilterCallback cb) {
      if (word instanceof ParsedIdentifier id && validateIdentifierDefaults(id)) return true;
      if (word instanceof SimpleParsedWord spw && validateSimpleWord(spw)) return true;
      if (word instanceof ParsedIdentifier id2 && validateIdentifierSpecials(id2)) return true;
      if (isURI && word instanceof ParsedURL rL) return isValidURI(rL, cb);
      if (isIdentifier && word instanceof ParsedIdentifier) return true;
      if (isIDSelector) return isValidIdSelector(word);
      return isString && word instanceof ParsedString;
    }

    private boolean validateIdentifierDefaults(ParsedIdentifier word) {
      String lower = word.original.toLowerCase(Locale.ROOT);
      if (allowedValues != null && allowedValues.contains(lower)) return true;
      return isDefaultingKeyword(lower);
    }

    private boolean validateSimpleWord(SimpleParsedWord word) {
      String w = word.original;
      if (matchesAllowedValue(w)) return true;
      if (matchesNumericTypes(w)) return true;
      return matchesOtherTypes(w);
    }

    private boolean matchesAllowedValue(String w) {
      return allowedValues != null && allowedValues.contains(w);
    }

    private boolean matchesNumericTypes(String w) {
      return (isInteger && isIntegerChecker(w))
          || (isReal && isRealChecker(w))
          || (isPercentage && FilterUtils.isPercentage(w))
          || (isLength && FilterUtils.isLength(w, false))
          || (isAngle && FilterUtils.isAngle(w));
    }

    private boolean matchesOtherTypes(String w) {
      return (isColor && FilterUtils.isColor(w))
          || (isShape && FilterUtils.isValidCSSShape(w))
          || (isFrequency && FilterUtils.isFrequency(w))
          || (isTime && FilterUtils.isTime(w))
          || (isTransform && FilterUtils.isCSSTransform(w));
    }

    private boolean validateIdentifierSpecials(ParsedIdentifier word) {
      String value = word.original;
      if (isColor && FilterUtils.isColor(value)) return true;
      if (!isLength) return false;
      // Note: fit-content(20em)
      return value.equalsIgnoreCase("min-content")
          || value.equalsIgnoreCase("max-content")
          || value.equalsIgnoreCase("fit-content");
    }

    private boolean isValidIdSelector(ParsedWord word) {
      String result = htmlElementVerifier(word.original, true);
      return !(result == null || result.isEmpty());
    }

    /**
     * Parser expression encoding overview.
     *
     * <p>The parser encodes high-level operators into a compact internal form using indices of
     * {@code auxilaryVerifiers}. Examples (illustrative only): - Logical OR is encoded by joining
     * indices with the letter 'a'. - Logical AND is encoded by joining indices with the letter 'b'.
     * - Repetition bounds are encoded using angle brackets, e.g., {@code <1,4>}. - Optional and
     * one-or-more are mapped to equivalent bounded forms. - Token windows can be expressed with
     * square brackets to indicate minimum/maximum tokens.
     *
     * <p>The verifier explores combinations which allow the full value to be consumed by the
     * expression: it tries each sub-expression in turn and distributes the remaining tokens to the
     * rest. If any combination validates, the whole expression is accepted.
     *
     * @param expression encoded verifier expression made of indices and operators.
     * @param words token sequence to be validated against the expression.
     * @param cb callback consulted for nested URL checks as needed.
     * @return {@code true} if the expression validates the entire sequence; otherwise {@code
     *     false}.
     */
    public boolean recursiveParserExpressionVerifier(
        String expression, ParsedWord[] words, FilterCallback cb) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "1recursiveParserExpressionVerifier called: with {} {}", expression, toString(words));
      if (expression == null || expression.trim().isEmpty()) {
        return words == null || words.length == 0;
      }

      // Find the first operator occurrence to decide which handler to use.
      int idxA = expression.indexOf('a');
      int idxB = expression.indexOf('b');
      int idxSpace = expression.indexOf(' ');
      int idxQ = expression.indexOf('?');
      int idxLt = expression.indexOf('<');

      int firstIndex = minNonNegative(idxA, idxB, idxSpace, idxQ, idxLt);
      if (firstIndex == -1) {
        return handleSingleVerifier(expression, words, cb);
      }

      char op = expression.charAt(firstIndex);
      return switch (op) {
        case 'a' -> handleOrExpression(expression, words, cb);
        case 'b' -> handleAndExpression(expression, words, cb);
        case ' ' -> handleSequenceExpression(expression, firstIndex, words, cb);
        case '?' -> handleOptionalExpression(expression, firstIndex, words, cb);
        case '<' -> handleRangeExpression(expression, firstIndex, words, cb);
        default ->
            // Should not happen, but fallback to single verifier behavior.
            handleSingleVerifier(expression, words, cb);
      };
    }

    private int minNonNegative(int... values) {
      int min = Integer.MAX_VALUE;
      boolean found = false;
      for (int v : values) {
        if (v >= 0 && v < min) {
          min = v;
          found = true;
        }
      }
      return found ? min : -1;
    }

    private boolean handleSingleVerifier(String expression, ParsedWord[] words, FilterCallback cb) {
      if (LOG.isTraceEnabled()) LOG.trace("10Single token:{}", expression);
      int index = Integer.parseInt(expression);
      return CSSTokenizerFilter.auxilaryVerifiers[index].checkValidity(words, cb);
    }

    private boolean handleOrExpression(String expression, ParsedWord[] words, FilterCallback cb) {
      // Identifying || chain like "1a2a3 [rest]"
      int endIndex = findEndOfOrChain(expression);
      String firstPart = expression.substring(0, endIndex);
      String secondPart = endIndex != expression.length() ? expression.substring(endIndex + 1) : "";

      int start = secondPart.isEmpty() ? words.length : 1;
      for (int j = start; j <= words.length; j++) {
        if (LOG.isTraceEnabled())
          LOG.trace("2Making recursiveDoubleBarVerifier to consume {} words", j);
        ParsedWord[] head = Arrays.copyOf(words, j);
        if (!recursiveDoubleBarVerifier(firstPart, head, cb)) continue;
        ParsedWord[] tail = Arrays.copyOfRange(words, j, words.length);
        if (recursiveParserExpressionVerifier(secondPart, tail, cb)) return true;
      }
      return false;
    }

    /** Returns the index where the initial 1a2a3... chain ends (position of the last digit). */
    private int findEndOfOrChain(String expression) {
      int endIndex = expression.length();
      for (int j = 0; j < expression.length(); j++) {
        char ch = expression.charAt(j);
        if (!(ch == 'a' || ('0' <= ch && '9' >= ch))) {
          endIndex = j;
          break;
        }
      }
      return endIndex;
    }

    private boolean handleAndExpression(String expression, ParsedWord[] words, FilterCallback cb) {
      // Identifying && chain like "1b2b3 [rest]"
      int endIndex = findEndOfAndChain(expression);
      String firstPart = expression.substring(0, endIndex);
      String secondPart = endIndex != expression.length() ? expression.substring(endIndex + 1) : "";

      for (int j = words.length; j >= 1; j--) {
        ParsedWord[] head = Arrays.copyOf(words, j);
        if (!doubleAmpersandVerifier(firstPart, head, cb)) continue;
        ParsedWord[] tail = Arrays.copyOfRange(words, j, words.length);
        if (recursiveParserExpressionVerifier(secondPart, tail, cb)) return true;
      }
      return false;
    }

    /** Returns the index where the initial 1b2b3... chain ends. */
    private int findEndOfAndChain(String expression) {
      int endIndex = expression.length();
      for (int j = 0; j < expression.length(); j++) {
        char ch = expression.charAt(j);
        if (!(ch == 'b' || ('0' <= ch && '9' >= ch))) {
          endIndex = j;
          break;
        }
      }
      return endIndex;
    }

    private boolean handleSequenceExpression(
        String expression, int spaceIndex, ParsedWord[] words, FilterCallback cb) {
      if (words == null || words.length == 0) return false;
      int index = Integer.parseInt(expression.substring(0, spaceIndex));
      boolean ok = CSSTokenizerFilter.auxilaryVerifiers[index].checkValidity(words[0], cb);
      if (!ok) return false;
      ParsedWord[] rest = Arrays.copyOfRange(words, 1, words.length);
      return recursiveParserExpressionVerifier(expression.substring(spaceIndex + 1), rest, cb);
    }

    private boolean handleOptionalExpression(
        String expression, int qIndex, ParsedWord[] words, FilterCallback cb) {
      String firstPart = expression.substring(0, qIndex);
      String secondPart = expression.substring(qIndex + 1);
      int index = Integer.parseInt(firstPart);
      if (words.length > 0) {
        boolean result = CSSTokenizerFilter.auxilaryVerifiers[index].checkValidity(words[0], cb);
        if (result) {
          ParsedWord[] partToPass = Arrays.copyOfRange(words, 1, words.length);
          return recursiveParserExpressionVerifier(secondPart, partToPass, cb);
        }
      } else {
        return recursiveParserExpressionVerifier(secondPart, words, cb);
      }
      return false;
    }

    private boolean handleRangeExpression(
        String expression, int ltIndex, ParsedWord[] words, FilterCallback cb) {
      int tindex = expression.indexOf('>');
      if (tindex <= ltIndex) return false;

      int[] giveLimits = parseGivenLimits(expression, tindex);
      int firstIndex = giveLimits[2];
      int tokensLower = giveLimits[0];
      int tokensUpper = giveLimits[1];

      String firstPart = expression.substring(0, ltIndex);
      String secondPart = normalizeSecondPart(expression.substring(firstIndex));
      if (secondPart == null) return false;

      if (LOG.isDebugEnabled())
        LOG.debug(
            "9in < firstPart={} secondPart={} tokensCanBeGivenLowerLimit={}"
                + " tokensCanBeGivenUpperLimit={}",
            firstPart,
            secondPart,
            tokensLower,
            tokensUpper);

      int index = Integer.parseInt(firstPart);
      String[] strLimits = FilterUtils.splitOnChar(expression.substring(ltIndex + 1, tindex), ',');
      if (strLimits.length != 2) return false;
      int lowerLimit = Integer.parseInt(strLimits[0]);
      int upperLimit = Integer.parseInt(strLimits[1]);

      VariableOccurrenceLimits limits =
          new VariableOccurrenceLimits(lowerLimit, upperLimit, tokensLower, tokensUpper);
      VariableOccurrenceParams params =
          new VariableOccurrenceParams(index, words, limits, secondPart, cb);
      return recursiveVariableOccuranceVerifier(params);
    }

    private int[] parseGivenLimits(String expression, int tindex) {
      // returns [tokensLower, tokensUpper, firstIndexAfterLimits]
      int firstIndex = tindex + 1;
      int tokensLower = 1;
      int tokensUpper = 1;
      if (tindex != expression.length() - 1 && expression.charAt(tindex + 1) == '[') {
        int end = expression.indexOf(']');
        if (end > tindex + 1) {
          String[] limits = FilterUtils.splitOnChar(expression.substring(tindex + 2, end), ',');
          tokensLower = Integer.parseInt(limits[0]);
          tokensUpper = Integer.parseInt(limits[1]);
          firstIndex = end + 1;
        }
      }
      return new int[] {tokensLower, tokensUpper, firstIndex};
    }

    private String normalizeSecondPart(String secondPart) {
      if (secondPart.isEmpty()) return secondPart;
      if (secondPart.charAt(0) == ' ') return secondPart.substring(1);
      // Invalid/unknown format
      return null;
    }

    /**
     * Takes b-expressions and evaluates them.
     *
     * <p>{@literal &&} means all the expressions must occur in any order.<br>
     * CSS Grammar {@code list-item && [ block | nonsense ] && [ more ]?}<br>
     * Will accept the following inputs as valid:<br>
     * {@code list-item block}<br>
     * {@code block list-item more}<br>
     * {@code more nonsense list-item}<br>
     * You can model that using the b expression: {@code 1b2b3} where 1 is ["list-item"] 2 is
     * ["block", "nonsense"] and 3 is {@code 4?} and 4 is ["more"].
     *
     * @param expression the encoded expression, as explained above.
     * @param words tokens to parse.
     * @param cb callback consulted for nested URL checks as needed.
     * @return {@code true} if all verifiers and all words are consumed; {@code false} otherwise.
     */
    public boolean doubleAmpersandVerifier(
        String expression, ParsedWord[] words, FilterCallback cb) {
      validateAndChainExpression(expression);
      List<CSSPropertyVerifier> verifiers = parseVerifiers(expression);
      return consumeInAnyOrder(verifiers, words, cb);
    }

    /** Basic format validation for 'b'-chained expressions used by '&&' CSS shorthands. */
    private void validateAndChainExpression(String expression) {
      final char chain = 'b';
      if (expression == null || expression.isEmpty())
        throw new IllegalArgumentException("expression must not be null or empty");
      if (expression.charAt(expression.length() - 1) == chain)
        throw new IllegalArgumentException("expression must not end with '" + chain + "'");
      if (expression.charAt(0) == chain)
        throw new IllegalArgumentException("expression must not start with '" + chain + "'");
    }

    /** Parses 1b2b3 into a list of auxiliary verifiers. */
    private List<CSSPropertyVerifier> parseVerifiers(String expression) {
      final char chain = 'b';
      ArrayList<CSSPropertyVerifier> list = new ArrayList<>();
      int last = -1;
      for (int i = 0; i <= expression.length(); i++) {
        if (i == expression.length() || expression.charAt(i) == chain) {
          String part = expression.substring(last + 1, i);
          int index = Integer.parseInt(part);
          list.add(CSSTokenizerFilter.auxilaryVerifiers[index]);
          last = i;
        }
      }
      return list;
    }

    /**
     * Consumes the words with the verifiers in any order, each verifier at most once. Remaining
     * verifiers may accept empty arrays and will be applied after consumption.
     */
    private boolean consumeInAnyOrder(
        List<CSSPropertyVerifier> verifiers, ParsedWord[] words, FilterCallback cb) {
      int maxLoops = words.length;
      while (maxLoops-- > 0 && !verifiers.isEmpty()) {
        if (consumeOne(words, verifiers, cb)) {
          words = Arrays.copyOfRange(words, 1, words.length);
        }
        if (words.length == 0) break;
      }
      if (words.length > 0) return false;
      for (CSSPropertyVerifier v : verifiers) if (!v.checkValidity(words, cb)) return false;
      return true;
    }

    /** Attempts to consume the first token with any verifier, removing the successful one. */
    private boolean consumeOne(
        ParsedWord[] words, List<CSSPropertyVerifier> verifiers, FilterCallback cb) {
      for (int i = words.length; i > 0; i--) {
        ParsedWord[] head = Arrays.copyOf(words, i);
        for (int j = 0; j < verifiers.size(); j++) {
          CSSPropertyVerifier v = verifiers.get(j);
          if (v.checkValidity(head, cb)) {
            verifiers.remove(j);
            return true;
          }
        }
      }
      return false;
    }

    /**
     * Joins a contiguous slice of {@code parts} into a single space-separated string.
     *
     * @param parts array of strings; may be {@code null} to yield an empty result.
     * @param lowerIndex inclusive lower bound index into {@code parts}.
     * @param upperIndex exclusive upper bound index into {@code parts}.
     * @return joined slice or an empty string when the bounds fall outside {@code parts}.
     */
    public static String getStringFromArray(String[] parts, int lowerIndex, int upperIndex) {
      StringBuilder buffer = new StringBuilder();
      if (parts != null && lowerIndex < parts.length) {
        for (int i = lowerIndex; i < upperIndex && i < parts.length; i++) {
          buffer.append(parts[i]);
          buffer.append(' ');
        }
        return buffer.toString();
      } else return "";
    }

    /*
     * This function takes an array of string and concatenates everything in a " " seperated string.
     */
    /**
     * Joins all elements of {@code parts} into a single space-separated string.
     *
     * @param parts array of strings; {@code null} is treated as empty.
     * @return joined string or an empty string if {@code parts} is {@code null} or empty.
     */
    public static String getStringFromArray(String[] parts) {
      return getStringFromArray(parts, 0, parts.length - 1);
    }

    /**
     * Creates a new subarray from {@code array} spanning {@code [lowerIndex, upperIndex)}.
     *
     * @param array source array; {@code null} yields an empty array.
     * @param lowerIndex inclusive lower bound index into {@code array}.
     * @param upperIndex exclusive upper bound index into {@code array}.
     * @return a newly allocated array containing the requested slice or an empty array if out of
     *     bounds.
     */
    public static ParsedWord[] getSubArray(ParsedWord[] array, int lowerIndex, int upperIndex) {
      ParsedWord[] arrayToReturn = new ParsedWord[upperIndex - lowerIndex];
      if (array != null && lowerIndex < array.length) {
        for (int i = lowerIndex; i < upperIndex && i < array.length; i++) {
          arrayToReturn[i - lowerIndex] = array[i];
        }
        return arrayToReturn;
      } else return new ParsedWord[0];
    }

    /**
     * Limits governing repetitions and token consumption for variable-occurrence checks.
     *
     * @param lowerLimit minimum allowed repetitions.
     * @param upperLimit maximum allowed repetitions (inclusive), or zero for none.
     * @param tokensLower minimum number of tokens that the sub-expression may consume.
     * @param tokensUpper maximum number of tokens that the sub-expression may consume.
     */
    private record VariableOccurrenceLimits(
        int lowerLimit, int upperLimit, int tokensLower, int tokensUpper) {
      private VariableOccurrenceLimits withBounds(int newLowerLimit, int newUpperLimit) {
        return new VariableOccurrenceLimits(newLowerLimit, newUpperLimit, tokensLower, tokensUpper);
      }
    }

    /** Parameters for verifying parse expressions that use the {@code []} repetition operator. */
    @SuppressWarnings({"java:S6206", "ClassCanBeRecord"})
    private static final class VariableOccurrenceParams {
      private final int verifierIndex;
      private final ParsedWord[] valueParts;
      private final VariableOccurrenceLimits limits;
      private final String secondPart;
      private final FilterCallback cb;

      /**
       * @param verifierIndex index into {@code auxilaryVerifiers} for the repeated sub-expression.
       * @param valueParts token sequence to validate.
       * @param limits repetition bounds and token consumption limits.
       * @param secondPart expression to validate after the repeated part.
       * @param cb callback consulted by nested verifiers when URLs are encountered.
       */
      private VariableOccurrenceParams(
          int verifierIndex,
          ParsedWord[] valueParts,
          VariableOccurrenceLimits limits,
          String secondPart,
          FilterCallback cb) {
        this.verifierIndex = verifierIndex;
        this.valueParts = valueParts;
        this.limits = limits;
        this.secondPart = secondPart;
        this.cb = cb;
      }

      private int verifierIndex() {
        return verifierIndex;
      }

      private ParsedWord[] valueParts() {
        return valueParts;
      }

      private VariableOccurrenceLimits limits() {
        return limits;
      }

      private String secondPart() {
        return secondPart;
      }

      private FilterCallback cb() {
        return cb;
      }

      @Override
      public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof VariableOccurrenceParams other)) return false;
        return verifierIndex == other.verifierIndex
            && Arrays.equals(valueParts, other.valueParts)
            && Objects.equals(limits, other.limits)
            && Objects.equals(secondPart, other.secondPart)
            && Objects.equals(cb, other.cb);
      }

      @Override
      public int hashCode() {
        int result = Integer.hashCode(verifierIndex);
        result = 31 * result + Arrays.hashCode(valueParts);
        result = 31 * result + Objects.hashCode(limits);
        result = 31 * result + Objects.hashCode(secondPart);
        result = 31 * result + Objects.hashCode(cb);
        return result;
      }

      @Override
      public @NotNull String toString() {
        return "VariableOccurrenceParams["
            + "verifierIndex="
            + verifierIndex
            + ", valueParts="
            + Arrays.toString(valueParts)
            + ", limits="
            + limits
            + ", secondPart="
            + secondPart
            + ", cb="
            + cb
            + "]";
      }

      private VariableOccurrenceParams withPartsAndLimits(
          ParsedWord[] newValueParts, VariableOccurrenceLimits newLimits) {
        return new VariableOccurrenceParams(
            verifierIndex, newValueParts, newLimits, secondPart, cb);
      }
    }

    /**
     * Verifies part of a parse expression that uses the {@code []} repetition operator.
     *
     * @param params grouped parameters for the repetition check.
     * @return {@code true} if a partitioning satisfies the repetition bounds and validates the
     *     tail.
     */
    private boolean recursiveVariableOccuranceVerifier(VariableOccurrenceParams params) {
      int verifierIndex = params.verifierIndex();
      ParsedWord[] valueParts = params.valueParts();
      VariableOccurrenceLimits limits = params.limits();
      int lowerLimit = limits.lowerLimit();
      int upperLimit = limits.upperLimit();
      int tokensLower = limits.tokensLower();
      int tokensUpper = limits.tokensUpper();
      String secondPart = params.secondPart();
      FilterCallback cb = params.cb();
      if (LOG.isDebugEnabled())
        LOG.debug(
            "recursiveVariableOccurranceVerifier({},{},{},{},{},{},{})",
            verifierIndex,
            toString(valueParts),
            lowerLimit,
            upperLimit,
            tokensLower,
            tokensUpper,
            secondPart);

      if (canSucceedWithZero(valueParts, lowerLimit)) return true;
      if (lowerLimit <= 0 && trySecondPartOnly(secondPart, valueParts, cb)) return true;
      if (upperLimit == 0) return false; // no more parts allowed

      return attemptPrefixMatches(params);
    }

    private boolean canSucceedWithZero(ParsedWord[] valueParts, int lowerLimit) {
      return (valueParts == null || valueParts.length == 0) && lowerLimit == 0;
    }

    private boolean trySecondPartOnly(
        String secondPart, ParsedWord[] valueParts, FilterCallback cb) {
      if (recursiveParserExpressionVerifier(secondPart, valueParts, cb)) {
        if (LOG.isTraceEnabled())
          LOG.trace("recursiveVariableOccurranceVerifier completed by {}", secondPart);
        return true;
      }
      return false;
    }

    private boolean attemptPrefixMatches(VariableOccurrenceParams params) {
      int verifierIndex = params.verifierIndex();
      ParsedWord[] valueParts = params.valueParts();
      VariableOccurrenceLimits limits = params.limits();
      int lowerLimit = limits.lowerLimit();
      int upperLimit = limits.upperLimit();
      int tokensLower = limits.tokensLower();
      int tokensUpper = limits.tokensUpper();
      String secondPart = params.secondPart();
      FilterCallback cb = params.cb();
      for (int i = tokensLower; i <= tokensUpper && i <= valueParts.length; i++) {
        ParsedWord[] before = Arrays.copyOf(valueParts, i);
        if (!CSSTokenizerFilter.auxilaryVerifiers[verifierIndex].checkValidity(before, cb))
          continue;

        if (i == valueParts.length) {
          if (lowerLimit <= 1)
            return recursiveParserExpressionVerifier(secondPart, new ParsedWord[0], cb);
          return false;
        }

        ParsedWord[] after = Arrays.copyOfRange(valueParts, i, valueParts.length);
        if (LOG.isTraceEnabled()) LOG.trace("rest of tokens: {}", toString(after));
        VariableOccurrenceLimits nextLimits = limits.withBounds(lowerLimit - 1, upperLimit - 1);
        VariableOccurrenceParams nextParams = params.withPartsAndLimits(after, nextLimits);
        if (recursiveVariableOccuranceVerifier(nextParams)) return true;
      }
      return false;
    }

    /**
     * Returns a comma-separated string representation of the provided token array for logging.
     *
     * @param words array of tokens; may be {@code null}.
     * @return a comma-delimited list of token {@code toString()} values, or {@code null} when
     *     {@code words} is {@code null}.
     */
    static String toString(ParsedWord[] words) {
      if (words == null) return null;
      StringBuilder sb = new StringBuilder();
      boolean first = true;
      for (ParsedWord word : words) {
        if (!first) sb.append(",");
        first = false;
        sb.append(word);
      }
      return sb.toString();
    }

    /**
     * Verifies an OR ({@code ||}) group by exploring all partitions of the token stream among
     * sub-expressions until one validates the entire value.
     *
     * @param expression concatenated sub-expression pattern using {@code 'a'} as a separator.
     * @param words token sequence to validate against the OR group; empty sequence is accepted.
     * @param cb callback consulted by nested verifiers (e.g., for URL checks).
     * @return {@code true} if some partition validates the full sequence; {@code false} otherwise.
     * @throws IllegalArgumentException if {@code expression} is {@code null}, empty, or starts/ends
     *     with {@code 'a'}.
     */
    public boolean recursiveDoubleBarVerifier(
        String expression, ParsedWord[] words, FilterCallback cb) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "11in recursiveDoubleBarVerifier expression={} value={}", expression, toString(words));

      if (words == null || words.length == 0) return true;

      // Basic validation
      if (expression == null || expression.isEmpty()) {
        throw new IllegalArgumentException("expression must not be null or empty");
      }
      if (expression.charAt(expression.length() - 1) == 'a') {
        throw new IllegalArgumentException("expression must not end with 'a'");
      }
      if (expression.charAt(0) == 'a') {
        throw new IllegalArgumentException("expression must not start with 'a'");
      }

      List<String> parts = splitDoubleBarExpression(expression);

      // Fast path: single token (no 'a')
      if (parts.size() == 1) {
        int index = Integer.parseInt(parts.getFirst());
        boolean ok = CSSTokenizerFilter.auxilaryVerifiers[index].checkValidity(words, cb);
        if (LOG.isDebugEnabled())
          LOG.debug(
              "16Single token:{} with value=*{}* validity={}",
              expression,
              Fields.commaList(words),
              ok);
        return ok;
      }

      // Multi-token case: try consuming from each component once, recurse for the rest
      for (int p = 0; p < parts.size(); p++) {
        if (tryMatchComponent(parts, p, words, cb)) return true;
      }

      // Equivalent to (lastA != -1) return false; in original flow
      return false;
    }

    private List<String> splitDoubleBarExpression(String expression) {
      // Preserve behavior for invalid sequences (e.g., empty parts cause NumberFormatException
      // later when parsed as int)
      ArrayList<String> parts = new ArrayList<>();
      int last = 0;
      for (int i = 0; i <= expression.length(); i++) {
        if (i == expression.length() || expression.charAt(i) == 'a') {
          parts.add(expression.substring(last, i));
          last = i + 1;
        }
      }
      return parts;
    }

    private boolean tryMatchComponent(
        List<String> parts, int partIndex, ParsedWord[] words, FilterCallback cb) {
      String firstPart = parts.get(partIndex);
      String secondPart = joinParts(parts, partIndex + 1, parts.size());
      if (LOG.isDebugEnabled())
        LOG.debug(
            "12in a firstPart={} secondPart={} for expression {}",
            firstPart,
            secondPart,
            String.join("a", parts));

      int index = Integer.parseInt(firstPart);

      for (int j = 0; j < words.length; j++) {
        ParsedWord[] head = getSubArray(words, 0, j + 1);
        if (!CSSTokenizerFilter.auxilaryVerifiers[index].checkValidity(head, cb)) continue;
        if (verifyRest(parts, partIndex, secondPart, words, j, cb)) return true;
      }
      return false;
    }

    private boolean verifyRest(
        List<String> parts,
        int partIndex,
        String secondPart,
        ParsedWord[] words,
        int j,
        FilterCallback cb) {
      ParsedWord[] valueToPass = Arrays.copyOfRange(words, j + 1, words.length);
      if (valueToPass.length == 0) return true;
      String ignored = joinParts(parts, 0, partIndex);
      String pattern = joinNonEmptyWithA(ignored, secondPart);
      if (pattern.isEmpty()) return false;
      return recursiveDoubleBarVerifier(pattern, valueToPass, cb);
    }

    private String joinParts(List<String> parts, int fromInclusive, int toExclusive) {
      if (fromInclusive >= toExclusive) return "";
      StringBuilder sb = new StringBuilder();
      for (int i = fromInclusive; i < toExclusive; i++) {
        if (i > fromInclusive) sb.append('a');
        sb.append(parts.get(i));
      }
      return sb.toString();
    }

    private String joinNonEmptyWithA(String left, String right) {
      if (left.isEmpty()) return right;
      if (right.isEmpty()) return left;
      return left + 'a' + right;
    }
  }

  /** CSSPropertyVerifier specialization for the {@code content} property. */
  static class ContentPropertyVerifier extends CSSPropertyVerifier {
    /**
     * Creates a verifier for {@code content} constrained by the given allowed keywords.
     *
     * @param allowedValues additional literal keywords accepted by {@code content}; may be {@code
     *     null}.
     */
    ContentPropertyVerifier(Collection<String> allowedValues) {
      super(allowedValues, null, null, null);
    }

    /**
     * Checks whether the supplied {@code content} value is acceptable.
     *
     * <p>Accepts a single keyword from {@code allowedValues}, any string, or a counter/counters
     * construct with an optional list style type.
     *
     * @param media unused for {@code content}; may be {@code null}.
     * @param elements unused for {@code content}; may be {@code null}.
     * @param value tokenized value; must contain exactly one token.
     * @param cb callback consulted for URL validation (not used here).
     * @return {@code true} when the value is valid for {@code content}.
     */
    @Override
    public boolean checkValidity(
        String[] media, String[] elements, ParsedWord[] value, FilterCallback cb) {
      if (LOG.isTraceEnabled())
        LOG.trace("ContentPropertyVerifier checkValidity called: {}", toString(value));
      if (value.length != 1) return false;
      if (value[0] instanceof ParsedIdentifier identifier
          && allowedValues != null
          && allowedValues.contains(identifier.getDecoded())) return true;
      // String processing
      if (value[0] instanceof ParsedString) {
        return true;
      }
      if (value[0] instanceof ParsedCounter counter) {
        if (counter.listType != null) {
          HashSet<String> listStyleType =
              new HashSet<>(
                  Arrays.asList(
                      "disc",
                      V_CIRCLE,
                      "square",
                      "decimal",
                      "decimal-leading-zero",
                      "lower-roman",
                      "upper-roman",
                      "lower-greek",
                      "lower-latin",
                      "upper-latin",
                      "armenian",
                      "georgian",
                      "lower-alpha",
                      "upper-alpha",
                      "none",
                      "arabic-indic",
                      "bengali",
                      "cambodian",
                      "cjk-decimal",
                      "cjk-earthly-branch",
                      "cjk-heavenly-stem",
                      "cjk-ideographic",
                      "devanagari",
                      "disclosure-closed",
                      "disclosure-open",
                      "ethiopic-numeric",
                      "gujarati",
                      "gurmukhi",
                      "hebrew",
                      "hiragana",
                      "hiragana-iroha",
                      "japanese-formal",
                      "japanese-informal",
                      "kannada",
                      "katakana",
                      "katakana-iroha",
                      "khmer",
                      "korean-hangul-formal",
                      "korean-hanja-formal",
                      "lao",
                      "lower-armenian",
                      "malayalam",
                      "mongolian",
                      "myanmar",
                      "oriya",
                      "persian",
                      "simp-chinese-formal",
                      "simp-chinese-informal",
                      "tamil",
                      "telugu",
                      "thai",
                      "tibetan",
                      "trad-chinese-formal",
                      "trad-chinese-informal",
                      "upper-armenian"));
          return listStyleType.contains(counter.listType.getDecoded());
        }
        return true;
      }
      return value[0] instanceof ParsedAttr;
    }
  }

  /**
   * Verifier for font-related shorthand parts such as style, variant, weight, size, and
   * line-height.
   */
  static class FontPartPropertyVerifier extends CSSPropertyVerifier {
    /** Creates a verifier for parts used by the {@code font} shorthand. */
    FontPartPropertyVerifier() {
      super(false);
    }

    @Override
    public boolean checkValidity(
        String[] media, String[] elements, ParsedWord[] value, FilterCallback cb) {
      if (LOG.isTraceEnabled())
        LOG.trace("FontPartPropertyVerifier called with {}", toString(value));
      CSSPropertyVerifier fontSize = buildFontSizeVerifier();
      if (fontSize.checkValidity(value, cb)) return true;
      for (ParsedWord word : value) {
        if (!isValidFontSizeOrSlashForm(fontSize, word, cb)) return false;
      }
      return true;
    }

    private CSSPropertyVerifier buildFontSizeVerifier() {
      return new CSSPropertyVerifier(
          Arrays.asList(
              "xx-small",
              "x-small",
              "small",
              V_MEDIUM,
              "large",
              "x-large",
              "xx-large",
              "larger",
              "smaller"),
          Arrays.asList("le", "pe"),
          null,
          null,
          true);
    }

    private boolean isValidFontSizeOrSlashForm(
        CSSPropertyVerifier fontSize, ParsedWord word, FilterCallback cb) {
      if (fontSize.checkValidity(word, cb)) return true;
      if (!(word instanceof SimpleParsedWord sp)) return false;
      String orig = sp.original;
      int slashIndex = orig.indexOf('/');
      if (slashIndex <= 0 || slashIndex == orig.length() - 1) return false;

      String firstPart = orig.substring(0, slashIndex);
      String secondPart = orig.substring(slashIndex + 1);
      CSSPropertyVerifier lineHeight =
          new CSSPropertyVerifier(
              List.of(V_NORMAL), Arrays.asList("le", "pe", "re", "in"), null, null, true);
      ParsedWord[] first = split(firstPart, false);
      ParsedWord[] second = split(secondPart, false);
      return first.length == 1
          && second.length == 1
          && fontSize.checkValidity(first, cb)
          && lineHeight.checkValidity(second, cb);
    }
  }

  /** Base verifier for properties that accept comma-separated font family lists. */
  abstract static class FamilyPropertyVerifier extends CSSPropertyVerifier {
    /**
     * Creates a font-family style verifier.
     *
     * @param valueOnly when {@code true}, ignores media/element context.
     * @param mediaTypes optional set of media identifiers for which this verifier applies.
     */
    FamilyPropertyVerifier(boolean valueOnly, Set<String> mediaTypes) {
      super(null, mediaTypes, null, null, valueOnly, true);
    }

    // We do not change the tokens.
    // We probably should put in quotes around unquoted font family names, put spaces after commas
    // etc., but this may be a bit tricky: we'd have to put spaces etc. inside some words, and
    // delete some
    // words...
    // Quite possible, but not a high priority, "verdana,arial,times new roman,sans-serif" is not
    // dangerous, it's just hard to parse.
    @Override
    public boolean checkValidity(
        String[] media, String[] elements, ParsedWord[] value, FilterCallback cb) {
      if (LOG.isTraceEnabled()) LOG.trace("font verifier: {}", toString(value));
      if (isInherit(value)) return true;

      if (!isMediaAllowed(media)) return false;

      ArrayList<String> fontWords = new ArrayList<>();
      // Delete fonts we don't know about but let through ones we do.
      // Or allow unknown fonts given [a-z][A-Z][0-9] ???
      int i = 0;
      while (i < value.length) {
        ParsedWord word = value[i];
        StartDecision start = analyzeStartWord(word, i);

        if (start.kind() == StartDecision.Kind.CONTINUE) {
          i++;
          continue;
        }
        if (start.kind() == StartDecision.Kind.INVALID) return false;

        // START of an unquoted, possibly multi-word font name
        fontWords.clear();
        fontWords.add(start.firstWord());
        if (LOG.isTraceEnabled()) LOG.trace("first word: \"{}\"", start.firstWord());

        ProcessResult pr = consumeUnquotedFont(value, i, fontWords);
        if (pr.shouldReturn) return pr.returnValue;

        // Continue the outer loop from the consumed index
        i = pr.nextIndex + 1;
      }
      if (LOG.isTraceEnabled()) LOG.trace("font: reached end, valid");
      return true;
    }

    private boolean isInherit(ParsedWord[] value) {
      if (value.length != 1) return false;
      ParsedWord w = value[0];
      if (w instanceof ParsedIdentifier && "inherit".equalsIgnoreCase(w.original)) {
        if (LOG.isTraceEnabled()) LOG.trace("font: inherit");
        return true;
      }
      return false;
    }

    private boolean isMediaAllowed(String[] media) {
      if (allowedMedia == null || onlyValueVerifier) return true;
      for (String m : media) {
        if (allowedMedia.contains(m)) return true;
      }
      if (LOG.isDebugEnabled())
        LOG.debug(
            "FontPartPropertyVerifier media not allowed. media={} allowedMedia={}",
            Fields.commaList(media),
            allowedMedia);
      return false;
    }

    private StartDecision analyzeStartWord(ParsedWord word, int index) {
      if (word instanceof ParsedString s) return analyzeStartFromString(s);
      if (word instanceof ParsedIdentifier id) return analyzeStartFromIdentifier(id, word, index);
      return StartDecision.invalid();
    }

    private StartDecision analyzeStartFromString(ParsedString string) {
      String decoded = string.getDecoded();
      if (LOG.isTraceEnabled()) LOG.trace("decoded: \"{}\"", decoded);
      String lower = decoded.toLowerCase(Locale.ROOT);
      if (isSpecificFamily(lower) || isGenericFamily(lower)) return StartDecision.continueNext();
      return StartDecision.startWith(decoded);
    }

    private StartDecision analyzeStartFromIdentifier(
        ParsedIdentifier identifier, ParsedWord raw, int index) {
      String s = identifier.getDecoded();
      if (isGenericFamily(s) || isSpecificFamily(s)) return StartDecision.continueNext();
      if (raw.postComma) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Word ends in comma, but is not a valid font on its own: {} (index {})", raw, index);
        return StartDecision.invalid();
      }
      return StartDecision.startWith(s);
    }

    private ProcessResult consumeUnquotedFont(
        ParsedWord[] value, int startIndex, List<String> fontWords) {
      if (atLastWord(startIndex, value)) return finalizeLastWord(fontWords);
      if (!possiblyValidFontWords(fontWords)) return ProcessResult.returning(false);
      return consumeFollowingFontWords(value, startIndex, fontWords);
    }

    private boolean atLastWord(int startIndex, ParsedWord[] value) {
      return startIndex == value.length - 1;
    }

    private ProcessResult finalizeLastWord(List<String> fontWords) {
      boolean ok = validFontWords(fontWords);
      if (LOG.isDebugEnabled())
        LOG.debug(
            "last word. font words: {} valid={}",
            getStringFromArray(fontWords.toArray(new String[0])),
            ok);
      return ProcessResult.returning(ok);
    }

    private ProcessResult consumeFollowingFontWords(
        ParsedWord[] value, int startIndex, List<String> fontWords) {
      for (int j = startIndex + 1; j < value.length; j++) {
        ParsedWord newWord = value[j];
        if (!isIdentifier(newWord)) return ProcessResult.returning(false);

        fontWords.add(newWord.original);
        if (LOG.isTraceEnabled()) LOG.trace("adding word: \"{}\"", newWord.original);

        ProcessResult maybe = maybeReturnAtLastIndex(newWord, j, value, fontWords);
        if (maybe != null) return maybe;

        if (newWord.postComma) return handleCommaInFontList(fontWords, j);
      }
      return ProcessResult.returning(validFontWords(fontWords));
    }

    private ProcessResult maybeReturnAtLastIndex(
        ParsedWord newWord, int j, ParsedWord[] value, List<String> fontWords) {
      if (!isLastIndex(j, value)) return null;
      if (newWord.postComma && LOG.isTraceEnabled()) LOG.trace("not valid: trailing comma at end");
      if (validFontWords(fontWords)) return ProcessResult.returning(true);
      return null;
    }

    private boolean isIdentifier(ParsedWord w) {
      if (w instanceof ParsedIdentifier) return true;
      if (LOG.isTraceEnabled()) LOG.trace("cannot parse {}", w);
      return false;
    }

    private boolean isLastIndex(int j, ParsedWord[] value) {
      return j == value.length - 1;
    }

    private ProcessResult handleCommaInFontList(List<String> fontWords, int j) {
      if (validFontWords(fontWords)) {
        fontWords.clear();
        return ProcessResult.continuingFrom(j);
      }
      if (LOG.isDebugEnabled())
        LOG.debug(
            "comma but can't parse font words: {}",
            Fields.commaList(fontWords.toArray(new String[0])));
      return ProcessResult.returning(false);
    }

    private record StartDecision(Kind kind, String firstWord) {
      enum Kind {
        CONTINUE,
        INVALID,
        START
      }

      static StartDecision continueNext() {
        return new StartDecision(Kind.CONTINUE, null);
      }

      static StartDecision invalid() {
        return new StartDecision(Kind.INVALID, null);
      }

      static StartDecision startWith(String first) {
        return new StartDecision(Kind.START, first);
      }
    }

    /**
     * Result container for recursive parser steps.
     *
     * @param shouldReturn when {@code true}, the caller should return immediately using {@code
     *     returnValue}.
     * @param returnValue value to return when {@code shouldReturn} is {@code true}.
     * @param nextIndex next index to continue from when {@code shouldReturn} is {@code false}.
     */
    private record ProcessResult(boolean shouldReturn, boolean returnValue, int nextIndex) {

      static ProcessResult returning(boolean value) {
        return new ProcessResult(true, value, -1);
      }

      static ProcessResult continuingFrom(int index) {
        return new ProcessResult(false, false, index);
      }
    }

    private boolean possiblyValidFontWords(List<String> fontWords) {
      if (ElementInfo.DISALLOW_UNKNOWN_SPECIFIC_FONTS) {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (String s : fontWords) {
          if (!first) sb.append(' ');
          first = false;
          sb.append(s);
        }
        String s = sb.toString().toLowerCase(Locale.ROOT);
        return ElementInfo.isWordPrefixOrMatchOfSpecificFontFamily(s);
      } else {
        for (String s : fontWords) if (!isSpecificFamily(s)) return false;
        return true;
      }
    }

    private boolean validFontWords(List<String> fontWords) {
      for (String s : fontWords) {
        if (s == null) throw new NullPointerException();
      }
      if (fontWords.size() == 1 && isGenericFamily(fontWords.getFirst().toLowerCase(Locale.ROOT)))
        return true;
      StringBuilder sb = new StringBuilder();
      boolean first = true;
      for (String s : fontWords) {
        if (!first) sb.append(' ');
        first = false;
        sb.append(s);
      }
      return isSpecificFamily(sb.toString().toLowerCase(Locale.ROOT));
    }

    /**
     * Tests whether {@code s} denotes a specific font family name rather than a generic family.
     *
     * @param s case-insensitive candidate family name.
     * @return {@code true} if {@code s} is recognized as a specific family.
     */
    abstract boolean isSpecificFamily(String s);

    /**
     * Tests whether {@code s} denotes a generic font family (e.g., {@code serif}).
     *
     * @param s case-insensitive candidate family name.
     * @return {@code true} if {@code s} is recognized as a generic family.
     */
    abstract boolean isGenericFamily(String s);
  }

  /** Verifier for the complex {@code font} shorthand property. */
  static class FontPropertyVerifier extends FamilyPropertyVerifier {
    /**
     * Creates a verifier for the {@code font} shorthand.
     *
     * @param valueOnly when {@code true}, ignores media/element context.
     */
    FontPropertyVerifier(boolean valueOnly) {
      super(valueOnly, ElementInfo.VISUALMEDIA);
    }

    @Override
    boolean isSpecificFamily(String s) {
      return ElementInfo.isSpecificFontFamily(s);
    }

    @Override
    boolean isGenericFamily(String s) {
      return ElementInfo.isGenericFontFamily(s);
    }
  }

  /** Verifier for {@code voice-family} lists (speech-related CSS). */
  static class VoiceFamilyPropertyVerifier extends FamilyPropertyVerifier {
    /**
     * Creates a verifier for {@code voice-family} lists.
     *
     * @param valueOnly when {@code true}, ignores media/element context.
     */
    VoiceFamilyPropertyVerifier(boolean valueOnly) {
      super(valueOnly, ElementInfo.AURALMEDIA);
    }

    @Override
    boolean isSpecificFamily(String s) {
      return ElementInfo.isSpecificVoiceFamily(s);
    }

    @Override
    boolean isGenericFamily(String s) {
      return ElementInfo.isGenericVoiceFamily(s);
    }
  }

  /**
   * Removes a single matching pair of outer quotes from the given string when present.
   *
   * <p>Quotes must be balanced and use the same quote character at both ends. Inner characters are
   * not interpreted.
   *
   * @param decoded input string to examine; may be quoted with single or double quotes.
   * @return the inner substring when quoted; otherwise returns the original input unchanged.
   */
  public static String removeOuterQuotes(String decoded) {
    if (decoded.length() < 2) return decoded;
    char first = decoded.charAt(0);
    if (!(first == '\'' || first == '\"')) return decoded;
    if (decoded.charAt(decoded.length() - 1) == first) {
      return decoded.substring(1, decoded.length() - 1);
    }
    return decoded;
  }

  /**
   * Returns the charset declared by an {@code @charset} statement encountered during parsing.
   *
   * <p>The value is only available after a successful {@link #parse()} run that encountered a
   * {@code @charset}. When {@code stopAtDetectedCharset} is {@code true}, the method still reports
   * the detected value even though no output is written.
   *
   * @return the detected charset name in the source, or {@code null} when no {@code @charset} was
   *     present.
   */
  public String detectedCharset() {
    return detectedCharset;
  }
}
