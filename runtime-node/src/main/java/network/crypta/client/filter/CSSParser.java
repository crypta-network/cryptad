package network.crypta.client.filter;

import java.io.Reader;
import java.io.Writer;

/**
 * Parser and sanitizer for cascading style sheets used by the client filtering pipeline.
 *
 * <p>This class is a thin, package‑scope façade over {@link CSSTokenizerFilter}. It exists to
 * provide a concise entry point for code that needs to parse CSS from a {@link Reader}, validate it
 * with a {@link FilterCallback}, and write the sanitized output to a {@link Writer}. The
 * implementation focuses on robust tokenization and conservative validation rather than exhaustive
 * specification coverage, which keeps the behavior predictable and resistant to malicious input. In
 * particular, it purposefully allows a broadly useful subset of CSS while dropping unknown or
 * dangerous constructs.
 *
 * <p>Compared to the HTML filter, this parser is intentionally less exhaustive: it does not attempt
 * to enumerate every attribute or vendor extension. Future CSS features could introduce additional
 * include mechanisms or metadata; the design mitigates this by validating {@code @import} and
 * {@code url()} through the callback and by ignoring unrecognized or structurally invalid tokens.
 * This is still substantially more rigorous than the legacy CSS filter used earlier in the codebase
 * and has proved resilient in practice.
 *
 * <ul>
 *   <li>Input: reads characters from a {@link Reader} and discovers {@code @charset} declarations.
 *   <li>URIs: validates and optionally rewrites via {@link FilterCallback#processURI(String,
 *       String)}.
 *   <li>Output: emits normalized, filtered CSS to a caller‑supplied {@link Writer}.
 *   <li>Mode: supports full stylesheets and inline style attribute heuristics.
 * </ul>
 *
 * <p>Thread‑safety: instances are not thread‑safe. Create a new parser per input and do not share
 * across threads.
 *
 * @see CSSTokenizerFilter
 * @see CSSReadFilter
 * @see FilterCallback
 */
class CSSParser extends CSSTokenizerFilter {

  /**
   * Creates a CSS parser bound to the given streams and validation callback.
   *
   * <p>The parser reads CSS from {@code r}, validates selectors, properties, and URIs using {@code
   * cb}, and writes sanitized CSS to {@code w}. The {@code charset} name is used for comparing any
   * in‑document {@code @charset} declarations. When {@code stopAtDetectedCharset} is {@code true},
   * the parser halts after encountering an explicit {@code @charset} and does not emit output;
   * callers can then restart with the detected encoding if desired. The {@code isInline} flag
   * enables minor heuristics appropriate for inline style attributes rather than full sheets.
   *
   * @param r character input supplying the stylesheet content; must be non‑null when {@link
   *     #parse()} is invoked, and positioned at the start of the CSS to be read.
   * @param w destination writer that receives filtered CSS output; caller retains responsibility
   *     for closing and flushing the stream after parsing completes.
   * @param cb callback used to validate or rewrite URIs referenced by the stylesheet; it may reject
   *     disallowed schemes or hosts and return {@code null} to indicate rejection.
   * @param charset declared input charset name used for case‑insensitive comparison with any
   *     {@code @charset} directive encountered during parsing; may be {@code null}.
   * @param stopAtDetectedCharset when {@code true}, stop immediately after detecting
   *     {@code @charset} and write nothing, allowing the caller to reconfigure decoding.
   * @param isInline when {@code true}, parse using rules suitable for inline style attributes,
   *     which differ slightly from full stylesheet handling.
   */
  CSSParser(
      Reader r,
      Writer w,
      FilterCallback cb,
      String charset,
      boolean stopAtDetectedCharset,
      boolean isInline) {
    super(r, w, cb, charset, stopAtDetectedCharset, isInline);
  }
}
