package network.crypta.client.filter;

import java.util.Set;
import java.util.regex.Pattern;

/**
 * Catalog and validation utilities for HTML/CSS filtering.
 *
 * <p>This class centralizes whitelists and small, allocation‑free validators used by the CSS and
 * HTML content filters. It answers questions such as whether a token is a valid CSS identifier,
 * whether a pseudo‑class is acceptable, and whether a tag name is part of the allowed element set.
 * The API is intentionally small and based on primitives so it can be called frequently during
 * tokenization and parsing without introducing extra object churn.
 *
 * <p>The class is stateless and thread‑safe. All collections exposed as {@code public static final}
 * are effectively immutable and read‑only; they can be shared across threads and reused for the
 * lifetime of the JVM. Validation methods perform strict syntax checks that are aligned with the
 * filtering needs of Crypta. For example, identifier parsing supports CSS escapes, including
 * hexadecimal escapes and line continuation rules.
 *
 * <ul>
 *   <li>Responsibilities: small validators and curated token sets.
 *   <li>Performance: avoids allocations and favors simple character checks.
 *   <li>Thread‑safety: all members are either constants or pure functions.
 * </ul>
 */
public class ElementInfo {
  private ElementInfo() {
    throw new IllegalStateException("Utility class");
  }

  /**
   * Controls whether specific font family names must be on a known allow list.
   *
   * <p>When {@code true}, {@link #isSpecificFontFamily(String)} accepts only names present in the
   * predefined {@link #FONTS} set. When {@code false}, the decision may be delegated to the {@link
   * #DISALLOW_NON_ALNUM_FONTS} guard for character‑level checks.
   */
  public static final boolean DISALLOW_UNKNOWN_SPECIFIC_FONTS = false;

  /**
   * Restricts font family names to a conservative character set.
   *
   * <p>When {@code true}, specific font families are allowed only if every character is a space,
   * digit, ASCII letter, or one of {@code . _ - , + ~}. This helps prevent control characters or
   * punctuation with special meaning from leaking into style contexts.
   */
  public static final boolean DISALLOW_NON_ALNUM_FONTS = true;

  /**
   * Upper limit used by callers that require a small, integral bound.
   *
   * <p>The constant is exposed for consistency with historical usage in the filtering subsystem.
   * Semantics are intentionally neutral; no units are implied by this symbol.
   */
  public static final int UPPERLIMIT = 10;

  // Common media keywords reused across multiple sets (Sonar: java:S1192)
  private static final String MEDIA_HANDHELD = "handheld";
  private static final String MEDIA_PRINT = "print";
  private static final String MEDIA_PROJECTION = "projection";
  private static final String MEDIA_SCREEN = "screen";
  private static final String MEDIA_TTY = "tty";
  private static final String MEDIA_TV = "tv";
  private static final String MEDIA_SPEECH = "speech";

  // Pseudo-class tokens reused in validation (Sonar: java:S1192)
  private static final String PC_LANG = "lang";
  private static final String PC_NTH_CHILD = "nth-child";
  private static final String PC_NTH_LAST_CHILD = "nth-last-child";
  private static final String PC_NTH_OF_TYPE = "nth-of-type";
  private static final String PC_NTH_LAST_OF_TYPE = "nth-last-of-type";
  private static final String PC_DIR = "dir";

  /**
   * Set of HTML void elements (no closing tag, no content).
   *
   * <p>Members are lower‑case tag names. The set is read‑only and intended for lookups via {@link
   * #isVoidElement(String)} and related helpers in the filtering pipeline.
   */
  public static final Set<String> VOID_ELEMENTS =
      Set.of(
          "area",
          "base",
          "basefont",
          "bgsound",
          "br",
          "col",
          "command",
          "embed",
          "event-source",
          "frame",
          "hr",
          "img",
          "input",
          "keygen",
          "link",
          "meta",
          "param",
          "source",
          "spacer",
          "wbr");

  /**
   * Allowed HTML elements for the sanitizer layer.
   *
   * <p>This is a snapshot of the configured allow list at class‑load time. Names are typically
   * lower‑case; callers that accept user input should normalize the case or use {@link
   * #isValidHTMLTag(String)} which performs the appropriate case handling.
   */
  public static final Set<String> HTML_ELEMENTS = Set.copyOf(HTMLFilter.getAllowedHTMLTags());

  /**
   * CSS media types recognized by the filter.
   *
   * <p>The set includes legacy and current tokens as lower‑case strings (for example, {@code all},
   * {@code screen}, {@code print}). It is immutable and safe for concurrent access.
   */
  public static final Set<String> MEDIA =
      Set.of(
          "all",
          "aural",
          "braille",
          "embossed",
          MEDIA_HANDHELD,
          MEDIA_PRINT,
          MEDIA_PROJECTION,
          MEDIA_SCREEN,
          MEDIA_SPEECH,
          MEDIA_TTY,
          MEDIA_TV);

  /**
   * Subset of {@link #MEDIA} representing visual media contexts.
   *
   * <p>Contains only tokens relevant to visual rendering surfaces. Immutable and thread‑safe.
   */
  public static final Set<String> VISUALMEDIA =
      Set.of(MEDIA_HANDHELD, MEDIA_PRINT, MEDIA_PROJECTION, MEDIA_SCREEN, MEDIA_TTY, MEDIA_TV);

  /**
   * Subset of media tokens that target aural/speech output.
   *
   * <p>Contains {@code speech} and historical {@code aural}. Immutable and thread‑safe.
   */
  public static final Set<String> AURALMEDIA = Set.of(MEDIA_SPEECH, "aural");

  /**
   * Visual media intended for paged output environments.
   *
   * <p>Includes tokens such as {@code print} and {@code embossed}. Immutable and thread‑safe.
   */
  public static final Set<String> VISUALPAGEDMEDIA =
      Set.of(
          "embossed",
          MEDIA_HANDHELD,
          MEDIA_PRINT,
          MEDIA_PROJECTION,
          MEDIA_SCREEN,
          MEDIA_TTY,
          MEDIA_TV);

  /**
   * Visual media intended for interactive environments.
   *
   * <p>Includes screen‑oriented and input‑capable media kinds. Immutable and thread‑safe.
   */
  public static final Set<String> VISUALINTERACTIVEMEDIA =
      Set.of(
          "braille",
          MEDIA_HANDHELD,
          MEDIA_PRINT,
          MEDIA_PROJECTION,
          MEDIA_SCREEN,
          MEDIA_SPEECH,
          MEDIA_TTY,
          MEDIA_TV);

  /**
   * Canonical allow list of specific font family names.
   *
   * <p>The names are provided in lower‑case. This list is used when {@link
   * #DISALLOW_UNKNOWN_SPECIFIC_FONTS} is enabled to constrain accepted family names. Immutable and
   * shared across threads.
   */
  public static final Set<String> FONTS =
      Set.of(
          "arial",
          "helvetica",
          "arial black",
          "gadget",
          "comic sans ms",
          "comic sans ms5",
          "courier new",
          "courier6",
          "monospace georgia1",
          "georgia",
          "impact",
          "impact5",
          "charcoal6",
          "lucida console",
          "monaco5",
          "lucida sans unicode",
          "lucida grande",
          "palatino linotype",
          "book antiqua3",
          "palatino6",
          "tahoma",
          "geneva",
          "times new roman",
          "times",
          "trebuchet ms1",
          "verdana",
          "webdings",
          "webdings2",
          "wingdings",
          "zapf dingbats",
          "zapf dingbats2",
          "ms sans serif4",
          "ms serif4",
          "new york6");

  // https://developer.mozilla.org/en-US/docs/Web/CSS/font-family
  /**
   * Generic font family keywords defined by CSS.
   *
   * <p>Examples include {@code serif}, {@code sans-serif}, and {@code system-ui}. Values are
   * expected to be provided in lower‑case by callers that perform validation.
   */
  public static final Set<String> GENERIC_FONT_KEYWORDS =
      Set.of(
          "serif",
          "sans-serif",
          "cursive",
          "fantasy",
          "monospace",
          "system-ui",
          "ui-serif",
          "ui-sans-serif",
          "ui-monospace",
          "ui-rounded",
          "emoji",
          "math",
          "fangsong");

  /**
   * Generic voice family keywords used by speech synthesis properties.
   *
   * <p>Contains a small, conventional set. Case handling is left to call sites.
   */
  public static final Set<String> GENERIC_VOICE_KEYWORDS = Set.of("male", "female", "child");

  /**
   * Pseudo‑classes that the filter recognizes as valid or specially handled.
   *
   * <p>Members are provided as lower‑case names; some entries require argument validation which is
   * performed by {@link #isValidPseudoClass(String)}.
   */
  public static final Set<String> PSEUDOCLASS =
      Set.of(
          "first-child",
          "last-child",
          PC_NTH_CHILD,
          PC_NTH_LAST_CHILD,
          PC_NTH_OF_TYPE,
          PC_NTH_LAST_OF_TYPE,
          "link", // inverse of visited (see BANNED_PSEUDOCLASS below)
          "visited", // privacy risk (see BANNED_PSEUDOCLASS below)
          "hover",
          "active",
          "checked", // forms
          "focus",
          "focus-within",
          "first-line",
          "first-letter",
          "before",
          "after",
          "target",
          "any-link",
          "default", // forms
          "defined", // Javascript only (BANNED_PSEUDOCLASS)
          "disabled", // forms
          "empty",
          "enabled", // forms
          "focus-visible",
          "indeterminate", // forms
          "in-range", // forms
          "invalid", // forms
          "only-child",
          "only-of-type",
          "optional", // forms
          "out-of-range", // forms
          "placeholder-shown", // forms
          "read-only", // forms
          "read-write", // forms
          "required", // forms
          "root");

  // :visited is considered harmful as it may leak browser history to an adversary.
  // This may not be obvious immediately, but :visited gives an adversary the
  // opportunity to tailor the page to the user's browser history, and may capture
  // this information based on where the user interacts (e.g. he can alternate the
  // visibility of buttons/links on the page based on browser history to encode
  // exactly which sites of interest a user has visited in the past, and use the
  // click to either 1) send this information somewhere through a reachable social
  // networking plugin, or 2) somehow present this knowledge to the user as a scare
  // tactic)
  //
  // The fact that CSS can do Boolean algebra[1] makes this attack easy: the
  // attacker
  // can query a large number of sites in the browser history using only a limited
  // number
  // of previously mentioned buttons or links.
  //
  // A general lack of :visited does not harm the user experience much; especially
  // on
  // Freenet where we often use USKs to visit sites, which are implemented through
  // permanent redirects. Users should hence already expect :visited not to work
  // occasionally. The downside is that some (if only a few) freesites will look
  // less pretty. Given the lack of harm to the overall user experience, and the
  // effectiveness of potential attacks through :visited, we disallow :visited in
  // CSS selectors (by ignoring it).
  //
  // TL;DR: Protecting the user is the main purpose of the CSS ContentFilter,
  // :visited
  //        is considered too much of a danger, so we scrub that pseudoclass.
  //
  // [1] http://lcamtuf.coredump.cx/css_calc/
  /**
   * Pseudo‑classes that are explicitly disallowed during filtering.
   *
   * <p>For example, {@code :visited} is blocked due to privacy risks. The set is immutable.
   */
  public static final Set<String> BANNED_PSEUDOCLASS =
      Set.of(
          "link",
          "visited",
          // Javascript only
          "defined");

  /**
   * Tests whether a specific font family name is acceptable.
   *
   * <p>When {@link #DISALLOW_UNKNOWN_SPECIFIC_FONTS} is {@code true}, only values present in {@link
   * #FONTS} are accepted. Otherwise, when {@link #DISALLOW_NON_ALNUM_FONTS} is {@code true} the
   * name must consist solely of spaces, digits, ASCII letters, or {@code . _ - , + ~}.
   *
   * @param font candidate font family name to validate; expected in its original form; never {@code
   *     null}.
   * @return {@code true} when the name conforms to the currently configured constraints; {@code
   *     false} otherwise.
   */
  public static boolean isSpecificFontFamily(String font) {
    if (DISALLOW_UNKNOWN_SPECIFIC_FONTS) {
      return FONTS.contains(font);
    } else if (DISALLOW_NON_ALNUM_FONTS) {
      for (int i = 0; i < font.length(); i++) {
        char c = font.charAt(i);
        if (!(Character.isLetterOrDigit(c)
            || c == ' '
            || c == '.'
            || c == '_'
            || c == '-'
            || c == ','
            || c == '+'
            || c == '~')) return false;
      }
      return true;
    }
    // Allow anything. The caller will have enforced that unquoted font names must not contain
    // non-identifier characters.
    return true;
  }

  /**
   * Tests whether a specific voice family name is acceptable.
   *
   * <p>When {@link #DISALLOW_NON_ALNUM_FONTS} is {@code true}, the same conservative character
   * whitelist as font families applies.
   *
   * @param font candidate voice family token to validate; expected in its original form; never
   *     {@code null}.
   * @return {@code true} when the token conforms to the configured constraints; {@code false}
   *     otherwise.
   */
  public static boolean isSpecificVoiceFamily(String font) {
    if (DISALLOW_NON_ALNUM_FONTS) {
      for (int i = 0; i < font.length(); i++) {
        char c = font.charAt(i);
        if (!(Character.isLetterOrDigit(c)
            || c == ' '
            || c == '.'
            || c == '_'
            || c == '-'
            || c == ','
            || c == '+'
            || c == '~')) return false;
      }
      return true;
    }
    // Allow anything. The caller will have enforced that unquoted font names must not contain
    // non-identifier characters.
    return true;
  }

  /**
   * Checks whether the supplied token is a generic font family keyword.
   *
   * <p>Callers are expected to lowercase the input before validation. The method performs a set
   * membership test against {@link #GENERIC_FONT_KEYWORDS}.
   *
   * @param font lower‑case candidate keyword such as {@code serif} or {@code monospace}; never
   *     {@code null}.
   * @return {@code true} when the token is among the known generic font families; {@code false}
   *     otherwise.
   */
  public static boolean isGenericFontFamily(String font) {
    return GENERIC_FONT_KEYWORDS.contains(font);
  }

  /**
   * Checks whether the supplied token is a generic voice family keyword.
   *
   * <p>Callers are expected to lowercase the input before validation. The method performs a set
   * membership test against {@link #GENERIC_VOICE_KEYWORDS}.
   *
   * @param font lower‑case candidate keyword such as {@code male} or {@code child}; never {@code
   *     null}.
   * @return {@code true} when the token is among the known generic voice families; {@code false}
   *     otherwise.
   */
  public static boolean isGenericVoiceFamily(String font) {
    return GENERIC_VOICE_KEYWORDS.contains(font);
  }

  /**
   * Returns whether the argument equals or is a word‑prefix of any allowed specific font.
   *
   * <p>A word prefix is checked against a space‑delimited boundary (for example, {@code "lucida"}
   * is a prefix of {@code "lucida grande"}). This enables type‑ahead in UIs while keeping the
   * matching logic aligned with how font family lists are tokenized.
   *
   * @param prefix lower‑case candidate string compared against {@link #FONTS}; never {@code null}.
   * @return {@code true} when the argument is either an exact match or a word prefix; otherwise
   *     {@code false}.
   */
  public static boolean isWordPrefixOrMatchOfSpecificFontFamily(String prefix) {
    String extraSpace = prefix + " ";
    for (String s : FONTS) if (s.equals(prefix) || s.startsWith(extraSpace)) return true;
    return false;
  }

  /**
   * Tests whether the supplied tag name is a void element.
   *
   * <p>Void elements do not accept content and do not use a closing tag. Input is compared using
   * the case of the provided argument; call sites commonly lowercase input first.
   *
   * @param element HTML tag name to check; expected as a simple name without angle brackets; never
   *     {@code null}.
   * @return {@code true} if the name is contained in {@link #VOID_ELEMENTS}; {@code false}
   *     otherwise.
   */
  public static boolean isVoidElement(String element) {
    return VOID_ELEMENTS.contains(element);
  }

  /**
   * Indicates whether the parser should auto‑close the given element in common nesting cases.
   *
   * <p>This supports HTML list semantics where consecutive {@code li} items do not nest inside one
   * another. If the supplied name is {@code "li"}, the method returns {@code true}; other elements
   * currently return {@code false}.
   *
   * @param element HTML tag name to test; expected as a simple name; never {@code null}.
   * @return {@code true} when the element should be auto‑closed before inserting the next peer;
   *     otherwise {@code false}.
   */
  public static boolean tryAutoClose(String element) {
    return "li".equals(element);
  }

  /**
   * Checks whether the supplied tag name is allowed by the HTML sanitizer.
   *
   * <p>The comparison is effectively case‑insensitive: the method normalizes the argument to lower
   * case and checks membership in {@link #HTML_ELEMENTS} and {@link #VOID_ELEMENTS}.
   *
   * @param tag HTML tag name to validate; expected without angle brackets; never {@code null}.
   * @return {@code true} when the normalized name is in the allow list; {@code false} otherwise.
   */
  public static boolean isValidHTMLTag(String tag) {
    return (HTML_ELEMENTS.contains(tag.toLowerCase()) || VOID_ELEMENTS.contains(tag.toLowerCase()));
  }

  /**
   * Validates an HTML {@code id}/name‑like token against a conservative character set.
   *
   * <p>The first character must be an ASCII letter; subsequent characters may be letters, digits,
   * underscore, colon, dot, or hyphen. This method is used for simple attribute‑style identifiers
   * and is stricter than general CSS identifiers.
   *
   * @param name token to validate; evaluated character by character; never {@code null}.
   * @return {@code true} when the token matches the allowed pattern; {@code false} otherwise.
   */
  public static boolean isValidName(String name) {
    if (name.isEmpty()) return false;
    char first = name.charAt(0);
    if (!isAsciiLetter(first)) return false;
    for (int i = 1; i < name.length(); i++) {
      if (!isValidNameChar(name.charAt(i))) return false;
    }
    return true;
  }

  private static boolean isAsciiLetter(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
  }

  private static boolean isValidNameChar(char c) {
    return isAsciiLetter(c)
        || (c >= '0' && c <= '9')
        || c == '_'
        || c == ':'
        || c == '.'
        || c == '-';
  }

  /**
   * Validates a CSS identifier, including support for escapes and line continuations.
   *
   * <p>The parser accepts hexadecimal escapes of up to six digits and the backslash‑newline
   * continuation defined by CSS 2.1. Digits are restricted in leading positions unless escaped.
   * Control characters are rejected.
   *
   * @param name candidate identifier to validate in its original form; never {@code null}.
   * @return {@code true} if the token conforms to the identifier grammar accepted by the filter;
   *     {@code false} otherwise.
   */
  public static boolean isValidIdentifier(String name) {
    if (name.isEmpty()) {
      return false;
    } else {
      EscapeState esc = new EscapeState();
      boolean digitsAllowed = false;
      for (int i = 0; i < name.length(); i++) {
        char c = name.charAt(i);
        NonEscapeResult r = processIdentifierChar(c, esc, digitsAllowed);
        if (!r.valid) return false;
        digitsAllowed = r.digitsAllowed;
      }

      // Still in an escape.
      // Might be dangerous e.g. escaping the ] in E[foo=blah] could change the meaning completely.
      return !esc.escape;
    }
  }

  private static final class EscapeState {
    boolean escape = false;
    boolean escapeNewline = false;
    int unicodeChars = 0;
  }

  // Returns: -1 invalid, 1 consumed (continue), 0 proceed with non-escape handling
  private static int handleIdentifierEscape(char c, EscapeState st) {
    // Whitespace after an escape can be \r\n
    if (st.escapeNewline) {
      // We previously saw a CR as part of a line continuation. Consume an optional LF
      // and then treat the current character (if not LF) as a normal non-escape char.
      st.escapeNewline = false;
      st.escape = false;
      if (c == '\n') {
        return 1; // consumed the LF of CRLF
      }
      return 0; // process this char with non-escape handling
    }

    // Unicode escape: up to 6 hex digits, optionally followed by whitespace which is consumed
    if (isHexDigit(c)) {
      if (st.unicodeChars == 5) {
        // Full 6 character escape.
        st.unicodeChars = 0;
        st.escape = false;
      } else {
        st.unicodeChars++;
      }
      return 1;
    }
    if (st.unicodeChars > 0) {
      if (c == '\r') {
        // Consume CR and an optional following LF as whitespace terminator for the Unicode escape
        st.escapeNewline = true;
        st.unicodeChars = 0;
        return 1;
      } else if (!isWhitespaceAfterUnicodeEscape(c)) {
        // Only whitespace is allowed after a Unicode character escape.
        return -1;
      } else {
        // Whitespace after Unicode escape: consume and end the escape
        st.unicodeChars = 0;
        st.escape = false;
        return 1;
      }
    }
    // Line continuation per CSS 2.1 §4.1.3: a backslash followed by a newline is ignored
    if (c == '\r') {
      st.escapeNewline = true; // consume optional LF on next char
      // keep escape state until we handle the optional LF, then reset
      return 1;
    }
    if (c == '\n' || c == '\f') {
      // Consume LF or FF directly and end the escape
      st.escape = false;
      st.unicodeChars = 0;
      return 1;
    }
    // Directly escaped character
    st.escape = false;
    return 1;
  }

  private static boolean isDigit(char c) {
    return c >= '0' && c <= '9';
  }

  private static boolean isHexDigit(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
  }

  @SuppressWarnings("BooleanMethodIsAlwaysInverted")
  private static boolean isWhitespaceAfterUnicodeEscape(char c) {
    return c == '\n' || c == '\f' || c == '\t' || c == ' ';
  }

  private static boolean isNonAsciiPrintable(char c) {
    return c >= 0xA1 && !Character.isISOControl(c);
  }

  private record NonEscapeResult(boolean valid, boolean digitsAllowed, boolean escape) {}

  private static NonEscapeResult processIdentifierNonEscape(char c, boolean digitsAllowed) {
    if (digitsAllowed && isDigit(c)) {
      return new NonEscapeResult(true, true, false);
    }
    if (c == '-') {
      return new NonEscapeResult(true, digitsAllowed, false);
    }
    boolean newDigitsAllowed = true;
    if (c == '_') {
      return new NonEscapeResult(true, newDigitsAllowed, false);
    }
    if (c == '\\') {
      return new NonEscapeResult(true, newDigitsAllowed, true);
    }
    if (isAsciiLetter(c)) {
      return new NonEscapeResult(true, newDigitsAllowed, false);
    }
    if (isNonAsciiPrintable(c)) {
      // Spec strictly speaking allows control chars, but let's disallow them here as a paranoid
      // precaution.
      return new NonEscapeResult(true, newDigitsAllowed, false);
    }
    return new NonEscapeResult(false, digitsAllowed, false);
  }

  private static NonEscapeResult processIdentifierChar(
      char c, EscapeState esc, boolean digitsAllowed) {
    if (esc.escape) {
      int escAction = handleIdentifierEscape(c, esc);
      if (escAction < 0) {
        return new NonEscapeResult(false, digitsAllowed, false);
      }
      if (escAction == 0) {
        // Escape resolved without consuming this character (e.g., CR followed by non-LF)
        // process current character with normal non-escape handling
        return processIdentifierNonEscape(c, digitsAllowed);
      }
      // Consumed, digitsAllowed unchanged
      return new NonEscapeResult(true, digitsAllowed, false);
    }
    NonEscapeResult r = processIdentifierNonEscape(c, digitsAllowed);
    if (!r.valid) return r;
    if (r.escape) esc.escape = true;
    return new NonEscapeResult(true, r.digitsAllowed, false);
  }

  /**
   * Returns whether a pseudo‑class (or chain) contains a banned entry.
   *
   * <p>The method supports colon‑chained pseudo‑classes by splitting on {@code ':'} and checking
   * each sub‑token against {@link #BANNED_PSEUDOCLASS}.
   *
   * @param cname pseudo‑class token or chain as it appears in a selector; never {@code null}.
   * @return {@code true} when at least one member of the chain is explicitly banned; otherwise
   *     {@code false}.
   */
  public static boolean isBannedPseudoClass(String cname) {
    if (cname.indexOf(':') != -1) {
      // Pseudo-classes can be chained, at least dynamic ones can, see CSS2.1 section 5.11.3
      String[] split = cname.split(":");
      for (String s : split) if (isBannedPseudoClass2(s)) return true;
      return false;
    } else {
      return isBannedPseudoClass2(cname);
    }
  }

  private static boolean isBannedPseudoClass2(String cname) {
    return BANNED_PSEUDOCLASS.contains(cname.toLowerCase());
  }

  /**
   * Validates a pseudo‑class (or chain) against the allow list and argument rules.
   *
   * <p>Argument‑bearing pseudo‑classes such as {@code lang(...)} and {@code nth-child(...)} are
   * parsed to extract and validate their arguments.
   *
   * @param cname pseudo‑class token or chain as it appears in a selector; never {@code null}.
   * @return {@code true} if all members of the chain are recognized and individually valid;
   *     otherwise {@code false}.
   */
  public static boolean isValidPseudoClass(String cname) {
    if (cname.indexOf(':') != -1) {
      // Pseudo-classes can be chained, at least dynamic ones can, see CSS2.1 section 5.11.3
      String[] split = cname.split(":");
      for (String s : split) if (!isValidPseudoClass2(s)) return false;
      return true;
    } else {
      return isValidPseudoClass2(cname);
    }
  }

  private static boolean isValidPseudoClass2(String cname) {
    cname = cname.toLowerCase();
    if (PSEUDOCLASS.contains(cname)) return true;
    else if (cname.startsWith(PC_LANG)
        && Pattern.matches("[\\w\\-*]{1,30}", getPseudoClassArg(cname, PC_LANG))) {
      // More than 8000 valid BCP-47 language codes. Just let through all of them.
      return true;
    } else if (cname.startsWith(PC_NTH_CHILD)
        && FilterUtils.isNth(getPseudoClassArg(cname, PC_NTH_CHILD))) return true;
    else if (cname.startsWith(PC_NTH_LAST_CHILD)
        && FilterUtils.isNth(getPseudoClassArg(cname, PC_NTH_LAST_CHILD))) return true;
    else if (cname.startsWith(PC_NTH_OF_TYPE)
        && FilterUtils.isNth(getPseudoClassArg(cname, PC_NTH_OF_TYPE))) return true;
    else if (cname.startsWith(PC_NTH_LAST_OF_TYPE)
        && FilterUtils.isNth(getPseudoClassArg(cname, PC_NTH_LAST_OF_TYPE))) return true;
    else if (cname.startsWith(PC_DIR)) {
      String arg = getPseudoClassArg(cname, PC_DIR);
      return arg.equalsIgnoreCase("ltr") || arg.equalsIgnoreCase("rtl");
    }
    return false;
  }

  /**
   * Extracts the argument from a single pseudo‑class occurrence.
   *
   * <p>The method expects a token of the form {@code name(arg)} and returns the unquoted and
   * trimmed argument if the structure matches exactly. When the format is not recognized, an empty
   * string is returned.
   *
   * @param cname complete pseudo‑class content (e.g., {@code lang("en-US")}); never {@code null}.
   * @param cnameSansArg the pseudo‑class name without parentheses (e.g., {@code lang}); never
   *     {@code null}.
   * @return the extracted argument with outer quotes removed when present; or an empty string when
   *     the format is not recognized.
   */
  public static String getPseudoClassArg(String cname, String cnameSansArg) {
    String arg = "";
    int cnameIndex = cname.indexOf(cnameSansArg);
    int firstIndex = cname.indexOf('(');
    int secondIndex = cname.lastIndexOf(')');
    if (cnameIndex == -1 || firstIndex == -1 || secondIndex == -1) return "";
    if (cname.substring(cnameIndex + cnameSansArg.length(), firstIndex).trim().isEmpty()
        && cname.substring(0, cnameIndex).trim().isEmpty()
        && cname.substring(secondIndex + 1).trim().isEmpty()) {
      arg =
          CSSTokenizerFilter.removeOuterQuotes(cname.substring(firstIndex + 1, secondIndex).trim());
    }
    return arg;
  }

  /**
   * Tests whether a CSS string token (without surrounding quotes) is safe and syntactically valid.
   *
   * <p>The validator rejects unescaped quote characters and raw newlines, but permits escapes
   * including hexadecimal escapes and the line‑continuation rule. It does not allocate and is
   * intended for use inside tokenization loops.
   *
   * @param name the string to parse in its original encoded form; should not include surrounding
   *     quotes; never {@code null}.
   * @return {@code true} when the string is well‑formed under the accepted rules; {@code false}
   *     otherwise.
   */
  public static boolean isValidString(String name) {
    EscapeState esc = new EscapeState();
    for (int i = 0; i < name.length(); i++) {
      char c = name.charAt(i);
      if (esc.escape) {
        int action = handleStringEscape(c, esc);
        if (action < 0) return false;
        continue;
      }
      // No unquoted quotes
      if (c == '\'' || c == '\"') return false;
      // No unquoted newlines
      if (c == '\r' || c == '\n' || c == '\f') return false;
      if (c == '\\') {
        esc.escape = true;
      }
      // Allow everything else.
    }
    // Still in an escape.
    // Might be dangerous.
    return !esc.escape;
  }

  // Returns: -1 invalid, 1 consumed (continue)
  private static int handleStringEscape(char c, EscapeState st) {
    // Whitespace after an escape can be \r\n
    if (st.escapeNewline) {
      st.escapeNewline = false;
      st.escape = false;
      if (c == '\n') {
        return 1;
      }
    }

    if (isHexDigit(c)) {
      if (st.unicodeChars == 5) {
        // Full 6 character escape.
        st.unicodeChars = 0;
        st.escape = false;
      } else {
        st.unicodeChars++;
      }
      return 1;
    }
    if (st.unicodeChars > 0) {
      if (c == '\r') {
        st.escapeNewline = true;
        st.unicodeChars = 0;
        return 1;
      } else if (!isWhitespaceAfterUnicodeEscape(c)) {
        // Only whitespace is allowed after a Unicode character escape.
        return -1;
      }
    }
    if (c == '\r') {
      st.escapeNewline = true;
      st.escape = false;
      return 1;
    }
    // Newline is allowed escaped in a string.
    // Directly escaped character
    st.escape = false;
    return 1;
  }

  /**
   * Validates a quoted CSS string literal.
   *
   * <p>The method requires matching single or double quotes around the token and then delegates to
   * {@link #isValidString(String)} for inner content validation.
   *
   * @param string candidate literal including surrounding quotes; never {@code null}.
   * @return {@code true} when quotes match and the inner content passes validation; {@code false}
   *     otherwise.
   */
  public static boolean isValidStringWithQuotes(String string) {
    if (string.length() < 2) return false;
    if ((string.charAt(0) == '\'' && string.charAt(string.length() - 1) == '\'')
        || (string.charAt(0) == '\"' && string.charAt(string.length() - 1) == '\"')) {
      string = string.substring(1, string.length() - 1);
      return isValidString(string);
    } else return false;
  }
}
