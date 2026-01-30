package network.crypta.client.filter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility helpers for validating and normalizing CSS-like values used by client-side filters.
 *
 * <p>This class focuses on syntactic checks for common value categories such as numbers, lengths,
 * angles, colors, transforms, media queries, and timing-related units. Each method returns a
 * boolean indicating whether the provided string conforms to a conservative interpretation of the
 * respective specification (CSS/SVG where relevant). No state is kept; all methods are pure and
 * thread-safe.
 *
 * <p>Typical usage is to call individual predicates prior to accepting or acting upon untrusted
 * input (for example, when parsing style attributes, filter expressions, or plugin-provided
 * configuration). These helpers deliberately avoid throwing and instead return {@code false} for
 * malformed inputs, including null references in most cases. Where a richer outcome is useful,
 * dedicated accessors are provided (for example, {@link #sanitizeURI} and {@link #isURI}).
 *
 * <p>Notable characteristics:
 *
 * <ul>
 *   <li>Parsing is locale-independent and based on standard Java number parsing.
 *   <li>For CSS lengths, a curated set of absolute and relative units is recognized. SVG-specific
 *       rules are opt-in via parameters.
 *   <li>Color validation supports legacy and modern syntaxes, including hexadecimal and functional
 *       notations.
 * </ul>
 */
public class FilterUtils {
  private static final Logger LOG = LoggerFactory.getLogger(FilterUtils.class);

  private FilterUtils() {}

  private static final int MAX_NTH =
      999999; // Limit range of numbers allowed in isNth, due to incorrect behavior found in webkit

  // based browsers.

  // Basic Data types
  /**
   * Determines whether the supplied text represents a base-10 integer.
   *
   * <p>This check delegates to {@link Integer#parseInt(String)} and reports success without
   * throwing. Leading {@code +} or {@code -} signs are accepted; embedded whitespace and
   * non-decimal digits are not. The method is intentionally strict: any parsing failure results in
   * {@code false}.
   *
   * @param strValue candidate integer text; not trimmed; null yields {@code false} without throwing
   * @return {@code true} when {@link Integer#parseInt(String)} succeeds; otherwise {@code false}
   */
  public static boolean isInteger(String strValue) {
    try {
      Integer.parseInt(strValue);
      return true;
    } catch (Exception _) {
      return false;
    }
  }

  /**
   * Tests whether the given string is a finite number in decimal form, optionally with an exponent.
   *
   * <p>The mantissa is parsed using {@link Double#parseDouble(String)} and, when an exponent
   * segment separated by {@code 'e'} or {@code 'E'} is present, the exponent must be an integer
   * (base 10). The method treats NaN and infinite values as invalid and never throws.
   *
   * @param strNumber textual representation of the number; not trimmed; null returns {@code false}
   * @return {@code true} when the decimal part parses and, if present, the exponent is an integer
   */
  public static boolean isNumber(String strNumber) {
    try {
      boolean containsE = false;
      String strDecimal;
      String strInteger = null;
      if (strNumber.indexOf('e') >= 0) {
        containsE = true;
        strDecimal = strNumber.substring(0, strNumber.indexOf('e'));
        // Intentionally derive exponent from original string to keep current behavior
        strInteger = strNumber.substring(strDecimal.indexOf('e') + 1);
      } else if (strNumber.indexOf('E') >= 0) {
        containsE = true;
        strDecimal = strNumber.substring(0, strNumber.indexOf('E'));
        // Intentionally derive exponent from original string to keep current behavior
        strInteger = strNumber.substring(strDecimal.indexOf('E') + 1);
      } else {
        strDecimal = strNumber;
      }
      Double.parseDouble(strDecimal);
      if (containsE) return isInteger(strInteger);
      else return true;
    } catch (Exception _) {
      return false;
    }
  }

  private static final HashSet<String> allowedUnits = new HashSet<>();

  static {
    // W3C CSS Spec Section 5 (http://www.w3.org/TR/css3-values/)
    // "Distance Units: the '<length>' type"
    allowedUnits.add("em");
    allowedUnits.add("ex");
    allowedUnits.add("ch");
    allowedUnits.add("rem");
    allowedUnits.add("cm");
    allowedUnits.add("mm");
    allowedUnits.add("in");
    allowedUnits.add("pt");
    allowedUnits.add("pc");
    allowedUnits.add("px");
    allowedUnits.add("vw");
    allowedUnits.add("vh");
    allowedUnits.add("vmin");
    allowedUnits.add("vmax");
  }

  /**
   * Verifies that a string represents a percentage value in the form {@code <number>%}.
   *
   * <p>Both integer and decimal percentages are accepted, including negative values. A trailing
   * percent sign is required, and the numeric portion is parsed using standard Java number
   * semantics.
   *
   * @param value text ending with {@code '%'}; leading/trailing whitespace is not ignored here
   * @return {@code true} if the substring before {@code '%'} is a valid integer or decimal number
   */
  public static boolean isPercentage(String value) {
    if (value.length() >= 2 && value.charAt(value.length() - 1) == '%') // Valid percentage X%
    {
      // Percentages are <number>%
      // That means they can be positive, negative, zero, >100%, and they can contain decimal
      // points.
      try {
        Integer.parseInt(value.substring(0, value.length() - 1));
        return true;
      } catch (Exception _) {
        // Ignore parse failure; fall through to double parsing
      }
      try {
        Double.parseDouble(value.substring(0, value.length() - 1));
        return true;
      } catch (Exception _) {
        // Ignore parse failure; not a valid percentage
      }
    }
    return false;
  }

  /**
   * Validates a CSS/SVG length value with optional unit.
   *
   * <p>The validator recognizes a curated set of CSS length units such as {@code px}, {@code em},
   * {@code rem}, {@code cm}, {@code mm}, {@code in}, {@code pt}, {@code pc}, and viewport units
   * like {@code vw}/{@code vh}/{@code vmin}/{@code vmax}. When {@code isSVG} is {@code true}, a
   * trailing {@code '%'} is also permitted. A unitless zero is valid even when a unit would
   * otherwise be required.
   *
   * @param value candidate length string to validate; surrounding whitespace is ignored
   * @param isSVG whether to apply SVG rules (permit {@code %} values in addition to CSS units)
   * @return {@code true} if the value parses as a finite number and any required unit is present
   */
  public static boolean isLength(String value, boolean isSVG) { // SVG lengths allow % values
    String v = value.trim();
    if (v.isEmpty()) return false;

    LenParts parts = parseLengthParts(v, isSVG);
    String lengthValue = parts.len;
    boolean units = parts.units;

    try {
      int x = Integer.parseInt(lengthValue);
      return units || isSVG || x == 0;
    } catch (Exception _) {
      // Ignore parse failure; try parsing as double below
    }

    try {
      double dval = Double.parseDouble(lengthValue);
      if (!units && !isSVG && dval != 0) return false;
      return !(Double.isInfinite(dval) || Double.isNaN(dval));
    } catch (Exception _) {
      // Ignore parse failure; not a valid length
    }
    return false;
  }

  private record LenParts(String len, boolean units) {}

  private static LenParts parseLengthParts(String v, boolean isSVG) {
    if (isSVG && v.charAt(v.length() - 1) == '%') {
      return new LenParts(v.substring(0, v.length() - 1), true);
    }
    int pos = 0;
    int len = v.length();
    for (int i = len - 1; i >= 0; i--) {
      char c = v.charAt(i);
      if ((c >= '0' && c <= '9') || c == '.') {
        pos = i + 1;
        break;
      }
    }
    if (len - pos > 0 && allowedUnits.contains(v.substring(pos))) {
      return new LenParts(v.substring(0, pos), true);
    }
    return new LenParts(v, false);
  }

  /**
   * Checks whether a value is an angle expressed in degrees, radians, or gradians.
   *
   * <p>Accepted forms are {@code <number>deg}, {@code <number>rad}, and {@code <number>grad}. The
   * numeric portion may be integer or decimal and may include a sign. Whitespace between the number
   * and unit is not allowed.
   *
   * @param value the candidate angle string, such as {@code "90deg"} or {@code "1.57rad"}
   * @return {@code true} if the string ends with a recognized unit and the prefix parses as a float
   */
  public static boolean isAngle(String value) {
    boolean isValid = true;
    int index = -1;
    if (value.contains("deg")) {
      index = value.indexOf("deg");
      String secondpart = value.substring(index).trim();
      if (!"deg".equals(secondpart)) isValid = false;
    } else if (value.contains("grad")) {
      index = value.indexOf("grad");
      String secondpart = value.substring(index).trim();

      if (!"grad".equals(secondpart)) isValid = false;
    } else if (value.contains("rad")) {
      index = value.indexOf("rad");
      String secondpart = value.substring(index).trim();

      if (!"rad".equals(secondpart)) isValid = false;
    }
    if (index != -1 && isValid) {
      String firstPart = value.substring(0, index);
      try {
        Float.parseFloat(firstPart);
        return true;
      } catch (Exception _) {
        // Ignore parse failure; not a valid angle
      }
    }
    return false;
  }

  private static final HashSet<String> SVGcolorKeywords = new HashSet<>();

  static {
    SVGcolorKeywords.add("aliceblue");
    SVGcolorKeywords.add("antiquewhite");
    SVGcolorKeywords.add("aqua");
    SVGcolorKeywords.add("aquamarine");
    SVGcolorKeywords.add("azure");
    SVGcolorKeywords.add("beige");
    SVGcolorKeywords.add("bisque");
    SVGcolorKeywords.add("black");
    SVGcolorKeywords.add("blanchedalmond");
    SVGcolorKeywords.add("blue");
    SVGcolorKeywords.add("blueviolet");
    SVGcolorKeywords.add("brown");
    SVGcolorKeywords.add("burlywood");
    SVGcolorKeywords.add("cadetblue");
    SVGcolorKeywords.add("chartreuse");
    SVGcolorKeywords.add("chocolate");
    SVGcolorKeywords.add("coral");
    SVGcolorKeywords.add("cornflowerblue");
    SVGcolorKeywords.add("cornsilk");
    SVGcolorKeywords.add("crimson");
    SVGcolorKeywords.add("cyan");
    SVGcolorKeywords.add("darkblue");
    SVGcolorKeywords.add("darkcyan");
    SVGcolorKeywords.add("darkgoldenrod");
    SVGcolorKeywords.add("darkgray");
    SVGcolorKeywords.add("darkgreen");
    SVGcolorKeywords.add("darkgrey");
    SVGcolorKeywords.add("darkkhaki");
    SVGcolorKeywords.add("darkmagenta");
    SVGcolorKeywords.add("darkolivegreen");
    SVGcolorKeywords.add("darkorange");
    SVGcolorKeywords.add("darkorchid");
    SVGcolorKeywords.add("darkred");
    SVGcolorKeywords.add("darksalmon");
    SVGcolorKeywords.add("darkseagreen");
    SVGcolorKeywords.add("darkslateblue");
    SVGcolorKeywords.add("darkslategray");
    SVGcolorKeywords.add("darkslategrey");
    SVGcolorKeywords.add("darkturquoise");
    SVGcolorKeywords.add("darkviolet");
    SVGcolorKeywords.add("deeppink");
    SVGcolorKeywords.add("deepskyblue");
    SVGcolorKeywords.add("dimgray");
    SVGcolorKeywords.add("dimgrey");
    SVGcolorKeywords.add("dodgerblue");
    SVGcolorKeywords.add("firebrick");
    SVGcolorKeywords.add("floralwhite");
    SVGcolorKeywords.add("forestgreen");
    SVGcolorKeywords.add("fuchsia");
    SVGcolorKeywords.add("gainsboro");
    SVGcolorKeywords.add("ghostwhite");
    SVGcolorKeywords.add("gold");
    SVGcolorKeywords.add("goldenrod");
    SVGcolorKeywords.add("gray");
    SVGcolorKeywords.add("grey");
    SVGcolorKeywords.add("green");
    SVGcolorKeywords.add("greenyellow");
    SVGcolorKeywords.add("honeydew");
    SVGcolorKeywords.add("hotpink");
    SVGcolorKeywords.add("indianred");
    SVGcolorKeywords.add("indigo");
    SVGcolorKeywords.add("ivory");
    SVGcolorKeywords.add("khaki");
    SVGcolorKeywords.add("lavender");
    SVGcolorKeywords.add("lavenderblush");
    SVGcolorKeywords.add("lawngreen");
    SVGcolorKeywords.add("lemonchiffon");
    SVGcolorKeywords.add("lightblue");
    SVGcolorKeywords.add("lightcoral");
    SVGcolorKeywords.add("lightcyan");
    SVGcolorKeywords.add("lightgoldenrodyellow");
    SVGcolorKeywords.add("lightgray");
    SVGcolorKeywords.add("lightgreen");
    SVGcolorKeywords.add("lightgrey");
    SVGcolorKeywords.add("lightpink");
    SVGcolorKeywords.add("lightsalmon");
    SVGcolorKeywords.add("lightseagreen");
    SVGcolorKeywords.add("lightskyblue");
    SVGcolorKeywords.add("lightslategray");
    SVGcolorKeywords.add("lightslategrey");
    SVGcolorKeywords.add("lightsteelblue");
    SVGcolorKeywords.add("lightyellow");
    SVGcolorKeywords.add("lime");
    SVGcolorKeywords.add("limegreen");
    SVGcolorKeywords.add("linen");
    SVGcolorKeywords.add("magenta");
    SVGcolorKeywords.add("maroon");
    SVGcolorKeywords.add("mediumaquamarine");
    SVGcolorKeywords.add("mediumblue");
    SVGcolorKeywords.add("mediumorchid");
    SVGcolorKeywords.add("thistle");
    SVGcolorKeywords.add("tomato");
    SVGcolorKeywords.add("turquoise");
    SVGcolorKeywords.add("violet");
    SVGcolorKeywords.add("wheat");
    SVGcolorKeywords.add("white");
    SVGcolorKeywords.add("whitesmoke");
    SVGcolorKeywords.add("yellow");
    SVGcolorKeywords.add("yellowgreen");
    SVGcolorKeywords.add("rebeccapurple"); // CSS Colors Level 4: #663399
  }

  private static final HashSet<String> CSScolorKeywords = new HashSet<>();

  static {
    CSScolorKeywords.add("aqua");
    CSScolorKeywords.add("black");
    CSScolorKeywords.add("blue");
    CSScolorKeywords.add("fuchsia");
    CSScolorKeywords.add("gray");
    CSScolorKeywords.add("green");
    CSScolorKeywords.add("lime");
    CSScolorKeywords.add("maroon");
    CSScolorKeywords.add("navy");
    CSScolorKeywords.add("olive");
    CSScolorKeywords.add("orange");
    CSScolorKeywords.add("purple");
    CSScolorKeywords.add("red");
    CSScolorKeywords.add("silver");
    CSScolorKeywords.add("teal");
    CSScolorKeywords.add("white");
    CSScolorKeywords.add("yellow");
    // as of CSS3 this is valid: http://www.w3.org/TR/css3-color/#transparent-def
    CSScolorKeywords.add("transparent");
  }

  private static final HashSet<String> CSSsystemColorKeywords = new HashSet<>();

  static {
    CSSsystemColorKeywords.add("activeborder");
    CSSsystemColorKeywords.add("activecaption");
    CSSsystemColorKeywords.add("appworkspace");
    CSSsystemColorKeywords.add("background");
    CSSsystemColorKeywords.add("buttonface");
    CSSsystemColorKeywords.add("buttonhighlight");
    CSSsystemColorKeywords.add("buttonshadow");
    CSSsystemColorKeywords.add("buttontext");
    CSSsystemColorKeywords.add("captiontext");
    CSSsystemColorKeywords.add("graytext");
    CSSsystemColorKeywords.add("highlight");
    CSSsystemColorKeywords.add("highlighttext");
    CSSsystemColorKeywords.add("inactiveborder");
    CSSsystemColorKeywords.add("inactivecaption");
    CSSsystemColorKeywords.add("inactivecaptiontext");
    CSSsystemColorKeywords.add("infobackground");
    CSSsystemColorKeywords.add("infotext");
    CSSsystemColorKeywords.add("menu");
    CSSsystemColorKeywords.add("menutext");
    CSSsystemColorKeywords.add("scrollbar");
    CSSsystemColorKeywords.add("threeddarkshadow");
    CSSsystemColorKeywords.add("threedface");
    CSSsystemColorKeywords.add("threedhighlight");
    CSSsystemColorKeywords.add("threedlightshadow");
    CSSsystemColorKeywords.add("threedshadow");
    CSSsystemColorKeywords.add("window");
    CSSsystemColorKeywords.add("windowframe");
    CSSsystemColorKeywords.add("windowtext");
  }

  /**
   * Determines whether a value represents a valid {@code rect()} CSS shape.
   *
   * <p>The accepted form is {@code rect(t, r, b, l)} where each component is either an
   * absolute/relative length (as validated by {@link #isLength(String, boolean)}) or the
   * case-insensitive literal {@code auto}. Components are comma-separated and the closing
   * parenthesis must be present.
   *
   * @param value string starting with {@code rect(} and ending with {@code )}; not trimmed here
   * @return {@code true} when the syntax is {@code rect(...)} with four valid components
   */
  public static boolean isValidCSSShape(String value) {
    if (value.indexOf("rect(") == 0 && value.indexOf(')') == value.length() - 1) {
      String[] shapeParts = splitOnCharArray(value.substring(5, value.length() - 1), ",");
      if (shapeParts.length == 4) {
        for (String s : shapeParts) {
          s = s.trim();
          if (!(s.equalsIgnoreCase("auto") || isLength(s, false))) return false;
        }
        return true;
      }
    }
    return false;
  }

  private static final HashSet<String> cssMedia = new HashSet<>();

  static {
    cssMedia.addAll(
        Arrays.asList(
            "all",
            "aural",
            "braille",
            "embossed",
            "handheld",
            "print",
            "projection",
            "screen",
            "speech",
            "tty",
            "tv"));
  }

  /**
   * Returns {@code true} if the media token is recognized.
   *
   * <p>Recognized values include standard CSS media types such as {@code screen}, {@code print},
   * {@code speech}, and {@code all}. The comparison is case-sensitive in this implementation.
   *
   * @param media the media token to validate; use lower-case canonical tokens for best results
   * @return {@code true} when the token exists in the supported media set; otherwise {@code false}
   */
  public static boolean isMedia(String media) {
    return cssMedia.contains(media);
  }

  /**
   * Regular expression that matches hexadecimal color literals.
   *
   * <p>The pattern accepts the following forms (case-insensitive): {@code #RGB}, {@code #RGBA},
   * {@code #RRGGBB}, and {@code #RRGGBBAA}. The alpha channel, when present, appears as the last
   * component. Callers can use this pattern directly for additional matching requirements or rely
   * on {@link #isColor(String)} for higher-level checks.
   */
  public static final Pattern hexColorPattern =
      Pattern.compile("#(?>[0-9a-f]{8}|[0-9a-f]{6}|[0-9a-f]{3,4})", Pattern.CASE_INSENSITIVE);

  /**
   * Validates whether a string represents a color using CSS/SVG notations.
   *
   * <p>Supported categories include: named CSS/SVG keywords (e.g., {@code red}, {@code
   * transparent}), hexadecimal forms matched by {@link #hexColorPattern}, and functional forms such
   * as {@code rgb(...)}, {@code rgba(...)}, {@code hsl(...)}, and {@code hsla(...)}. For RGB, both
   * legacy comma-separated and modern space-separated syntaxes are recognized.
   *
   * @param value color candidate; surrounding whitespace is ignored; matching is case-insensitive
   * @return {@code true} if the value matches any supported color notation; otherwise {@code false}
   */
  public static boolean isColor(String value) {
    String v = value.trim().toLowerCase(Locale.ROOT);

    if (CSScolorKeywords.contains(v)
        || CSSsystemColorKeywords.contains(v)
        || SVGcolorKeywords.contains(v)) return true;

    if (v.indexOf('#') == 0) {
      return hexColorPattern.matcher(v).matches();
    }

    if ((v.startsWith("rgb(") || v.startsWith("rgba(")) && v.indexOf(')') == v.length() - 1) {
      return isColorRgb(v);
    }

    return isColorHsl(v) || isColorHsla(v);
  }

  private static boolean isColorHsl(String v) {
    if (v.indexOf("hsl(") != 0 || v.indexOf(')') != v.length() - 1) return false;
    String[] colorParts = splitOnCharArray(v.substring(4, v.length() - 1), ",");
    if (colorParts.length != 3) return false;
    return isNumber(colorParts[0]) && isPercentage(colorParts[1]) && isPercentage(colorParts[2]);
  }

  private static boolean isColorHsla(String v) {
    if (v.indexOf("hsla(") != 0 || v.indexOf(')') != v.length() - 1) return false;
    String[] colorParts = splitOnCharArray(v.substring(5, v.length() - 1), ",");
    if (colorParts.length != 4) return false;
    return isNumber(colorParts[0])
        && isPercentage(colorParts[1])
        && isPercentage(colorParts[2])
        && isNumber(colorParts[3]);
  }

  private static boolean isColorRgb(String value) {
    return value.contains(",") ? isColorRgbLegacy(value) : isColorRgbModern(value);
  }

  private static boolean isColorRgbLegacy(String v) {
    String[] colorParts = splitOnCharArray(v.substring(v.indexOf("(") + 1, v.length() - 1), ",");
    if (colorParts.length != 3 && colorParts.length != 4) return false;
    for (int i = 0; i < 3; i++) {
      if (!(isPercentage(colorParts[i].trim()) || isInteger(colorParts[i].trim()))) return false;
    }
    return colorParts.length == 3 || isNumber(colorParts[3]);
  }

  private static boolean isColorRgbModern(String vIn) {
    String v = vIn;
    if (v.contains("/")) {
      // Modern format rgba(r g b / a)
      String alphaPart = v.substring(v.indexOf("/") + 1, v.length() - 1).trim();
      if (!alphaPart.isEmpty()
          && !isPercentage(alphaPart)
          && !isNumber(alphaPart)
          && !alphaPart.equalsIgnoreCase("none")) return false;
      v = v.substring(0, v.indexOf("/")) + ")"; // Strip alpha value
    }
    // Modern format rgba(r g b)
    String[] colorParts = splitOnCharArray(v.substring(v.indexOf("(") + 1, v.length() - 1), " ");
    if (colorParts.length != 3) return false;
    for (int i = 0; i < 3; i++) {
      String trimmed = colorParts[i].trim();
      if (!(trimmed.equalsIgnoreCase("none")
          || isPercentage(trimmed)
          || (isInteger(trimmed) && isIntegerInRange(trimmed, 0, 255)))) return false;
    }
    return true;
  }

  /**
   * Tests whether a value is a valid single CSS transform function.
   *
   * <p>Recognized functions include {@code matrix()}, {@code translate()}, {@code translateX()},
   * {@code translateY()}, {@code scale()}, {@code scaleX()}, {@code scaleY()}, {@code rotate()},
   * {@code skew()}, {@code skewX()}, and {@code skewY()}. The method validates argument counts and
   * basic numeric/unit constraints but does not evaluate semantics beyond syntax.
   *
   * @param value the transform function string to test; leading/trailing spaces are ignored
   * @return {@code true} when the syntax matches one of the supported transform functions
   */
  public static boolean isCSSTransform(String value) {
    String v = value.trim();
    if (LOG.isTraceEnabled()) LOG.trace("isCSSTransform(\"{}\")", v);

    return isTransformMatrix(v)
        || isTransformTranslateX(v)
        || isTransformTranslateY(v)
        || isTransformTranslate(v)
        || isTransformScale(v)
        || isTransformScaleX(v)
        || isTransformScaleY(v)
        || isTransformRotate(v)
        || isTransformSkewX(v)
        || isTransformSkewY(v)
        || isTransformSkew(v);
  }

  private static boolean isTransformMatrix(String v) {
    if (v.indexOf("matrix(") == 0 && v.indexOf(')') == v.length() - 1) {
      String[] parts = splitOnCharArray(v.substring(7, v.length() - 1), ",");
      if (parts.length != 6) return false;
      for (String part : parts) if (!isNumber(part.trim())) return false;
      if (LOG.isTraceEnabled()) LOG.trace("isCSSTransform found a matrix()");
      return true;
    }
    return false;
  }

  private static boolean isTransformTranslateX(String v) {
    if (v.indexOf("translateX(") == 0 && v.indexOf(')') == v.length() - 1) {
      String part = v.substring(11, v.length() - 1);
      if (isPercentage(part.trim()) || isLength(part.trim(), false)) {
        if (LOG.isTraceEnabled()) LOG.trace("isCSSTransform found a translateX()");
        return true;
      }
    }
    return false;
  }

  private static boolean isTransformTranslateY(String v) {
    if (v.indexOf("translateY(") == 0 && v.indexOf(')') == v.length() - 1) {
      String part = v.substring(11, v.length() - 1);
      if (isPercentage(part.trim()) || isLength(part.trim(), false)) {
        if (LOG.isTraceEnabled()) LOG.trace("isCSSTransform found a translateY()");
        return true;
      }
    }
    return false;
  }

  private static boolean isTransformTranslate(String v) {
    if (v.indexOf("translate(") == 0 && v.indexOf(')') == v.length() - 1) {
      String[] parts = splitOnCharArray(v.substring(10, v.length() - 1), ",");
      boolean valid =
          (parts.length == 1 && (isPercentage(parts[0].trim()) || isLength(parts[0].trim(), false)))
              || (parts.length == 2
                  && (isPercentage(parts[0].trim()) || isLength(parts[0].trim(), false))
                  && (isPercentage(parts[1].trim()) || isLength(parts[1].trim(), false)));
      if (valid) {
        if (LOG.isTraceEnabled()) LOG.trace("isCSSTransform found a translate()");
        return true;
      }
    }
    return false;
  }

  private static boolean isTransformScale(String v) {
    if (v.indexOf("scale(") == 0 && v.indexOf(')') == v.length() - 1) {
      String[] parts = splitOnCharArray(v.substring(6, v.length() - 1), ",");
      boolean valid =
          (parts.length == 1 && isNumber(parts[0].trim()))
              || (parts.length == 2 && isNumber(parts[0].trim()) && isNumber(parts[1].trim()));
      if (valid) {
        if (LOG.isTraceEnabled()) LOG.trace("isCSSTransform found a scale()");
        return true;
      }
    }
    return false;
  }

  private static boolean isTransformScaleX(String v) {
    if (v.indexOf("scaleX(") == 0 && v.indexOf(')') == v.length() - 1) {
      String part = v.substring(7, v.length() - 1);
      if (isNumber(part.trim())) {
        if (LOG.isTraceEnabled()) LOG.trace("isCSSTransform found a scaleX()");
        return true;
      }
    }
    return false;
  }

  private static boolean isTransformScaleY(String v) {
    if (v.indexOf("scaleY(") == 0 && v.indexOf(')') == v.length() - 1) {
      String part = v.substring(7, v.length() - 1);
      if (isNumber(part.trim())) {
        if (LOG.isTraceEnabled()) LOG.trace("isCSSTransform found a scaleY()");
        return true;
      }
    }
    return false;
  }

  private static boolean isTransformRotate(String v) {
    if (v.indexOf("rotate(") == 0 && v.indexOf(')') == v.length() - 1) {
      String part = v.substring(7, v.length() - 1);
      if (isAngle(part.trim())) {
        if (LOG.isTraceEnabled()) LOG.trace("isCSSTransform found a rotate()");
        return true;
      }
    }
    return false;
  }

  private static boolean isTransformSkewX(String v) {
    if (v.indexOf("skewX(") == 0 && v.indexOf(')') == v.length() - 1) {
      String part = v.substring(6, v.length() - 1);
      if (isNumber(part.trim()) || isAngle(part.trim())) {
        if (LOG.isTraceEnabled()) LOG.trace("isCSSTransform found a skewX()");
        return true;
      }
    }
    return false;
  }

  private static boolean isTransformSkewY(String v) {
    if (v.indexOf("skewY(") == 0 && v.indexOf(')') == v.length() - 1) {
      String part = v.substring(6, v.length() - 1);
      if (isNumber(part.trim()) || isAngle(part.trim())) {
        if (LOG.isTraceEnabled()) LOG.trace("isCSSTransform found a skewY()");
        return true;
      }
    }
    return false;
  }

  private static boolean isTransformSkew(String v) {
    if (v.indexOf("skew(") == 0 && v.indexOf(')') == v.length() - 1) {
      String[] parts = splitOnCharArray(v.substring(5, v.length() - 1), ",");
      boolean valid =
          (parts.length == 1 && (isNumber(parts[0].trim()) || isAngle(parts[0].trim())))
              || (parts.length == 2
                  && (isNumber(parts[0].trim()) || isAngle(parts[0].trim()))
                  && (isNumber(parts[1].trim()) || isAngle(parts[0].trim())));
      if (valid) {
        if (LOG.isTraceEnabled()) LOG.trace("isCSSTransform found a skew()");
        return true;
      }
    }
    return false;
  }

  /**
   * Validates a frequency value expressed in hertz.
   *
   * <p>Accepted spellings are {@code <number>hz} and {@code <number>khz}; units are
   * case-insensitive in this implementation. A unitless positive number is also accepted for
   * compatibility. Values must parse as a positive {@code float}; zero and negative values are
   * rejected.
   *
   * @param value candidate frequency, for example {@code "440hz"} or {@code "1.5kHz"}
   * @return {@code true} if a positive number is present with an optional Hz/kHz suffix
   */
  public static boolean isFrequency(String value) {
    String firstPart;
    value = value.trim().toLowerCase(Locale.ROOT);
    boolean isValidFrequency = true;
    if (value.contains("khz")) {
      int index = value.indexOf("khz");
      firstPart = value.substring(0, index).trim();
      if (!"khz".equals(value.substring(index).trim())) {
        isValidFrequency = false;
      }

    } else if (value.contains("hz")) {
      int index = value.indexOf("hz");
      firstPart = value.substring(0, index).trim();
      if (!"hz".equals(value.substring(index).trim())) {
        isValidFrequency = false;
      }

    } else firstPart = value.trim();
    if (isValidFrequency) {
      try {
        float temp = Float.parseFloat(firstPart);
        if (temp > 0) return true;
      } catch (Exception _) {
        // Ignore parse failure; not a valid frequency
      }
    }
    return false;
  }

  /**
   * Checks whether a time duration is expressed in seconds or milliseconds.
   *
   * <p>Accepted forms are {@code <number>s} and {@code <number>ms}. Both integer and decimal
   * numbers are supported; the value is validated using {@link #isNumber(String)}. Negative
   * durations are allowed if the numeric check permits them.
   *
   * @param value candidate duration ending in {@code s} or {@code ms}; case-insensitive
   * @return {@code true} if a numeric value followed by a supported unit is present
   */
  public static boolean isTime(String value) {
    value = value.toLowerCase(Locale.ROOT);
    String intValue;
    if (value.contains("ms") && value.length() > 2)
      intValue = value.substring(0, value.length() - 2);
    else if (value.indexOf('s') > -1 && value.length() > 1)
      intValue = value.substring(0, value.length() - 1);
    else return false;
    return isNumber(intValue);
  }

  /**
   * Trims and filters an array of strings, optionally removing outer quotes.
   *
   * <p>Each element is {@code trim()}-med; when {@code stripQuotes} is {@code true}, matching outer
   * single or double quotes are removed prior to trimming again. Empty results are dropped. A
   * {@code null} input array is returned as {@code null} to preserve the caller contract.
   *
   * @param values input array to clean; may be {@code null}; entries may include extra whitespace
   * @param stripQuotes when {@code true}, remove matching outer quotes before final trimming
   * @return a newly allocated array containing only non-empty cleaned elements, in original order
   */
  @SuppressWarnings("java:S1168")
  public static String[] removeWhiteSpace(String[] values, boolean stripQuotes) {
    if (values == null) return null; // Preserve API contract expected by callers/tests
    ArrayList<String> arrayToReturn = new ArrayList<>();
    for (String value : values) {
      value = value.trim();
      if (stripQuotes) value = CSSTokenizerFilter.removeOuterQuotes(value).trim();
      if (!value.trim().isEmpty()) arrayToReturn.add(value);
    }
    return arrayToReturn.toArray(new String[0]);
  }

  /**
   * Invokes the provided callback to sanitize a URI and converts failures to an empty string.
   *
   * <p>The callback receives the raw {@code uri} and a {@code null} context object to preserve
   * existing behavior. If the callback throws or returns {@code null}, this method returns an empty
   * string. Use together with {@link #isURI} when only accept-or-reject semantics are required.
   *
   * @param cb the callback responsible for canonicalizing/sanitizing the URI input
   * @param uri the original URI string to process; may be any user-provided value
   * @return the sanitized URI on success; otherwise an empty string to signal rejection/failure
   */
  public static String sanitizeURI(FilterCallback cb, String uri) {
    try {
      return cb.processURI(uri, null);
    } catch (Exception _) {
      return "";
    }
  }

  /**
   * Determines whether a URI string is accepted by the sanitizer without modification.
   *
   * <p>The method sanitizes {@code uri} via {@link #sanitizeURI} and compares the result to the
   * input using {@link String#equals(Object)}. If they are identical, the URI is considered valid
   * and unchanged; otherwise it is rejected or would be rewritten.
   *
   * @param cb the callback applied to sanitize the URI according to application policy
   * @param uri the candidate URI string for validation against the sanitizer
   * @return {@code true} when the sanitizer returns the same string instance content as provided
   */
  public static boolean isURI(FilterCallback cb, String uri) {
    return uri.equals(sanitizeURI(cb, uri));
  }

  /**
   * Splits a string by any character present in a delimiter set, collapsing consecutive delimiters.
   *
   * <p>Delimiters are not returned. Runs of delimiter characters produce no empty tokens because
   * consecutive delimiters are treated as a single boundary. The original ordering is preserved.
   *
   * @param value the source text to split; not {@code null}; no trimming is performed
   * @param splitOn string containing all delimiter characters to consider during splitting
   * @return an array of non-empty tokens in encounter order; may be empty but never {@code null}
   */
  public static String[] splitOnCharArray(String value, String splitOn) {
    ArrayList<String> pointPairs = new ArrayList<>();
    // Creating HashMap for faster search operation
    int i;
    int prev = 0;
    for (i = 0; i < value.length(); i++) {
      if (splitOn.indexOf(value.charAt(i)) != -1) {
        pointPairs.add(value.substring(prev, i));
        while (i < value.length() && splitOn.indexOf(value.charAt(i)) != -1) {
          i++;
        }
        prev = i;
        i--;
      }
    }
    boolean isLastElement = false;
    for (i = prev; i < value.length(); i++) {
      if (splitOn.indexOf(value.charAt(i)) == -1) {
        isLastElement = true;
        break;
      }
    }
    if (isLastElement) {
      pointPairs.add(value.substring(prev));
    }
    return pointPairs.toArray(new String[0]);
  }

  /**
   * Validates a sequence of point pairs in the form {@code x,y} separated by whitespace.
   *
   * <p>Each pair must contain exactly two floating-point numbers separated by a comma. The method
   * accepts multiple pairs separated by spaces, tabs, or newlines and returns {@code true} only if
   * every pair parses successfully.
   *
   * @param value the text containing one or more comma-separated coordinate pairs
   * @return {@code true} when all tokens follow the {@code x,y} floating-point pattern
   */
  public static boolean isPointPair(String value) {
    String[] pointPairs = splitOnCharArray(value, " \n\t");
    for (String pointPair : pointPairs) {
      String[] strParts = splitOnCharArray(pointPair, ",");
      if (strParts.length != 2) return false;
      try {
        Float.parseFloat(strParts[0]);
        Float.parseFloat(strParts[1]);
      } catch (Exception _) {
        return false;
      }
    }
    return true;
  }

  /**
   * Tests whether a string parses as an integer within an inclusive range.
   *
   * <p>Leading {@code +} is permitted and removed for compatibility with differences between
   * historical Java versions. The range check is inclusive at both ends. Parsing failures and
   * values outside the range return {@code false}.
   *
   * @param strValue the integer string to parse; a leading {@code +} sign is tolerated
   * @param min the inclusive minimum allowed value; no constraint is placed on relation to {@code
   *     max}
   * @param max the inclusive maximum allowed value; effective only when parsing succeeds
   * @return {@code true} if parsed successfully and the value lies between {@code min} and {@code
   *     max}
   */
  public static boolean isIntegerInRange(String strValue, int min, int max) {
    try {
      // Strip any leading '+' character, because Integer.parseInt handles it differently between
      // Java 6 (fails) and 7 (succeeds).
      if (strValue.length() > 1
          && strValue.charAt(0) == '+'
          && Character.isDigit(strValue.charAt(1))) {
        strValue = strValue.substring(1);
      }

      int value = Integer.parseInt(strValue);
      return (value >= min && value <= max);
    } catch (Exception _) {
      return false;
    }
  }

  /**
   * Validates an {@code nth-} expression compatible with CSS selectors (e.g., {@code :nth-child}).
   *
   * <p>Accepted forms include the literals {@code odd} and {@code even}, a bounded integer in the
   * inclusive range {@code [-999999, 999999]}, or the linear expression {@code an+b} where both
   * coefficients are integers within the same bounds. No whitespace is allowed within the token.
   *
   * @param value the input token to validate, for example {@code "2n+1"}, {@code "odd"}, or {@code
   *     "4"}
   * @return {@code true} if the token matches any of the supported {@code nth-} formats
   */
  public static boolean isNth(String value) {
    if (value.equals("odd") || value.equals("even") || isIntegerInRange(value, -MAX_NTH, MAX_NTH)) {
      return true;
    } else {
      // Check if value has the form "an+b" - where a and b can be any in range integer.
      int nIndex = value.indexOf('n');
      if (nIndex != -1
          && (nIndex == 0
              || (nIndex == 1 && value.charAt(0) == '-')
              || isIntegerInRange(value.substring(0, nIndex), -MAX_NTH, MAX_NTH))) {
        int bIndex = nIndex + 1;
        int bLength = value.length() - bIndex;
        return bLength == 0
            || ((value.charAt(bIndex) == '+' || value.charAt(bIndex) == '-')
                && isIntegerInRange(value.substring(bIndex), -MAX_NTH, MAX_NTH));
      }
    }
    return false;
  }
}
