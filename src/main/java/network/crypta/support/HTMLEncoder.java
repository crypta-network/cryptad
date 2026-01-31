package network.crypta.support;

import java.util.Map;

/**
 * HTML encoder utilities.
 *
 * <p>Provides helpers to encode text for safe inclusion in HTML or XML contexts. The main entry is
 * {@link #encode(String)}, which replaces characters according to {@link HTMLEntities#encodeMap}
 * with their corresponding named (or numeric) HTML entity, while deliberately leaving ASCII letters
 * and decimal digits unchanged so that readable text is preserved.
 *
 * <p>For XML-specific escaping, {@link #encodeXML(String)} emits numeric character references for
 * the minimal set of XML-special characters ({@code &}, {@code "}, {@code '}, {@code <}, {@code
 * >}).
 *
 * <p>Thread-safety: this class is stateless and all data used for encoding is immutable after
 * initialization; all methods are safe for concurrent use.
 *
 * <p>Complexity: linear in the length of the input {@code O(n)} for all public methods.
 *
 * <p>Notes:
 *
 * <ul>
 *   <li>The exact set of characters encoded by {@link #encode(String)} is determined by {@link
 *       HTMLEntities#encodeMap}. ASCII letters/digits are never encoded even if the map contains
 *       entries for them; this is intentional for readability and compatibility.
 *   <li>Methods in this class do not accept {@code null} arguments and will throw {@link
 *       NullPointerException} from underlying JDK calls if invoked with {@code null}.
 * </ul>
 *
 * <p>Originally derived from the {@code com.websiteasp.ox} package.
 *
 * @author avian (Yves Lempereur)
 * @author Unique Person@w3nO30p4p9L81xKTXbCaQBOvUww (via Frost)
 */
public class HTMLEncoder {
  private static final CharTable charTable = new CharTable(HTMLEntities.encodeMap);

  private HTMLEncoder() {}

  /**
   * Encode a string for safe inclusion in HTML.
   *
   * <p>Characters that have entries in {@link HTMLEntities#encodeMap} are replaced by {@literal
   * &name;} (or numeric) entity references, except that ASCII letters and decimal digits are always
   * left unchanged. Characters without a mapping are appended verbatim.
   *
   * @param s non-{@code null} input string
   * @return encoded string suitable for use as HTML text or attribute value
   * @throws NullPointerException if {@code s} is {@code null}
   */
  @SuppressWarnings("EscapedEntity")
  public static String encode(String s) {
    int n = s.length();
    StringBuilder sb = new StringBuilder(n);
    encodeToBuffer(n, s, sb);
    return sb.toString();
  }

  /**
   * Encode a string and append the result to the provided buffer.
   *
   * <p>Semantics are identical to {@link #encode(String)} but the output is appended to {@code sb}.
   * This is useful when building larger strings efficiently.
   *
   * @param s non-{@code null} input string
   * @param sb non-{@code null} destination buffer which will receive the encoded characters
   * @throws NullPointerException if either argument is {@code null}
   */
  public static void encodeToBuffer(String s, StringBuilder sb) {
    encodeToBuffer(s.length(), s, sb);
  }

  /**
   * Internal encoding loop shared by public entry points.
   *
   * <p>Encodes the first {@code n} characters of {@code s} into {@code sb}. Keeps the hot path in a
   * single method to help JIT inlining.
   */
  private static void encodeToBuffer(int n, String s, StringBuilder sb) {
    for (int i = 0; i < n; i++) {
      char c = s.charAt(i);
      String entity;
      if (Character.isLetterOrDigit(c)) { // only special characters need checking
        sb.append(c);
      } else if ((entity = charTable.get(c)) != null) {
        sb.append('&');
        sb.append(entity);
        sb.append(';');
      } else {
        sb.append(c);
      }
    }
  }

  /**
   * Encode a string so it is safe for XML attribute values and text nodes.
   *
   * <p>This routine emits numeric character references for the minimal set of XML-special
   * characters: {@literal &} ({@literal &#38;}), {@literal "} ({@literal &#34;}), {@literal '}
   * ({@literal &#39;}), {@literal <} ({@literal &#60;}), and {@literal >} ({@literal &#62;}). It
   * does not perform the broader HTML entity substitution that {@link #encode(String)} performs.
   *
   * <p>References:
   *
   * <ul>
   *   <li>XML 1.0, production <em>AttValue</em> and <em>CharData</em>
   * </ul>
   *
   * @param s non-{@code null} input string
   * @return XML-safe string using numeric character references
   * @throws NullPointerException if {@code s} is {@code null}
   */
  @SuppressWarnings("EscapedEntity")
  public static String encodeXML(String s) {
    // XML grammar requires quoting of these characters in attribute values and text. We use
    // numeric references to avoid dependencies on entity declarations.
    s = s.replace("&", "&#38;");

    s = s.replace("\"", "&#34;");
    s = s.replace("'", "&#39;");

    s = s.replace("<", "&#60;");
    s = s.replace(">", "&#62;"); // CharData can't contain ']]>'

    return s;
  }

  /**
   * Compact, fixed-size hash table for character-to-entity lookups.
   *
   * <p>Built from {@link HTMLEntities#encodeMap} at class initialization time. Not part of the
   * public API; kept small and allocation-free in the hot path.
   */
  private static final class CharTable {
    private final char[] chars;
    private final String[] strings;
    private int modulo;

    public CharTable(Map<Character, String> map) {
      int[] keys = new int[map.size()];
      int keyIndex = 0;

      int max = 0;
      for (Character key : map.keySet()) {
        int val = key;
        keys[keyIndex++] = val;
        if (val > max) max = val;
      }

      modulo = map.size();
      // Use an integer-marked collision table (rather than booleans) so we can reuse the same
      // array while probing increasing moduli without clearing it between attempts.
      int[] collisionTable = new int[max + 1];
      boolean ok = false;
      while (!ok) {
        ++modulo; // try a higher modulo
        ok = true;
        for (int i = 0; ok && i < keys.length; ++i) {
          keyIndex = keys[i] % modulo; // try this modulo
          if (collisionTable[keyIndex] == modulo) { // this slot is already used for this modulo
            ok = false;
          } else {
            collisionTable[keyIndex] = modulo;
          }
        }
      }
      // At this point, each key maps to a unique slot with the chosen modulo.

      chars = new char[modulo];
      strings = new String[modulo];
      for (Map.Entry<Character, String> entry : map.entrySet()) {
        Character character = entry.getKey();
        keyIndex = character % modulo;
        chars[keyIndex] = character;
        strings[keyIndex] = entry.getValue();
      }
      // Avoid a false positive match for key 0 caused by the default zero value in {@code chars}.
      if (chars[0] == 0 && strings[0] != null) chars[0] = 1;
    }

    public String get(char key) {
      return chars[key % modulo] == key ? strings[key % modulo] : null;
    }
  }
}
