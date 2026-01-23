package network.crypta.support;

import java.util.Map;

/**
 * Description: Utility for converting character references e.g.: &lt; &gt; &quot; &#229; &#1048;
 * &#x6C34;
 *
 * @author Yves Lempereur (avian)
 */
public class HTMLDecoder {

  private static final Map<String, Character> charTable = HTMLEntities.decodeMap;

  public static String decode(String s) {
    int maxPos = s.length();
    StringBuilder sb = new StringBuilder(maxPos);
    int curPos = 0;
    while (curPos < maxPos) {
      char c = s.charAt(curPos++);
      if (c == '&') {
        DecodeResult res = decodeAfterAmp(s, curPos, maxPos);
        if (res.decoded) {
          c = res.ch;
          curPos = res.nextPos;
        }
      }
      sb.append(c);
    }
    return sb.toString();
  }

  private record DecodeResult(boolean decoded, char ch, int nextPos) {}

  private static DecodeResult decodeAfterAmp(String s, int curPos, int maxPos) {
    int tmpPos = curPos;
    if (tmpPos >= maxPos) {
      return new DecodeResult(false, '&', curPos);
    }
    char d = s.charAt(tmpPos++);
    if (d == '#') {
      return decodeNumericEntity(s, tmpPos, maxPos, curPos);
    } else if (isLetter(d)) {
      return decodeNamedEntity(s, tmpPos, maxPos, curPos);
    }
    return new DecodeResult(false, '&', curPos);
  }

  private static DecodeResult decodeNumericEntity(String s, int tmpPos, int maxPos, int curPos) {
    if (tmpPos >= maxPos) {
      return new DecodeResult(false, '&', curPos);
    }
    char d = s.charAt(tmpPos++);
    if ((d == 'x') || (d == 'X')) {
      return decodeHexEntity(s, tmpPos, maxPos, curPos);
    } else if (isDigit(d)) {
      return decodeDecEntity(s, tmpPos, maxPos, curPos);
    }
    return new DecodeResult(false, '&', curPos);
  }

  private static DecodeResult decodeHexEntity(String s, int tmpPos, int maxPos, int curPos) {
    if (tmpPos >= maxPos) {
      return new DecodeResult(false, '&', curPos);
    }
    char d = s.charAt(tmpPos++);
    if (isHexDigit(d)) {
      return scanHexEntity(s, tmpPos, maxPos, curPos);
    }
    return new DecodeResult(false, '&', curPos);
  }

  private static DecodeResult scanHexEntity(String s, int tmpPos, int maxPos, int curPos) {
    boolean done = false;
    while (tmpPos < maxPos && !done) {
      char d = s.charAt(tmpPos++);
      if (!isHexDigit(d)) {
        if (d == ';') {
          String t = s.substring(curPos + 2, tmpPos - 1);
          Character ch = parseHexChar(t);
          if (ch != null) return new DecodeResult(true, ch, tmpPos);
        }
        done = true;
      }
    }
    return new DecodeResult(false, '&', curPos);
  }

  private static DecodeResult decodeDecEntity(String s, int tmpPos, int maxPos, int curPos) {
    while (tmpPos < maxPos) {
      char d = s.charAt(tmpPos++);
      if (!isDigit(d)) {
        if (d == ';') {
          String t = s.substring(curPos + 1, tmpPos - 1);
          Character ch = parseDecChar(t);
          if (ch != null) return new DecodeResult(true, ch, tmpPos);
        }
        break;
      }
    }
    return new DecodeResult(false, '&', curPos);
  }

  private static DecodeResult decodeNamedEntity(String s, int tmpPos, int maxPos, int curPos) {
    while (tmpPos < maxPos) {
      char d = s.charAt(tmpPos++);
      if (!isLetterOrDigit(d)) {
        if (d == ';') {
          String t = s.substring(curPos, tmpPos - 1);
          Character ch = charTable.get(t);
          if (ch != null) {
            return new DecodeResult(true, ch, tmpPos);
          }
        }
        break;
      }
    }
    return new DecodeResult(false, '&', curPos);
  }

  private static boolean isLetterOrDigit(char c) {
    return isLetter(c) || isDigit(c);
  }

  private static boolean isHexDigit(char c) {
    return isHexLetter(c) || isDigit(c);
  }

  private static boolean isLetter(char c) {
    return ((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z'));
  }

  private static boolean isHexLetter(char c) {
    return ((c >= 'a') && (c <= 'f')) || ((c >= 'A') && (c <= 'F'));
  }

  private static boolean isDigit(char c) {
    return (c >= '0') && (c <= '9');
  }

  public static String compact(String s) {
    int maxPos = s.length();
    StringBuilder sb = new StringBuilder(maxPos);
    int curPos = 0;
    while (curPos < maxPos) {
      char c = s.charAt(curPos++);
      if (isWhitespace(c)) {
        while ((curPos < maxPos) && isWhitespace(s.charAt(curPos))) {
          curPos++;
        }
        c = ' ';
      }
      sb.append(c);
    }
    return sb.toString();
  }

  // HTML is very particular about what constitutes white space.
  public static boolean isWhitespace(char ch) {
    return
    // space
    (ch == ' ')
        // Mac newline
        || (ch == '\r')
        // Unix newline
        || (ch == '\n')
        // tab
        || (ch == '\t')
        // Control
        || (ch == '\u000c')
        // zero width space
        || (ch == '\u200b');
  }

  private HTMLDecoder() {}

  private static Character parseHexChar(String t) {
    try {
      int i = Integer.parseInt(t, 16);
      if ((i >= 0) && (i < 65536)) {
        return (char) i;
      }
    } catch (NumberFormatException _) {
      // ignore
    }
    return null;
  }

  private static Character parseDecChar(String t) {
    try {
      int i = Integer.parseInt(t);
      if ((i >= 0) && (i < 65536)) {
        return (char) i;
      }
    } catch (NumberFormatException _) {
      // ignore
    }
    return null;
  }
}
