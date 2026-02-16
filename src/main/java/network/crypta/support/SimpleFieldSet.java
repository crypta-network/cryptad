package network.crypta.support;

import static java.util.Collections.emptyMap;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import network.crypta.node.FSParseException;
import network.crypta.support.io.LineReader;
import network.crypta.support.io.Readers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Hierarchical key-value container with dot-separated keys and an optional Base64 value encoding.
 *
 * <p>This class stores configuration-like data as a tree where dots ({@code '.'}) delimit levels in
 * a key. For example:
 *
 * <pre>
 * DirectKey=Value
 * Subset.Key=Value
 * Subset.Subset.Key=Value
 * End
 * </pre>
 *
 * <p>Each entry has the form {@code <key>=<value>}. Keys may contain multiple levels separated by
 * {@link #MULTI_LEVEL_CHAR}, and values are plain strings. Arrays are encoded within a single value
 * by separating elements with {@link #MULTI_VALUE_CHAR} (e.g., {@code a;b;c}). An alternate, robust
 * value format is supported: {@code <key>==<base64(value)>}. When present, the value is Base64 of
 * the UTF‑8 bytes and may therefore include characters that would otherwise be illegal (whitespace,
 * control characters, separators). Reading in this format is always supported when enabled; writing
 * can be forced via the constructor flag.
 *
 * <p>Character encoding: when writing to {@link java.io.OutputStream}, UTF‑8 is used. When writing
 * to a {@link java.io.Writer}, the writer's own charset applies. Reading uses UTF‑8 unless
 * specified otherwise in the {@link LineReader}-based constructor.
 *
 * <p>Threading: some operations synchronize on {@code this} (e.g., lookups and mutations that
 * traverse subsets). The class does not guarantee full thread safety for all call sequences. If the
 * instance is accessed from multiple threads concurrently, external synchronization around read and
 * write operations is recommended.
 *
 * @author amphibian
 */
public final class SimpleFieldSet {
  private static final Logger LOG = LoggerFactory.getLogger(SimpleFieldSet.class);
  private static final String CANNOT_PARSE = "Cannot parse ";

  private final Map<String, String> values;
  private volatile ConcurrentHashMap<String, SimpleFieldSet> subsets;
  private volatile String endMarker;
  private final boolean shortLived;
  private final boolean alwaysUseBase64;
  String[] header;

  /** Separates levels in hierarchical keys (for example, {@code group.key} uses {@code '.'}). */
  public static final char MULTI_LEVEL_CHAR = '.';

  /** Separates multiple values stored within a single value field (for example, {@code a;b;c}). */
  public static final char MULTI_VALUE_CHAR = ';';

  /** Separator between a key and its value when writing a text form ({@code key=value}). */
  public static final char KEYVALUE_SEPARATOR_CHAR = '=';

  private static final String[] EMPTY_STRING_ARRAY = new String[0];

  /**
   * Create an empty field set.
   *
   * @param shortLived if {@code false}, keys and values are interned to reduce heap usage at the
   *     cost of CPU; set {@code true} only for small or short‑lived instances.
   */
  public SimpleFieldSet(boolean shortLived) {
    this(shortLived, false);
  }

  /**
   * Create an empty field set with optional Base64 enforcement.
   *
   * @param shortLived if {@code false}, keys and values are interned to reduce duplicate strings;
   *     set {@code true} for small/ephemeral instances.
   * @param alwaysUseBase64 if {@code true}, values that contain characters unsafe for the plain
   *     format (whitespace, control characters, separators) are written using the {@code ==} Base64
   *     form; reading always tolerates such values when allowed.
   */
  public SimpleFieldSet(boolean shortLived, boolean alwaysUseBase64) {
    values = new HashMap<>();
    subsets = null;
    this.shortLived = shortLived;
    this.alwaysUseBase64 = alwaysUseBase64;
  }

  /**
   * Construct from a buffered character stream.
   *
   * @param br source to read lines from (UTF‑8 assumed by default downstream).
   * @param allowMultiple if {@code true}, repeated keys are aggregated using {@link
   *     #MULTI_VALUE_CHAR}; if {@code false}, duplicates cause an error.
   * @param shortLived see {@link #SimpleFieldSet(boolean)}.
   * @throws IOException if I/O fails or the content is malformed.
   */
  public SimpleFieldSet(BufferedReader br, boolean allowMultiple, boolean shortLived)
      throws IOException {
    this(br, allowMultiple, shortLived, false, false);
  }

  /**
   * Construct from a buffered character stream with explicit Base64 options.
   *
   * @param br reader to consume lines from.
   * @param allowMultiple if {@code true}, repeated keys are aggregated using {@link
   *     #MULTI_VALUE_CHAR}; if {@code false}, duplicates cause an error.
   * @param shortLived see {@link #SimpleFieldSet(boolean)}.
   * @param allowBase64 if {@code true}, accepts {@code key==<base64>} lines during parsing.
   * @param alwaysBase64 if {@code true}, marks this instance so future writes may emit the Base64
   *     representation for values that need it.
   * @throws IOException on I/O errors or malformed input.
   */
  public SimpleFieldSet(
      BufferedReader br,
      boolean allowMultiple,
      boolean shortLived,
      boolean allowBase64,
      boolean alwaysBase64)
      throws IOException {
    this(shortLived, alwaysBase64);
    read(Readers.fromBufferedReader(br), allowMultiple, allowBase64);
  }

  /**
   * Copy constructor.
   *
   * <p>Performs a shallow copy of values and subsets; nested {@code SimpleFieldSet} instances are
   * shared. Reference copies header and end marker.
   *
   * @param sfs source to copy from.
   */
  public SimpleFieldSet(SimpleFieldSet sfs) {
    values = new HashMap<>(sfs.values);
    if (sfs.subsets != null) subsets = new ConcurrentHashMap<>(sfs.subsets);
    this.shortLived = false; // it's been copied!
    this.header = sfs.header;
    this.endMarker = sfs.endMarker;
    this.alwaysUseBase64 = sfs.alwaysUseBase64;
  }

  /**
   * Construct from a {@link LineReader} with size and charset controls.
   *
   * @param lis source of lines.
   * @param maxLineLength maximum number of characters per line; lines longer than this fail.
   * @param lineBufferSize buffer size used by the reader implementation.
   * @param utf8OrIso88591 if {@code true}, lines are interpreted as UTF‑8; otherwise ISO‑8859‑1.
   * @param allowMultiple if {@code true}, repeated keys are aggregated using {@link
   *     #MULTI_VALUE_CHAR}; if {@code false}, duplicates cause an error.
   * @param shortLived see {@link #SimpleFieldSet(boolean)}.
   * @throws IOException on I/O errors or malformed input.
   */
  public SimpleFieldSet(
      LineReader lis,
      int maxLineLength,
      int lineBufferSize,
      boolean utf8OrIso88591,
      boolean allowMultiple,
      boolean shortLived)
      throws IOException {
    this(lis, maxLineLength, lineBufferSize, utf8OrIso88591, allowMultiple, shortLived, false);
  }

  /**
   * Construct from a {@link LineReader} with optional Base64 support.
   *
   * @param lis source of lines.
   * @param maxLineLength maximum number of characters per line; lines longer than this fail.
   * @param lineBufferSize buffer size used by the reader implementation.
   * @param utf8OrIso88591 if {@code true}, lines are interpreted as UTF‑8; otherwise ISO‑8859‑1.
   * @param allowMultiple if {@code true}, repeated keys are aggregated using {@link
   *     #MULTI_VALUE_CHAR}; if {@code false}, duplicates cause an error.
   * @param shortLived see {@link #SimpleFieldSet(boolean)}.
   * @param allowBase64 if {@code true}, accepts {@code key==<base64>} lines during parsing.
   * @throws IOException on I/O errors or malformed input.
   */
  public SimpleFieldSet(
      LineReader lis,
      int maxLineLength,
      int lineBufferSize,
      boolean utf8OrIso88591,
      boolean allowMultiple,
      boolean shortLived,
      boolean allowBase64)
      throws IOException {
    this(shortLived);
    read(lis, maxLineLength, lineBufferSize, utf8OrIso88591, allowMultiple, allowBase64);
  }

  /**
   * Construct from a string containing one mapping per line, terminated by an end marker.
   *
   * <p>Format example: {@code key0=val0\nkey1=val1\nEnd\n}
   *
   * @param content textual representation to parse.
   * @param allowMultiple if {@code true}, repeated keys are aggregated using {@link
   *     #MULTI_VALUE_CHAR}; if {@code false}, duplicates cause an error.
   * @param shortLived see {@link #SimpleFieldSet(boolean)}.
   * @param allowBase64 if {@code true}, accepts {@code key==<base64>} lines during parsing.
   * @throws IOException if content is truncated, malformed, or otherwise invalid.
   */
  public SimpleFieldSet(
      String content, boolean allowMultiple, boolean shortLived, boolean allowBase64)
      throws IOException {
    this(shortLived);
    StringReader sr = new StringReader(content);
    BufferedReader br = new BufferedReader(sr);
    read(Readers.fromBufferedReader(br), allowMultiple, allowBase64);
  }

  /**
   * Construct from a string array, one line per array element.
   *
   * <p>Equivalent to the string constructor but avoids concatenation for pre-split content.
   *
   * @param content lines to parse (without trailing newlines).
   * @param allowMultiple if {@code true}, repeated keys are aggregated using {@link
   *     #MULTI_VALUE_CHAR}; if {@code false}, duplicates cause an error.
   * @param shortLived see {@link #SimpleFieldSet(boolean)}.
   * @param allowBase64 if {@code true}, accepts {@code key==<base64>} lines during parsing.
   * @throws IOException if parsing fails due to malformed input.
   */
  public SimpleFieldSet(
      String[] content, boolean allowMultiple, boolean shortLived, boolean allowBase64)
      throws IOException {
    this(shortLived);
    read(Readers.fromStringArray(content), allowMultiple, allowBase64);
  }

  /**
   * @see #read(LineReader, int, int, boolean, boolean, boolean)
   */
  private void read(LineReader lr, boolean allowMultiple, boolean allowBase64) throws IOException {
    read(lr, Integer.MAX_VALUE, 0x100, true, allowMultiple, allowBase64);
  }

  /**
   * Read from the stream. Format:
   *
   * <p># Header1 # Header2 key0=val0 key1=val1 # comment key2=val2 End
   *
   * <p>(headers and comments are optional)
   *
   * @param utfOrIso88591 If true, read as UTF-8, otherwise read as ISO-8859-1.
   */
  private void read(
      LineReader br,
      int maxLength,
      int bufferSize,
      boolean utfOrIso88591,
      boolean allowMultiple,
      boolean allowBase64)
      throws IOException {
    List<String> headers = new ArrayList<>();
    String firstDataLine =
        readHeader(br, maxLength, bufferSize, utfOrIso88591, headers); // maybe null
    if (!headers.isEmpty()) this.header = headers.toArray(new String[0]);
    readBody(br, maxLength, bufferSize, utfOrIso88591, allowMultiple, allowBase64, firstDataLine);
  }

  private String readHeader(
      LineReader br, int maxLength, int bufferSize, boolean utfOrIso88591, List<String> headers)
      throws IOException {
    boolean sawNonEmpty = false;
    while (true) {
      String line = br.readLine(maxLength, bufferSize, utfOrIso88591);
      if (line == null) {
        if (!sawNonEmpty) throw new EOFException();
        LOG.error("Missing end marker while reading header");
        return null;
      }
      if (!line.isEmpty()) {
        sawNonEmpty = true;
        if (isHeaderLine(line)) {
          headers.add(line.substring(1).trim());
        } else {
          return line; // first non-header, non-empty line
        }
      }
    }
  }

  private void readBody(
      LineReader br,
      int maxLength,
      int bufferSize,
      boolean utfOrIso88591,
      boolean allowMultiple,
      boolean allowBase64,
      String firstLine)
      throws IOException {
    String line = firstLine;
    while (true) {
      if (line == null) {
        // No end marker seen before EOF
        LOG.error("Missing end marker while reading body");
        return;
      }
      if (!line.isEmpty()) {
        // Inline comments inside the body must be ignored, not treated as end markers.
        if (isHeaderLine(line)) {
          line = br.readLine(maxLength, bufferSize, utfOrIso88591);
          continue;
        }
        if (handleDataLine(line, allowBase64, allowMultiple)) {
          return; // end marker reached
        }
      }
      line = br.readLine(maxLength, bufferSize, utfOrIso88591);
    }
  }

  private static boolean isHeaderLine(String line) {
    return !line.isEmpty() && line.charAt(0) == '#';
  }

  /**
   * Handle a non-header line. Returns true if the line is an end-marker (no '=') and reading should
   * stop; otherwise, processes the mapping and returns false.
   */
  private boolean handleDataLine(String line, boolean allowBase64, boolean allowMultiple)
      throws IOException {
    int index = line.indexOf(KEYVALUE_SEPARATOR_CHAR);
    if (index >= 0) {
      String before = line.substring(0, index).trim();
      String after = line.substring(index + 1);
      after = maybeDecodeValue(after, allowBase64);
      if (!shortLived) after = after.intern();
      put(before, after, allowMultiple, false, true);
      return false;
    }
    endMarker = line;
    return true;
  }

  private static String maybeDecodeValue(String value, boolean allowBase64) throws IOException {
    if (!value.isEmpty() && value.charAt(0) == '=' && allowBase64) {
      try {
        String v = value.substring(1).replaceAll("\\s", "");
        return Base64.decodeUTF8(v);
      } catch (IllegalBase64Exception _) {
        throw new IOException(
            "Unable to decode UTF8, = should not be allowed as first character of a value");
      }
    }
    return value;
  }

  /**
   * Look up a value by key, traversing subsets as needed.
   *
   * <p>The key may be a direct key (no dots) or a hierarchical path such as {@code
   * subset.subsubset.key}. If a subset component does not exist the method returns {@code null}.
   *
   * @param key key to resolve (may include {@link #MULTI_LEVEL_CHAR}).
   * @return the value, or {@code null} if absent.
   */
  public synchronized String get(String key) {
    int idx = key.indexOf(MULTI_LEVEL_CHAR);
    return switch (idx) {
      case -1 -> values.get(key);
      case 0 -> {
        SimpleFieldSet root = subset("");
        if (root == null) {
          yield null;
        }
        yield root.get(key.substring(1));
      }
      default -> {
        if (subsets == null) {
          yield null;
        }
        String before = key.substring(0, idx);
        String after = key.substring(idx + 1);
        SimpleFieldSet fs = subsets.get(before);
        if (fs == null) {
          yield null;
        }
        yield fs.get(after);
      }
    };
  }

  /**
   * Return a split view of a multivalued field.
   *
   * <p>Splits the value associated with {@code key} on {@link #MULTI_VALUE_CHAR} and preserves
   * leading/trailing empty elements.
   *
   * @param key key to resolve.
   * @return an array of elements, or {@code null} if the key is absent.
   */
  public String[] getAll(String key) {
    String k = get(key);
    return (k == null) ? null : split(k);
  }

  /**
   * Decode a multivalued Base64 field into plain UTF‑8 strings.
   *
   * <p>Each element in the underlying value is expected to be Base64 of UTF‑8 bytes.
   *
   * @param key key to resolve.
   * @return decoded elements, or {@code null} if the key is absent.
   * @throws IllegalBase64Exception if any element is not valid, Base64.
   */
  public String[] getAllEncoded(String key) throws IllegalBase64Exception {
    String k = get(key);
    String[] ret = null;
    if (k != null) {
      ret = split(k);
      for (int i = 0; i < ret.length; i++) {
        ret[i] = Base64.decodeUTF8(ret[i]);
      }
    }
    return ret;
  }

  /**
   * Split on {@link #MULTI_VALUE_CHAR} while preserving empty leading/trailing elements.
   *
   * <p>Example: {@code ";a;b;;" -> ["", "a", "b", "", ""]}. This differs from {@link
   * String#split(String)} which drops trailing empty strings.
   *
   * @param string input to split; {@code null} yields an empty array.
   * @return array of parts, preserving empties.
   */
  public static String[] split(String string) {
    if (string == null) return EMPTY_STRING_ARRAY;
    // Java 7 version of String.split() trims the extra delimiters at each end.
    int emptyAtStart = 0;
    while (emptyAtStart < string.length() && string.charAt(emptyAtStart) == MULTI_VALUE_CHAR) {
      emptyAtStart++;
    }
    if (emptyAtStart == string.length()) {
      String[] ret = new String[string.length()];
      Arrays.fill(ret, "");
      return ret;
    }
    int emptyAtEnd = 0;
    for (int i = string.length() - 1; i >= 0 && string.charAt(i) == MULTI_VALUE_CHAR; i--)
      emptyAtEnd++;
    string = string.substring(emptyAtStart, string.length() - emptyAtEnd);
    String[] split = string.split(String.valueOf(MULTI_VALUE_CHAR));
    if (emptyAtStart != 0 || emptyAtEnd != 0) {
      String[] ret = new String[emptyAtStart + split.length + emptyAtEnd];
      System.arraycopy(split, 0, ret, emptyAtStart, split.length);
      split = ret;
      for (int i = 0; i < split.length; i++) if (split[i] == null) split[i] = "";
    }
    return split;
  }

  /**
   * Join elements with {@link #MULTI_VALUE_CHAR} without escaping.
   *
   * @param strings elements to join.
   * @return the joined string.
   */
  private static String unsplit(String[] strings) {
    if (strings.length == 0) return "";
    StringBuilder sb = new StringBuilder();
    for (String s : strings) {
      sb.append(s);
      assert (s.indexOf(MULTI_VALUE_CHAR) == -1);
      sb.append(MULTI_VALUE_CHAR);
    }
    // assert(sb.length() > 0) -- always true as strings.length != 0
    // remove the last MULTI_VALUE_CHAR
    sb.deleteCharAt(sb.length() - 1);
    return sb.toString();
  }

  /**
   * Merge another field set into this one, overwriting existing keys and recursively merging
   * subsets.
   *
   * @param fs source to copy from; {@code null} is no‑op.
   */
  public void putAllOverwrite(SimpleFieldSet fs) {
    // overwrite old
    values.putAll(fs.values);
    if (fs.subsets == null) return;
    if (subsets == null) subsets = new ConcurrentHashMap<>();
    for (Map.Entry<String, SimpleFieldSet> entry : fs.subsets.entrySet()) {
      String key = entry.getKey();
      SimpleFieldSet hisFS = entry.getValue();
      SimpleFieldSet myFS = subsets.get(key);
      if (myFS != null) {
        myFS.putAllOverwrite(hisFS);
      } else {
        subsets.put(key, hisFS);
      }
    }
  }

  /**
   * Set a key to a value, failing if a value already exists at that path.
   *
   * @param key key to set (may include {@link #MULTI_LEVEL_CHAR}).
   * @param value value to store (must not contain newlines unless Base64 is enforced).
   * @throws IllegalStateException if the key already exists and aggregation/overwrite is not
   *     permitted.
   */
  public void putSingle(String key, String value) {
    if (value == null) return;
    if (!shortLived) value = value.intern();
    if (!put(key, value, false, false, false))
      throw new IllegalStateException(
          "Value already exists: " + value + " but want to set " + key + " to " + value);
  }

  /**
   * Append a value to a potentially multivalued key using {@link #MULTI_VALUE_CHAR}.
   *
   * <p>If the key is absent, behaves like {@link #putSingle(String, String)}. If present, appends
   * {@code MULTI_VALUE_CHAR + value}. Prefer {@link #putOverwrite(String, String)} when aggregation
   * is not required.
   *
   * @param key key to set.
   * @param value value to append.
   */
  public void putAppend(String key, String value) {
    if (value == null) return;
    if (!shortLived) value = value.intern();
    put(key, value, true, false, false);
  }

  /**
   * Set a key to a value, overwriting any existing value without aggregation checks.
   *
   * @param key key to set.
   * @param value value to store.
   */
  public void putOverwrite(String key, String value) {
    if (value == null) return;
    if (!shortLived) value = value.intern();
    put(key, value, false, true, false);
  }

  /**
   * Set a key to a value.
   *
   * @param key The key.
   * @param value The value.
   * @param allowMultiple If true, if the key already exists, then the value will be appended to the
   *     existing value. If false, we return false to indicate that the old value is unchanged.
   * @return True unless allowMultiple was false and there was a pre-existing value, or value was
   *     null.
   */
  private synchronized boolean put(
      String key, String value, boolean allowMultiple, boolean overwrite, boolean fromRead) {
    if (value == null) return true; // valid no-op
    validatePutArguments(key, value, allowMultiple, fromRead);

    int idx = key.indexOf(MULTI_LEVEL_CHAR);
    if (idx == -1) {
      return putAtTopLevel(key, value, allowMultiple, overwrite);
    }

    String before = key.substring(0, idx);
    String after = key.substring(idx + 1);
    putInSubset(before, after, value, allowMultiple, overwrite, fromRead);
    return true;
  }

  private void validatePutArguments(
      String key, String value, boolean allowMultiple, boolean fromRead) {
    if (!alwaysUseBase64 && value.indexOf('\n') != -1)
      throw new IllegalArgumentException("A simplefieldSet can't accept newlines !");
    if (allowMultiple && !fromRead && value.indexOf(MULTI_VALUE_CHAR) != -1) {
      throw new IllegalArgumentException(
          "Appending a string to a SimpleFieldSet value should not contain the multi-value char \""
              + MULTI_VALUE_CHAR
              + "\" but it does: \""
              + value
              + "\" for \""
              + key
              + "\"",
          new Exception("error"));
    }
  }

  private boolean putAtTopLevel(
      String key, String value, boolean allowMultiple, boolean overwrite) {
    if (!shortLived) key = key.intern();

    if (overwrite) {
      values.put(key, value);
      return true;
    }
    boolean wasAbsent = !values.containsKey(key);
    String existing = values.computeIfAbsent(key, _ -> value);
    if (wasAbsent) return true; // was absent, now set to value
    if (!allowMultiple) return false;
    values.put(key, existing + MULTI_VALUE_CHAR + value);
    return true;
  }

  private void putInSubset(
      String before,
      String after,
      String value,
      boolean allowMultiple,
      boolean overwrite,
      boolean fromRead) {
    if (subsets == null) subsets = new ConcurrentHashMap<>();
    String subsetKey = shortLived ? before : before.intern();
    SimpleFieldSet fs =
        subsets.computeIfAbsent(subsetKey, _ -> new SimpleFieldSet(shortLived, alwaysUseBase64));
    fs.put(after, value, allowMultiple, overwrite, fromRead);
  }

  /** Store an {@code int} value as a decimal string. */
  public void put(String key, int value) {
    // Use putSingle so it does the intern check
    putSingle(key, Integer.toString(value));
  }

  /** Store a {@code long} value as a decimal string. */
  public void put(String key, long value) {
    putSingle(key, Long.toString(value));
  }

  /** Store a {@code short} value as a decimal string. */
  public void put(String key, short value) {
    putSingle(key, Short.toString(value));
  }

  /** Store a single {@code char} value. */
  public void put(String key, char c) {
    putSingle(key, Character.toString(c));
  }

  /** Store a {@code boolean} value using {@code true} or {@code false}. */
  public void put(String key, boolean b) {
    // Don't use putSingle, avoid intern check (Boolean.toString returns interned strings anyway)
    put(key, Boolean.toString(b), false, false, false);
  }

  /** Store a {@code double} value using {@link Double#toString(double)}. */
  public void put(String key, double windowSize) {
    putSingle(key, Double.toString(windowSize));
  }

  /** Store a byte array encoded as Base64. */
  public void put(String key, byte[] bytes) {
    putSingle(key, Base64.encode(bytes));
  }

  /**
   * Write this field set in textual form to a {@link Writer}.
   *
   * <p>Callers should pass a buffered writer to avoid poor performance. {@link StringWriter} is
   * already buffered. The encoding depends on the {@code Writer}; use the {@code OutputStream}
   * overloads to guarantee UTF‑8.
   *
   * @param w destination writer (not closed by this method).
   * @throws IOException if writing fails.
   */
  public void writeTo(Writer w) throws IOException {
    writeTo(w, "", false, false);
  }

  /**
   * Internal write implementation with controls for prefixing, end marker, and Base64 emission.
   *
   * @param w destination writer (not closed).
   * @param prefix key prefix to prepend (useful when emitting nested structures).
   * @param noEndMarker if {@code true}, suppresses the trailing end marker line.
   * @param useBase64 if {@code true}, encodes values that contain whitespace, control characters,
   *     or SFS separators using {@code ==<base64(UTF‑8)>}. May be forced by instance configuration.
   * @throws IOException if writing fails.
   */
  synchronized void writeTo(Writer w, String prefix, boolean noEndMarker, boolean useBase64)
      throws IOException {
    writeHeader(w);
    for (Map.Entry<String, String> entry : values.entrySet()) {
      String key = entry.getKey();
      String value = entry.getValue();
      writeValue(w, key, value, prefix, useBase64);
    }
    if (subsets != null) {
      for (Map.Entry<String, SimpleFieldSet> entry : subsets.entrySet()) {
        String key = entry.getKey();
        SimpleFieldSet subset = entry.getValue();
        if (subset == null) throw new NullPointerException();
        subset.writeTo(w, prefix + key + MULTI_LEVEL_CHAR, true, useBase64);
      }
    }
    if (!noEndMarker) {
      if (endMarker == null) w.write("End\n");
      else {
        w.write(endMarker);
        w.write('\n');
      }
    }
  }

  private void writeValue(Writer w, String key, String value, String prefix, boolean useBase64)
      throws IOException {
    w.write(prefix);
    w.write(key);
    w.write(KEYVALUE_SEPARATOR_CHAR);
    if ((useBase64 || alwaysUseBase64) && shouldBase64(value)) {
      w.write(KEYVALUE_SEPARATOR_CHAR);
      w.write(Base64.encodeUTF8(value));
    } else {
      w.write(value);
    }
    w.write('\n');
  }

  private boolean shouldBase64(String value) {
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      if (c == SimpleFieldSet.KEYVALUE_SEPARATOR_CHAR) return true;
      if (c == SimpleFieldSet.MULTI_LEVEL_CHAR) return true;
      if (c == SimpleFieldSet.MULTI_VALUE_CHAR) return true;
      if (Character.isISOControl(c)) return true;
      if (Character.isWhitespace(c)) return true;
    }
    return false;
  }

  /**
   * Write this field set in deterministic key order to a {@link Writer}.
   *
   * @param w destination writer (not closed).
   * @throws IOException if writing fails.
   */
  public void writeToOrdered(Writer w) throws IOException {
    writeToOrdered(w, "", false, false);
  }

  /**
   * Internal ordered write with controls for prefixing, end marker, and optional Base64.
   *
   * @param w destination writer (not closed).
   * @param prefix prefix for keys at this level.
   * @param noEndMarker if {@code true}, suppresses the trailing end marker line.
   * @param allowOptionalBase64 if {@code true}, may Base64-encode values containing whitespace or
   *     control/separator characters for robustness. Values may still be encoded regardless if this
   *     instance was created with {@code alwaysUseBase64}.
   * @throws IOException if writing fails.
   */
  private synchronized void writeToOrdered(
      Writer w, String prefix, boolean noEndMarker, boolean allowOptionalBase64)
      throws IOException {
    writeHeader(w);
    String[] keys = values.keySet().toArray(new String[0]);
    int i;

    // Sort
    Arrays.sort(keys);

    // Output
    for (i = 0; i < keys.length; i++) {
      writeValue(w, keys[i], get(keys[i]), prefix, allowOptionalBase64);
    }

    if (subsets != null) {
      String[] orderedPrefixes = subsets.keySet().toArray(new String[0]);
      // Sort
      Arrays.sort(orderedPrefixes);

      for (i = 0; i < orderedPrefixes.length; i++) {
        SimpleFieldSet subset = subset(orderedPrefixes[i]);
        if (subset == null) throw new NullPointerException();
        subset.writeToOrdered(
            w, prefix + orderedPrefixes[i] + MULTI_LEVEL_CHAR, true, allowOptionalBase64);
      }
    }

    if (!noEndMarker) {
      if (endMarker == null) w.write("End\n");
      else w.write(endMarker + '\n');
    }
  }

  private void writeHeader(Writer w) throws IOException {
    if (header != null) {
      for (String line : header) {
        w.write("# " + line + "\n");
      }
    }
  }

  /**
   * Return the textual representation produced by {@link #writeTo(Writer)}.
   *
   * @return UTF‑8‑compatible text form of the field set.
   */
  @Override
  public String toString() {
    StringWriter sw = new StringWriter();
    try {
      writeTo(sw);
    } catch (IOException e) {
      LOG.error("Failed to render SimpleFieldSet via toString: {}", e, e);
    }
    return sw.toString();
  }

  /**
   * Return the deterministic textual representation produced by {@link #writeToOrdered(Writer)}.
   *
   * @return ordered text form of the field set.
   */
  public String toOrderedString() {
    StringWriter sw = new StringWriter();
    try {
      writeToOrdered(sw);
    } catch (IOException e) {
      LOG.error("Failed to render SimpleFieldSet via toOrderedString: {}", e, e);
    }
    return sw.toString();
  }

  /**
   * Return the ordered textual representation allowing Base64 when helpful.
   *
   * @return ordered text form; values may be Base64‑encoded as needed.
   */
  public String toOrderedStringWithBase64() {
    StringWriter sw = new StringWriter();
    try {
      writeToOrdered(sw, "", false, true);
    } catch (IOException e) {
      LOG.error("Failed to render SimpleFieldSet via toOrderedStringWithBase64: {}", e, e);
    }
    return sw.toString();
  }

  /**
   * Get the line used to mark the end of the set during writing.
   *
   * <p>If {@code null}, {@code "End"} is written by default.
   *
   * @return the end marker, or {@code null} if the default should be used.
   */
  public String getEndMarker() {
    return endMarker;
  }

  /**
   * Set a custom end marker to use when writing.
   *
   * @param s end marker text; {@code null} restores the default {@code "End"}.
   */
  public void setEndMarker(String s) {
    endMarker = s;
  }

  /**
   * Return the subset at the given path, or {@code null} if absent.
   *
   * @param key subset path using {@link #MULTI_LEVEL_CHAR}.
   * @return subset {@code SimpleFieldSet} or {@code null}.
   */
  public synchronized SimpleFieldSet subset(String key) {
    if (subsets == null) return null;
    int idx = key.indexOf(MULTI_LEVEL_CHAR);
    if (idx == -1) return subsets.get(key);
    String before = key.substring(0, idx);
    String after = key.substring(idx + 1);
    SimpleFieldSet fs = subsets.get(before);
    if (fs == null) return null;
    return fs.subset(after);
  }

  /**
   * Variant of {@link #subset(String)} that throws if the subset path does not exist.
   *
   * @param key the subset path to resolve.
   * @return the subset at {@code key}.
   * @throws FSParseException if no such subset exists.
   */
  public synchronized SimpleFieldSet getSubset(String key) throws FSParseException {
    SimpleFieldSet fs = subset(key);
    if (fs == null) throw new FSParseException("No such subset " + key);
    return fs;
  }

  /** Iterate over all keys (including nested keys). */
  public Iterator<String> keyIterator() {
    return new KeyIterator("");
  }

  /**
   * Iterate over all keys (including nested keys) with a fixed prefix applied to the returned
   * names.
   *
   * @param prefix string to prepend to each returned key; typically the path of this subset.
   * @return iterator over fully qualified keys with the provided prefix.
   */
  public KeyIterator keyIterator(String prefix) {
    return new KeyIterator(prefix);
  }

  /**
   * Iterate keys present at the top level only (no {@link #MULTI_LEVEL_CHAR} in their names).
   *
   * @return iterator over direct keys.
   */
  public Iterator<String> toplevelKeyIterator() {
    return values.keySet().iterator();
  }

  /**
   * Iterator over fully qualified keys in depth-first order.
   *
   * <p>The iterator yields direct keys first, then recurses into subsets. Returned keys include the
   * provided prefix, if any. The iteration reflects a snapshot of the map state at iterator
   * creation time; modifying the underlying structure concurrently is not supported.
   */
  public class KeyIterator implements Iterator<String> {
    final Iterator<String> valuesIterator;
    final Iterator<String> subsetIterator;
    KeyIterator subIterator;
    String prefix;

    /**
     * Create an iterator over keys with a prefix applied to results.
     *
     * <p>Example: for entries {@code key1=value1}, {@code key2.sub2=value2}, the iterator with
     * prefix {@code "p."} yields {@code p.key1}, {@code p.key2.sub2}.
     *
     * @param prefix string placed before every returned key.
     */
    public KeyIterator(String prefix) {
      synchronized (SimpleFieldSet.this) {
        valuesIterator = values.keySet().iterator();
        subsetIterator = (subsets != null) ? subsets.keySet().iterator() : null;
        initFirstSubIterator(prefix);
        this.prefix = prefix;
      }
    }

    private void initFirstSubIterator(String prefix) {
      if (valuesIterator != null && valuesIterator.hasNext()) return;
      if (subsetIterator == null) return;

      while (subsetIterator.hasNext()) {
        String name = subsetIterator.next();
        if (name != null) {
          SimpleFieldSet fs = subsets.get(name);
          if (fs != null) {
            String newPrefix = prefix + name + MULTI_LEVEL_CHAR;
            KeyIterator ki = fs.keyIterator(newPrefix);
            if (ki.hasNext()) {
              subIterator = ki;
              return;
            }
          }
        }
      }
    }

    @Override
    public boolean hasNext() {
      synchronized (SimpleFieldSet.this) {
        while (true) {
          if (valuesIterator.hasNext()) return true;
          if ((subIterator != null) && subIterator.hasNext()) return true;
          if (subIterator != null) subIterator = null;
          if (subsetIterator != null && subsetIterator.hasNext()) {
            String key = subsetIterator.next();
            SimpleFieldSet fs = subsets.get(key);
            String newPrefix = prefix + key + MULTI_LEVEL_CHAR;
            subIterator = fs.keyIterator(newPrefix);
          } else return false;
        }
      }
    }

    @Override
    public final String next() {
      return nextKey();
    }

    public String nextKey() {
      synchronized (SimpleFieldSet.this) {
        if (valuesIterator != null && valuesIterator.hasNext()) {
          return prefix + valuesIterator.next();
        }
        return nextFromSubsets();
      }
    }

    private String nextFromSubsets() {
      String candidate = null;
      while (true) {
        if (hasNextInSub()) {
          if (candidate != null) return candidate;
          candidate = subIterator.next();
          if (hasNextInSub()) return candidate;
        } else if (!advanceToNextSubIterator()) {
          return returnCandidateOrThrow(candidate);
        }
      }
    }

    private boolean hasNextInSub() {
      return subIterator != null && subIterator.hasNext();
    }

    private boolean advanceToNextSubIterator() {
      subIterator = null;
      if (subsetIterator == null) return false;
      while (subsetIterator.hasNext()) {
        String key = subsetIterator.next();
        SimpleFieldSet fs = subsets.get(key);
        String newPrefix = prefix + key + MULTI_LEVEL_CHAR;
        KeyIterator ki = fs.keyIterator(newPrefix);
        if (ki.hasNext()) {
          subIterator = ki;
          return true;
        }
      }
      return false;
    }

    private String returnCandidateOrThrow(String candidate) {
      if (candidate == null) throw new NoSuchElementException();
      return candidate;
    }

    @Override
    public synchronized void remove() {
      throw new UnsupportedOperationException();
    }
  }

  /**
   * Return an unmodifiable view of direct key/value pairs (top-level only).
   *
   * @return immutable map of direct keys to their values.
   */
  public Map<String, String> directKeyValues() {
    return Collections.unmodifiableMap(values);
  }

  /**
   * Return an unmodifiable set of direct key names (no nested paths).
   *
   * @return immutable set of direct keys.
   */
  public Set<String> directKeys() {
    return Collections.unmodifiableSet(values.keySet());
  }

  /**
   * Return an unmodifiable view of direct subsets (child field sets by prefix).
   *
   * @return immutable map from subset name to the corresponding {@link SimpleFieldSet}.
   */
  public Map<String, SimpleFieldSet> directSubsets() {
    return subsets == null ? emptyMap() : Collections.unmodifiableMap(subsets);
  }

  /**
   * Put a non-empty subset; no‑op when {@code fs} is {@code null} or empty.
   *
   * @param key subset name.
   * @param fs subset to insert under {@code key}.
   */
  public void tput(String key, SimpleFieldSet fs) {
    if (fs == null || fs.isEmpty()) return;
    put(key, fs);
  }

  /**
   * Insert a subset at the given key, creating intermediate subsets on demand.
   *
   * <p>For example, inserting under {@code a.b.c} creates missing parents {@code a} and {@code
   * a.b}. The provided subset must not be empty.
   *
   * @param key path at which to attach {@code fs}.
   * @param fs subset to attach; must be non-empty.
   * @throws IllegalArgumentException if {@code fs} is empty or a value already exists at {@code
   *     key}.
   */
  public void put(String key, SimpleFieldSet fs) {
    if (fs == null) return; // legal no-op, because used everywhere
    if (fs.isEmpty()) { // can't just no-op, because the caller might add the FS then populate it...
      throw new IllegalArgumentException("Empty");
    }
    if (subsets == null) subsets = new ConcurrentHashMap<>();
    if (subsets.containsKey(key))
      throw new IllegalArgumentException(
          "Already contains " + key + " but trying to add a SimpleFieldSet!");
    if (!shortLived) key = key.intern();
    subsets.put(key, fs);
  }

  /**
   * Remove a value at any depth and prune now-empty subsets.
   *
   * @param key path to the value to remove.
   */
  public synchronized void removeValue(String key) {
    int idx;
    if ((idx = key.indexOf(MULTI_LEVEL_CHAR)) == -1) {
      values.remove(key);
    } else {
      if (subsets == null) return;
      String before = key.substring(0, idx);
      String after = key.substring(idx + 1);
      SimpleFieldSet fs = subsets.get(before);
      if (fs == null) {
        return;
      }
      fs.removeValue(after);
      if (fs.isEmpty()) {
        subsets.remove(before);
        if (subsets.isEmpty()) subsets = null;
      }
    }
  }

  /**
   * Remove the specified subset and all of its descendants.
   *
   * <p>Example: with entries {@code foo=bar}, {@code foo.bar=...}, {@code foo.bar.baz=...}, calling
   * {@code removeSubset("foo")} removes the latter two entries but not the direct top-level {@code
   * foo=bar} value.
   *
   * @param key the subset path to remove.
   */
  public synchronized void removeSubset(String key) {
    if (subsets == null) return;
    int idx;
    if ((idx = key.indexOf(MULTI_LEVEL_CHAR)) == -1) {
      subsets.remove(key);
    } else {
      String before = key.substring(0, idx);
      String after = key.substring(idx + 1);
      SimpleFieldSet fs = subsets.get(before);
      if (fs == null) {
        return;
      }
      fs.removeSubset(after);
      if (fs.isEmpty()) {
        subsets.remove(before);
        if (subsets.isEmpty()) subsets = null;
      }
    }
  }

  /**
   * Return whether this set has neither direct values nor direct subsets.
   *
   * @return {@code true} if empty.
   */
  public synchronized boolean isEmpty() {
    return values.isEmpty() && (subsets == null || subsets.isEmpty());
  }

  /**
   * Iterator over names of direct child subsets (not values).
   *
   * @return iterator over child subset names, or {@code null} if there are no subsets.
   */
  public Iterator<String> directSubsetNameIterator() {
    return (subsets == null) ? null : subsets.keySet().iterator();
  }

  /**
   * Return the names of direct child subsets as an array.
   *
   * @return array of child subset names; empty if there are none.
   */
  public String[] namesOfDirectSubsets() {
    return (subsets == null) ? EMPTY_STRING_ARRAY : subsets.keySet().toArray(new String[0]);
  }

  /**
   * Read a field set from an {@link InputStream} using UTF‑8 without Base64 acceptance.
   *
   * @param is input stream (not closed by this method).
   * @param allowMultiple whether duplicate keys are combined with {@link #MULTI_VALUE_CHAR}.
   * @param shortLived if {@code true}, do not intern strings in the result.
   * @return newly parsed field set.
   * @throws IOException on I/O or format errors.
   */
  public static SimpleFieldSet readFrom(InputStream is, boolean allowMultiple, boolean shortLived)
      throws IOException {
    return readFrom(is, allowMultiple, shortLived, false, false);
  }

  /**
   * Read a field set from an {@link InputStream} using UTF‑8 with optional Base64 support.
   *
   * @param is input stream (not closed).
   * @param allowMultiple whether duplicate keys are combined with {@link #MULTI_VALUE_CHAR}.
   * @param shortLived if {@code true}, do not intern strings in the result.
   * @param allowBase64 if {@code true}, accepts {@code key==<base64>} lines during parsing.
   * @param alwaysBase64 if {@code true}, marks the result so writes may use Base64 for unsafe
   *     values.
   * @return newly parsed field set.
   * @throws IOException on I/O or format errors.
   */
  public static SimpleFieldSet readFrom(
      InputStream is,
      boolean allowMultiple,
      boolean shortLived,
      boolean allowBase64,
      boolean alwaysBase64)
      throws IOException {
    try (BufferedInputStream bis = new BufferedInputStream(is);
        InputStreamReader isr = new InputStreamReader(bis, StandardCharsets.UTF_8);
        BufferedReader br = new BufferedReader(isr)) {
      return new SimpleFieldSet(br, allowMultiple, shortLived, allowBase64, alwaysBase64);
    }
  }

  /**
   * Read a field set from a file using UTF‑8 without Base64 acceptance.
   *
   * @param f source file.
   * @param allowMultiple whether duplicate keys are combined with {@link #MULTI_VALUE_CHAR}.
   * @param shortLived if {@code true}, do not intern strings in the result.
   * @return newly parsed field set.
   * @throws IOException on I/O or format errors.
   */
  public static SimpleFieldSet readFrom(File f, boolean allowMultiple, boolean shortLived)
      throws IOException {
    try (FileInputStream fis = new FileInputStream(f)) {
      return readFrom(fis, allowMultiple, shortLived);
    }
  }

  /** Write to the given {@link OutputStream} as UTF‑8 and flush. */
  public void writeTo(OutputStream os) throws IOException {
    writeTo(os, 4096);
  }

  /** Write to the given stream (UTF‑8) using a large buffer, then flush. */
  public void writeToBigBuffer(OutputStream os) throws IOException {
    writeTo(os, 65536);
  }

  /** Write to the given stream (UTF‑8) using the specified buffer size, then flush. */
  public void writeTo(OutputStream os, int bufferSize) throws IOException {
    BufferedOutputStream bos;
    OutputStreamWriter osw;
    BufferedWriter bw;

    bos = new BufferedOutputStream(os, bufferSize);
    osw = new OutputStreamWriter(bos, StandardCharsets.UTF_8);
    bw = new BufferedWriter(osw);
    writeTo(bw);
    bw.flush();
  }

  /**
   * Get an integer value for the given key. This may be at the top level or lower in the tree, it's
   * just key=value. (Value in decimal)
   *
   * @param key The key to fetch.
   * @param def The default value to return if the key does not exist or can't be parsed.
   * @return The integer value of the key, or the default value.
   */
  public int getInt(String key, int def) {
    String s = get(key);
    if (s == null) return def;
    try {
      return Integer.parseInt(s);
    } catch (NumberFormatException _) {
      return def;
    }
  }

  /**
   * Get an integer value for the given key. This may be at the top level or lower in the tree, it's
   * just key=value. (Value in decimal)
   *
   * @param key The key to fetch.
   * @return The integer value of the key, if it exists and is valid.
   * @throws FSParseException If the key=value pair does not exist, or if the value cannot be parsed
   *     as an integer.
   */
  public int getInt(String key) throws FSParseException {
    String s = get(key);
    if (s == null) throw new FSParseException("No key " + key);
    try {
      return Integer.parseInt(s);
    } catch (NumberFormatException _) {
      throw new FSParseException(CANNOT_PARSE + s + " for integer " + key);
    }
  }

  /**
   * Get a double precision value for the given key. This may be at the top level or lower in the
   * tree, it's just key=value. (Value in decimal)
   *
   * @param key The key to fetch.
   * @param def The default value to return if the key does not exist or can't be parsed.
   * @return The integer value of the key, or the default value.
   */
  public double getDouble(String key, double def) {
    String s = get(key);
    if (s == null) return def;
    try {
      return Double.parseDouble(s);
    } catch (NumberFormatException _) {
      return def;
    }
  }

  /**
   * Get a double precision value for the given key. This may be at the top level or lower in the
   * tree, it's just key=value. (Value in decimal)
   *
   * @param key The key to fetch.
   * @return The value of the key as a double, if it exists and is valid.
   * @throws FSParseException If the key=value pair does not exist, or if the value cannot be parsed
   *     as a double.
   */
  public double getDouble(String key) throws FSParseException {
    String s = get(key);
    if (s == null) throw new FSParseException("No key " + key);
    try {
      return Double.parseDouble(s);
    } catch (NumberFormatException _) {
      throw new FSParseException(CANNOT_PARSE + s + " for double " + key);
    }
  }

  /**
   * Get a long value for the given key. This may be at the top level or lower in the tree, it's
   * just key=value. (Value in decimal)
   *
   * @param key The key to fetch.
   * @param def The default value to return if the key does not exist or can't be parsed.
   * @return The long value of the key, or the default value.
   */
  public long getLong(String key, long def) {
    String s = get(key);
    if (s == null) return def;
    try {
      return Long.parseLong(s);
    } catch (NumberFormatException _) {
      return def;
    }
  }

  /**
   * Get a long value for the given key. This may be at the top level or lower in the tree, it's
   * just key=value. (Value in decimal)
   *
   * @param key The key to fetch.
   * @return The value of the key as a long integer, if it exists and is valid.
   * @throws FSParseException If the key=value pair does not exist, or if the value cannot be parsed
   *     as a long integer.
   */
  public long getLong(String key) throws FSParseException {
    String s = get(key);
    if (s == null) throw new FSParseException("No key " + key);
    try {
      return Long.parseLong(s);
    } catch (NumberFormatException _) {
      throw new FSParseException(CANNOT_PARSE + s + " for long " + key);
    }
  }

  /**
   * Get a short value for the given key. This may be at the top level or lower in the tree, it's
   * just key=value. (Value in decimal)
   *
   * @param key The key to fetch.
   * @return The value of the key as a short, if it exists and is valid.
   * @throws FSParseException If the key=value pair does not exist, or if the value cannot be parsed
   *     as a short.
   */
  public short getShort(String key) throws FSParseException {
    String s = get(key);
    if (s == null) throw new FSParseException("No key " + key);
    try {
      return Short.parseShort(s);
    } catch (NumberFormatException _) {
      throw new FSParseException(CANNOT_PARSE + s + " for short " + key);
    }
  }

  /**
   * Get a short value or return the provided default if missing or invalid.
   *
   * @param key key to fetch.
   * @param def default value to return on absence or parse failure.
   * @return parsed short or {@code def}.
   */
  public short getShort(String key, short def) {
    String s = get(key);
    if (s == null) return def;
    try {
      return Short.parseShort(s);
    } catch (NumberFormatException _) {
      return def;
    }
  }

  /**
   * Get a byte value for the given key (represented as a number in decimal). This may be at the top
   * level or lower in the tree, it's just key=value. (Value in decimal)
   *
   * @param key The key to fetch.
   * @return The value of the key as a byte, if it exists and is valid.
   * @throws FSParseException If the key=value pair does not exist, or if the value cannot be parsed
   *     as a byte.
   */
  public byte getByte(String key) throws FSParseException {
    String s = get(key);
    if (s == null) throw new FSParseException("No key " + key);
    try {
      return Byte.parseByte(s);
    } catch (NumberFormatException _) {
      throw new FSParseException(CANNOT_PARSE + '"' + s + '"' + " as a byte.");
    }
  }

  /**
   * Get a byte value for the given key (represented as a number in decimal). This may be at the top
   * level or lower in the tree, it's just key=value. (Value in decimal)
   *
   * @param key The key to fetch.
   * @return The value of the key as a byte, if it exists and is valid, otherwise the default value.
   */
  public byte getByte(String key, byte def) {
    try {
      return getByte(key);
    } catch (FSParseException _) {
      return def;
    }
  }

  /**
   * Get a byte array for the given key (represented in Base64). The key may be at the top level or
   * further down the tree, so this is key=[base64 of value].
   *
   * @param key The key to fetch.
   * @return The byte array to fetch.
   * @throws FSParseException If the key does not exist or cannot be parsed as a byte array.
   */
  public byte[] getByteArray(String key) throws FSParseException {
    String s = get(key);
    if (s == null) throw new FSParseException("No key " + key);
    try {
      return Base64.decode(s);
    } catch (IllegalBase64Exception _) {
      throw new FSParseException(CANNOT_PARSE + "value \"" + s + "\" as a byte[]");
    }
  }

  /**
   * Get a char for the given key (represented as a single character). The key may be at the top
   * level or further down the tree, so this is key=[character].
   *
   * @param key The key to fetch.
   * @return The character to fetch.
   * @throws FSParseException If the key does not exist or there is more than one character.
   */
  public char getChar(String key) throws FSParseException {
    String s = get(key);
    if (s == null) throw new FSParseException("No key " + key);
    if (s.length() == 1) return s.charAt(0);
    else throw new FSParseException(CANNOT_PARSE + s + " for char " + key);
  }

  /**
   * Get a single character or return the provided default if missing or invalid.
   *
   * @param key key to fetch.
   * @param def default character if absent or not a single character.
   * @return the character or {@code def}.
   */
  public char getChar(String key, char def) {
    String s = get(key);
    if (s == null) return def;
    if (s.length() == 1) return s.charAt(0);
    else return def;
  }

  /**
   * Parse a boolean value or return the provided default.
   *
   * <p>Delegates to {@link Fields#stringToBool(String, boolean)}. Accepts forms understood by that
   * utility (e.g., {@code true/false}, {@code yes/no}, {@code 1/0}).
   *
   * @param key key to fetch.
   * @param def default value when absent or invalid.
   * @return parsed boolean or {@code def}.
   */
  public boolean getBoolean(String key, boolean def) {
    return Fields.stringToBool(get(key), def);
  }

  /**
   * Parse a boolean value.
   *
   * @param key key to fetch.
   * @return parsed boolean.
   * @throws FSParseException if the key is absent or cannot be parsed by {@link
   *     Fields#stringToBool(String)}.
   */
  public boolean getBoolean(String key) throws FSParseException {
    try {
      return Fields.stringToBool(get(key));
    } catch (NumberFormatException e) {
      throw new FSParseException(e);
    }
  }

  /**
   * Store an {@code int[]} as a multivalued field.
   *
   * @param key key to set.
   * @param value array whose elements are appended using {@link #MULTI_VALUE_CHAR}.
   */
  public void put(String key, int[] value) {
    removeValue(key);
    for (int v : value) putAppend(key, String.valueOf(v));
  }

  /** Store a {@code double[]} as a multivalued field. */
  public void put(String key, double[] value) {
    removeValue(key);
    for (double v : value) putAppend(key, String.valueOf(v));
  }

  /** Store a {@code float[]} as a multivalued field. */
  public void put(String key, float[] value) {
    removeValue(key);
    for (float v : value) putAppend(key, String.valueOf(v));
  }

  /** Store a {@code short[]} as a multivalued field. */
  public void put(String key, short[] value) {
    removeValue(key);
    for (short v : value) putAppend(key, String.valueOf(v));
  }

  /** Store a {@code long[]} as a multivalued field. */
  public void put(String key, long[] value) {
    removeValue(key);
    for (long v : value) putAppend(key, String.valueOf(v));
  }

  /** Store a {@code boolean[]} as a multivalued field. */
  public void put(String key, boolean[] value) {
    removeValue(key);
    for (boolean v : value) putAppend(key, String.valueOf(v));
  }

  /**
   * Parse a multivalued field as an {@code int[]}.
   *
   * @param key key to fetch.
   * @return parsed array, or {@code null} on absence or parse failure.
   */
  public int[] getIntArray(String key) {
    String[] strings = getAll(key);
    boolean parseFailed = (strings == null);
    int[] ret = null;
    if (!parseFailed) {
      ret = new int[strings.length];
      for (int i = 0; i < strings.length; i++) {
        try {
          ret[i] = Integer.parseInt(strings[i]);
        } catch (NumberFormatException e) {
          LOG.error("Cannot parse int array element {} : {}", strings[i], e, e);
          parseFailed = true;
          break;
        }
      }
    }
    return parseFailed ? null : ret;
  }

  /** Parse a multivalued field as a {@code short[]}; {@code null} on failure. */
  public short[] getShortArray(String key) {
    String[] strings = getAll(key);
    boolean parseFailed = (strings == null);
    short[] ret = null;
    if (!parseFailed) {
      ret = new short[strings.length];
      for (int i = 0; i < strings.length; i++) {
        try {
          ret[i] = Short.parseShort(strings[i]);
        } catch (NumberFormatException e) {
          LOG.error("Cannot parse short array element {} : {}", strings[i], e, e);
          parseFailed = true;
          break;
        }
      }
    }
    return parseFailed ? null : ret;
  }

  /** Parse a multivalued field as a {@code long[]}; {@code null} on failure. */
  public long[] getLongArray(String key) {
    String[] strings = getAll(key);
    boolean parseFailed = (strings == null);
    long[] ret = null;
    if (!parseFailed) {
      ret = new long[strings.length];
      for (int i = 0; i < strings.length; i++) {
        try {
          ret[i] = Long.parseLong(strings[i]);
        } catch (NumberFormatException e) {
          LOG.error("Cannot parse long array element {} : {}", strings[i], e, e);
          parseFailed = true;
          break;
        }
      }
    }
    return parseFailed ? null : ret;
  }

  /** Parse a multivalued field as a {@code double[]}; {@code null} on failure. */
  public double[] getDoubleArray(String key) {
    String[] strings = getAll(key);
    boolean parseFailed = (strings == null);
    double[] ret = null;
    if (!parseFailed) {
      ret = new double[strings.length];
      for (int i = 0; i < strings.length; i++) {
        try {
          ret[i] = Double.parseDouble(strings[i]);
        } catch (NumberFormatException e) {
          LOG.error("Cannot parse double array element {} : {}", strings[i], e, e);
          parseFailed = true;
          break;
        }
      }
    }

    return parseFailed ? null : ret;
  }

  /** Parse a multivalued field as a {@code boolean[]}; {@code null} on failure. */
  public boolean[] getBooleanArray(String key) {
    String[] strings = getAll(key);
    boolean parseFailed = (strings == null);
    boolean[] ret = null;
    if (!parseFailed) {
      ret = new boolean[strings.length];
      for (int i = 0; i < strings.length; i++) {
        try {
          ret[i] = Boolean.parseBoolean(strings[i]);
        } catch (NumberFormatException e) {
          LOG.error("Cannot parse boolean array element {} : {}", strings[i], e, e);
          parseFailed = true;
          break;
        }
      }
    }

    return parseFailed ? null : ret;
  }

  /** Overwrite a key with the given string elements joined by {@link #MULTI_VALUE_CHAR}. */
  public void putOverwrite(String key, String[] strings) {
    putOverwrite(key, unsplit(strings));
  }

  /**
   * Write a multivalued field where each element is Base64 of UTF‑8.
   *
   * @param key key to set.
   * @param strings elements to encode and join.
   */
  public void putEncoded(String key, String[] strings) {
    String[] copy = Arrays.copyOf(strings, strings.length);
    for (int i = 0; i < copy.length; i++) {
      copy[i] = Base64.encodeUTF8(strings[i]);
    }
    putSingle(key, unsplit(copy));
  }

  /**
   * Return the raw string value associated with {@code key}.
   *
   * @param key key to fetch.
   * @return value string.
   * @throws FSParseException if the key is absent.
   */
  public String getString(String key) throws FSParseException {
    String s = get(key);
    if (s == null) throw new FSParseException("No such element " + key);
    return s;
  }

  /**
   * Set the headers. This is a list of String's that is written before the name=value pairs.
   * Usually this is a comment (with each line starting with "#").
   *
   * @param headers The list of lines to precede the SimpleFieldSet by when we write it.
   */
  public void setHeader(String... headers) {
    // Note: header lines should not contain newline characters
    this.header = headers;
  }

  /**
   * Get the headers. This is a list of String's that is written before the name=value pairs.
   * Usually this is a comment (with each line starting with "#").
   */
  public String[] getHeader() {
    return this.header;
  }

  public void put(String key, String[] values) {
    putSingle(key, unsplit(values));
  }
}
