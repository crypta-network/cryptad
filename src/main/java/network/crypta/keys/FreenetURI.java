package network.crypta.keys;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Random;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.InsertException;
import network.crypta.support.Base64;
import network.crypta.support.Fields;
import network.crypta.support.IllegalBase64Exception;
import network.crypta.support.URLDecoder;
import network.crypta.support.URLEncodedFormatException;
import network.crypta.support.URLEncoder;
import network.crypta.support.io.FileUtil;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents and parses Freenet-style URIs.
 *
 * <p>This class can construct and validate URIs for the key types {@code CHK}, {@code SSK}, {@code
 * KSK}, and {@code USK}. It also provides helpers to derive related URIs (for example, converting
 * USK ⇄ SSK forms) and to encode/decode a compact binary representation used in inter-node
 * protocols.
 *
 * <p>String form (simplified):
 *
 * <pre>{@code
 * freenet:[KeyType@]RoutingKey,CryptoKey[,n1=v1,n2=v2,...][/docname][/metastring]
 * }</pre>
 *
 * <ul>
 *   <li>{@code KeyType} is one of {@code USK}, {@code SSK}, {@code KSK}, or {@code CHK}. If omitted
 *       in legacy contexts it defaults to {@code KSK}.
 *   <li>{@code RoutingKey} and {@code CryptoKey} are modified-Base64 values. For {@code CHK}, the
 *       routing key and crypto key are each 32 bytes when decoded.
 *   <li>{@code docname} is meaningful for {@code SSK} and {@code USK}. {@code CHK} does not use a
 *       document name and goes straight into meta-strings if any.
 *   <li>{@code metastring} segments select items from a fetched manifest; multiple segments are
 *       processed left-to-right during retrieval.
 * </ul>
 *
 * <p>Notes:
 *
 * <ul>
 *   <li>Key/value metadata pairs (the {@code n1=v1} form) are not supported here; they existed in
 *       very old (0.5) code and are accepted only for historical parsing where applicable.
 *   <li>When parsing {@code CHK} strings, an optional filename extension (e.g., {@code
 *       CHK@...}.{@code html}) is ignored; parsing stops at the first dot in the base portion.
 * </ul>
 *
 * <p>Serialization warning: This class is {@link java.io.Serializable}. Changing non-transient
 * fields will affect the wire format and may restart downloads or lose uploads when upgrading
 * persisted state.
 */
public final class FreenetURI implements Comparable<FreenetURI>, Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(FreenetURI.class);

  /** For Serializable. */
  @Serial private static final long serialVersionUID = 1L;

  // No static initialization required

  private final String keyType;
  private final String docName;

  /**
   * Meta-string segments in the order provided.
   *
   * <p>Resolution typically fetches the base key (e.g., {@code SSK@.../filename}, {@code CHK@...},
   * {@code KSK@filename}, or {@code USK@.../filename/20}), interprets the returned metadata as a
   * manifest, and then follows each meta-string segment in sequence to locate the final target.
   * This behavior is performed by fetchers such as {@code SingleFileFetcher}.
   */
  private final String[] metaStr;

  /* For SSKs, {@code routingKey} stores the public key hash (pkHash). The effective routing key
   * used on the wire is derived from the pkHash and the document name; see NodeSSK for details. */
  private final byte[] routingKey;
  private final byte[] cryptoKey;
  private final byte[] extra;
  private final long suggestedEdition; // for USKs
  private boolean hasHashCode;
  private int hashCode;
  // uniqueHashCode was used in legacy debugging; keep lean fields only
  static final String[] VALID_KEY_TYPES = new String[] {"CHK", "SSK", "KSK", "USK"};

  @Override
  public synchronized int hashCode() {
    if (hasHashCode) return hashCode;
    int x = keyType.hashCode();
    if (docName != null) x ^= docName.hashCode();
    if (metaStr != null) for (String s : metaStr) x ^= s.hashCode();
    if (routingKey != null) x ^= Fields.hashCode(routingKey);
    if (cryptoKey != null) x ^= Fields.hashCode(cryptoKey);
    if (extra != null) x ^= Fields.hashCode(extra);
    if (keyType.equals("USK")) x ^= (int) suggestedEdition;
    hashCode = x;
    hasHashCode = true;
    return x;
  }

  @Override
  public boolean equals(Object o) {
    if (o == this) return true;
    if (!(o instanceof FreenetURI f)) return false;
    else {
      if (!keyType.equals(f.keyType)) return false;
      if (keyType.equals("USK") && suggestedEdition != f.suggestedEdition) return false;
      if ((docName == null) ^ (f.docName == null)) return false;
      if ((metaStr == null || metaStr.length == 0) ^ (f.metaStr == null || f.metaStr.length == 0))
        return false;
      if ((routingKey == null) ^ (f.routingKey == null)) return false;
      if ((cryptoKey == null) ^ (f.cryptoKey == null)) return false;
      if ((extra == null) ^ (f.extra == null)) return false;
      if ((docName != null) && !docName.equals(f.docName)) return false;
      if ((metaStr != null) && !Arrays.equals(metaStr, f.metaStr)) return false;
      if ((routingKey != null) && !Arrays.equals(routingKey, f.routingKey)) return false;
      if ((cryptoKey != null) && !Arrays.equals(cryptoKey, f.cryptoKey)) return false;
      return (extra == null) || Arrays.equals(extra, f.extra);
    }
  }

  /**
   * Is the keypair (the routing key and crypto key) the same as the given key?
   *
   * @return False if there is no routing key or no crypto key (CHKs, SSKs, USKs have them, KSKs
   *     don't), or if the keys don't have the same crypto key and routing key.
   */
  public boolean equalsKeypair(FreenetURI u2) {
    if (u2 == null) return false;
    if ((routingKey != null) && (cryptoKey != null))
      return Arrays.equals(routingKey, u2.routingKey) && Arrays.equals(cryptoKey, u2.cryptoKey);

    return false;
  }

  /**
   * Copy constructor.
   *
   * <p>Performs a defensive copy of array fields and preserves cached values (hash code and {@code
   * toString()} cache) to keep identity/performance characteristics equivalent to the source
   * instance.
   *
   * @param uri The source URI to copy; must have a non-null key type.
   * @throws NullPointerException if {@code uri.keyType} is {@code null}.
   */
  public FreenetURI(FreenetURI uri) {
    if (uri.keyType == null) throw new NullPointerException();
    keyType = uri.keyType;
    docName = uri.docName;
    if (uri.metaStr != null) {
      metaStr = uri.metaStr.clone();
    } else metaStr = null;
    if (uri.routingKey != null) {
      routingKey = uri.routingKey.clone();
    } else routingKey = null;
    if (uri.cryptoKey != null) {
      cryptoKey = uri.cryptoKey.clone();
    } else cryptoKey = null;
    if (uri.extra != null) {
      extra = uri.extra.clone();
    } else extra = null;
    this.suggestedEdition = uri.suggestedEdition;
    // Copy cached computed fields to preserve identity/performance semantics.
    this.hasHashCode = uri.hasHashCode;
    this.hashCode = uri.hashCode;
    this.toStringCache = uri.toStringCache;
    if (LOG.isTraceEnabled()) LOG.trace("Copied: {} from {}", this, uri);
  }

  /**
   * Construct a URI with a key type and document name only.
   *
   * <p>Convenience for creating {@code KSK}-style URIs (or as a basis for other types) with no
   * routing/crypto keys or meta-strings.
   *
   * @param keyType Key type name; uppercased and interned. Must be non-null.
   * @param docName Document name (may be {@code null} for types that do not use one).
   * @throws NullPointerException if {@code keyType} is {@code null}.
   */
  public FreenetURI(String keyType, String docName) {
    this(keyType, docName, null, null, null, null);
  }

  public static final FreenetURI EMPTY_CHK_URI =
      new FreenetURI("CHK", null, null, null, null, null);

  /**
   * Construct a URI from components.
   *
   * @param keyType Key type; uppercased and interned. Must be non-null.
   * @param docName Document name; meaningful for {@code SSK}/{@code USK}.
   * @param routingKey Routing key bytes. For {@code CHK}, must be 32 bytes; for other types may be
   *     {@code null} or type-specific.
   * @param cryptoKey Crypto key bytes. When provided must be 32 bytes.
   * @param extra2 Extra parameter bytes (algorithm/mode, etc.), type-specific; may be {@code null}.
   * @throws IllegalArgumentException if a {@code CHK} routing key is not 32 bytes, or if a crypto
   *     key is not 32 bytes.
   */
  public FreenetURI(
      String keyType, String docName, byte[] routingKey, byte[] cryptoKey, byte[] extra2) {
    this(keyType, docName, null, routingKey, cryptoKey, extra2);
  }

  /**
   * Construct a URI from components with a single meta-string.
   *
   * @param keyType Key type; uppercased and interned.
   * @param docName Document name.
   * @param metaStr Single meta-string segment; may be {@code null}.
   * @param routingKey Routing key bytes.
   * @param cryptoKey Crypto key bytes.
   * @throws IllegalArgumentException on invalid key lengths (see the other constructor).
   */
  public FreenetURI(
      String keyType, String docName, String metaStr, byte[] routingKey, byte[] cryptoKey) {
    this(
        keyType,
        docName,
        (metaStr == null ? null : new String[] {metaStr}),
        routingKey,
        cryptoKey,
        null);
  }

  /**
   * Construct a URI from components with optional meta-strings.
   *
   * @param keyType Key type; uppercased and interned.
   * @param docName Document name; may be {@code null} for types that do not require it.
   * @param metaStr Meta-string segments in order; may be {@code null}.
   * @param routingKey Routing key bytes.
   * @param cryptoKey Crypto key bytes.
   * @param extra2 Extra parameter bytes (type-specific); may be {@code null}.
   * @throws IllegalArgumentException on invalid key lengths (see above).
   */
  public FreenetURI(
      String keyType,
      String docName,
      String[] metaStr,
      byte[] routingKey,
      byte[] cryptoKey,
      byte[] extra2) {
    // Construct from components
    this.keyType = keyType.trim().toUpperCase(Locale.ROOT).intern();
    this.docName = docName;
    this.metaStr = metaStr;
    this.routingKey = routingKey;
    if (routingKey != null && keyType.equals("CHK") && routingKey.length != 32)
      throw new IllegalArgumentException("Bad URI: Routing key should be 32 bytes");
    this.cryptoKey = cryptoKey;
    if (cryptoKey != null && cryptoKey.length != 32)
      throw new IllegalArgumentException("Bad URI: Crypto key should be 32 bytes");
    this.extra = extra2;
    this.suggestedEdition = -1;
    if (LOG.isDebugEnabled()) LOG.debug("Created from components: {}", this);
  }

  /**
   * Construct a URI from components with an explicit suggested edition (for {@code USK}).
   *
   * @param keyType Key type.
   * @param docName Document name.
   * @param metaStr Meta-string segments.
   * @param routingKey Routing key bytes.
   * @param cryptoKey Crypto key bytes.
   * @param extra2 Extra parameter bytes.
   * @param suggestedEdition Suggested edition (used when {@code keyType == USK}).
   * @throws IllegalArgumentException on invalid key lengths.
   */
  public FreenetURI(
      String keyType,
      String docName,
      String[] metaStr,
      byte[] routingKey,
      byte[] cryptoKey,
      byte[] extra2,
      long suggestedEdition) {
    // Construct from components with an explicit edition
    this.keyType = keyType.trim().toUpperCase(Locale.ROOT).intern();
    this.docName = docName;
    this.metaStr = metaStr;
    this.routingKey = routingKey;
    if (routingKey != null && keyType.equals("CHK") && routingKey.length != 32)
      throw new IllegalArgumentException("Bad URI: Routing key should be 32 bytes");
    this.cryptoKey = cryptoKey;
    if (cryptoKey != null && cryptoKey.length != 32)
      throw new IllegalArgumentException("Bad URI: Crypto key should be 32 bytes");
    this.extra = extra2;
    this.suggestedEdition = suggestedEdition;
    if (LOG.isDebugEnabled()) LOG.debug("Created from components (B): {}", this);
  }

  // Strip optional http(s)://host/… and scheme prefixes like (web+|ext+)(freenet|hyphanet|hypha):
  static final Pattern URI_PREFIX =
      Pattern.compile("^(https?://[^/]+/+)?(((ext|web)\\+)?(freenet|hyphanet|hypha):)?");

  /**
   * Parse a URI string into a {@code FreenetURI}.
   *
   * <p>Accepts optional prefixes such as {@code freenet:}, {@code web+freenet:}, and plain paths
   * (where reserved characters may already be percent-encoded). Query strings are stripped during
   * normalization.
   *
   * @param uriString The input string; must not be {@code null}.
   * @throws MalformedURLException if parsing fails or if the key type is invalid.
   */
  public FreenetURI(String uriString) throws MalformedURLException {
    this(uriString, false);
  }

  /**
   * Parse a URI string with optional trimming of surrounding whitespace.
   *
   * <p>The parser removes a trailing query component, decodes percent-escapes where necessary, and
   * accepts optional scheme prefixes (e.g., {@code freenet:}). When {@code noTrim} is {@code
   * false}, leading and trailing whitespace are removed before parsing.
   *
   * @param uriString The input string; must not be {@code null}.
   * @param noTrim If {@code true}, do not trim the input string.
   * @throws MalformedURLException If the string could not be parsed.
   */
  public FreenetURI(String uriString, boolean noTrim) throws MalformedURLException {
    if (uriString == null) throw new MalformedURLException("No URI specified");

    String normalized = stripQueryAndMaybeDecode(uriString, noTrim);
    normalized = URI_PREFIX.matcher(normalized).replaceFirst("");

    // decode keyType (left of '@') and the remainder (right of '@')
    int atchar = normalized.indexOf('@');
    if (atchar == -1)
      throw new MalformedURLException("There is no @ in that URI! (" + normalized + ')');
    String kt = normalized.substring(0, atchar).toUpperCase(Locale.ROOT);
    String remainder = normalized.substring(atchar + 1);

    keyType = validateKeyTypeOrThrow(kt);
    final boolean isSSK = "SSK".equals(keyType);
    final boolean isUSK = "USK".equals(keyType);
    final boolean isKSK = "KSK".equals(keyType);

    MetaParse m = parseDocAndMeta(remainder, keyType, isKSK, isUSK, isSSK);
    docName = m.docName();
    metaStr = m.meta();
    suggestedEdition = m.edition();

    if (isKSK) {
      routingKey = extra = cryptoKey = null;
      if (LOG.isTraceEnabled()) LOG.trace("Created from parse: {} from {}", this, normalized);
      return;
    }

    // CHKs can have a ".ext" tail which should be ignored when parsing raw parts
    String raw = m.base();
    if ("CHK".equals(keyType)) {
      int idx = raw.lastIndexOf('.');
      if (idx != -1) raw = raw.substring(0, idx);
    }

    KeyParts parts = parseKeyParts(raw, keyType, isUSK, isSSK, docName);
    routingKey = parts.routingKey();
    cryptoKey = parts.cryptoKey();
    extra = parts.extra();
    if (LOG.isTraceEnabled()) LOG.trace("Created from parse: {} from {}", this, normalized);
  }

  private static String stripQueryAndMaybeDecode(String input, boolean noTrim)
      throws MalformedURLException {
    String s = noTrim ? input : input.trim();
    int q = s.indexOf('?');
    if (q > -1) s = s.substring(0, q);
    if (s.indexOf('@') < 0 || s.indexOf('/') < 0) {
      try {
        s = URLDecoder.decode(s, false);
      } catch (URLEncodedFormatException _) {
        throw new MalformedURLException(
            "Invalid URI: no @ or /, or @ or / is escaped but there are invalid escapes");
      }
    }
    return s;
  }

  private static String validateKeyTypeOrThrow(String kt) throws MalformedURLException {
    for (String valid : VALID_KEY_TYPES) {
      if (valid.equals(kt)) return valid;
    }
    throw new MalformedURLException("Invalid key type: " + kt);
  }

  @SuppressWarnings({"java:S6206", "ClassCanBeRecord"})
  private static final class MetaParse {
    private final String docName;
    private final String[] meta;
    private final long edition;
    private final String base;

    private MetaParse(String docName, String[] meta, long edition, String base) {
      this.docName = docName;
      this.meta = meta;
      this.edition = edition;
      this.base = base;
    }

    String docName() {
      return docName;
    }

    String[] meta() {
      return meta;
    }

    long edition() {
      return edition;
    }

    String base() {
      return base;
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof MetaParse other)) return false;
      return edition == other.edition
          && Objects.equals(docName, other.docName)
          && Objects.equals(base, other.base)
          && Arrays.equals(meta, other.meta);
    }

    @Override
    public int hashCode() {
      int result = Objects.hash(docName, edition, base);
      result = 31 * result + Arrays.hashCode(meta);
      return result;
    }

    @Override
    public @NotNull String toString() {
      return "MetaParse[docName="
          + docName
          + ", meta="
          + Arrays.toString(meta)
          + ", edition="
          + edition
          + ", base="
          + base
          + "]";
    }
  }

  private static MetaParse parseDocAndMeta(
      String remainder, String keyType, boolean isKSK, boolean isUSK, boolean isSSK)
      throws MalformedURLException {
    Segments segs = decodeSegments(remainder, isKSK);
    DocEdition de = deriveDocAndEdition(segs.list(), keyType, isUSK, isSSK, isKSK);
    String[] meta = toMetaArray(segs.list());
    if (meta.length == 0) meta = null; // preserve external behavior while satisfying S1168
    return new MetaParse(de.docName(), meta, de.edition(), segs.base());
  }

  private record Segments(List<String> list, String base) {}

  private static Segments decodeSegments(String remainder, boolean isKSK)
      throws MalformedURLException {
    ArrayList<String> segments = new ArrayList<>();
    String s = isKSK ? "/" + remainder : remainder;
    int slash2;
    while ((slash2 = s.lastIndexOf('/')) != -1) {
      String seg;
      try {
        seg = URLDecoder.decode(s.substring(slash2 + 1), true);
      } catch (URLEncodedFormatException e) {
        throw (MalformedURLException) new MalformedURLException(e.toString()).initCause(e);
      }
      if (seg != null) segments.add(seg);
      s = s.substring(0, slash2);
    }
    return new Segments(segments, s);
  }

  private record DocEdition(String docName, long edition) {}

  private static DocEdition deriveDocAndEdition(
      List<String> segments, String keyType, boolean isUSK, boolean isSSK, boolean isKSK)
      throws MalformedURLException {
    if (segments.isEmpty() && (isUSK || isKSK))
      throw new MalformedURLException("No docname for " + keyType);

    String docName;
    long edition;
    if ((isSSK || isUSK || isKSK) && !segments.isEmpty()) {
      docName = segments.removeLast();
      edition = isUSK ? parseUskEditionOrThrow(segments) : -1;
    } else {
      docName = null; // not supported for CHKs
      edition = -1;
    }
    return new DocEdition(docName, edition);
  }

  private static long parseUskEditionOrThrow(List<String> segments) throws MalformedURLException {
    if (segments.isEmpty()) throw new MalformedURLException("No suggested edition number for USK");
    try {
      return Long.parseLong(segments.removeLast());
    } catch (NumberFormatException e) {
      throw (MalformedURLException)
          new MalformedURLException("Invalid suggested edition: " + e).initCause(e);
    }
  }

  private static String[] toMetaArray(List<String> segments) {
    if (segments.isEmpty()) return new String[0];
    String[] meta = new String[segments.size()];
    for (int i = 0; i < meta.length; i++) {
      meta[i] = segments.get(meta.length - 1 - i).intern();
      if (meta[i] == null) throw new NullPointerException();
    }
    return meta;
  }

  @SuppressWarnings({"java:S6206", "ClassCanBeRecord"})
  private static final class KeyParts {
    private final byte[] routingKey;
    private final byte[] cryptoKey;
    private final byte[] extra;

    private KeyParts(byte[] routingKey, byte[] cryptoKey, byte[] extra) {
      this.routingKey = routingKey;
      this.cryptoKey = cryptoKey;
      this.extra = extra;
    }

    byte[] routingKey() {
      return routingKey;
    }

    byte[] cryptoKey() {
      return cryptoKey;
    }

    byte[] extra() {
      return extra;
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof KeyParts other)) return false;
      return Arrays.equals(routingKey, other.routingKey)
          && Arrays.equals(cryptoKey, other.cryptoKey)
          && Arrays.equals(extra, other.extra);
    }

    @Override
    public int hashCode() {
      int result = Arrays.hashCode(routingKey);
      result = 31 * result + Arrays.hashCode(cryptoKey);
      result = 31 * result + Arrays.hashCode(extra);
      return result;
    }

    @Override
    public @NotNull String toString() {
      return "KeyParts[routingKey="
          + Arrays.toString(routingKey)
          + ", cryptoKey="
          + Arrays.toString(cryptoKey)
          + ", extra="
          + Arrays.toString(extra)
          + "]";
    }
  }

  private static KeyParts parseKeyParts(
      String base, String keyType, boolean isUSK, boolean isSSK, String docName)
      throws MalformedURLException {
    StringTokenizer st = new StringTokenizer(base, ",");
    try {
      byte[] rKey;
      byte[] cKey;
      byte[] extraBytes;
      if (st.hasMoreTokens()) {
        rKey = Base64.decode(st.nextToken());
        if (rKey.length != 32 && keyType.equals("CHK"))
          throw new MalformedURLException("Bad URI: Routing key should be 32 bytes long");
      } else {
        if (isUSK || (isSSK && docName != null))
          throw new MalformedURLException("Bad URI: Routing key missing");
        return new KeyParts(null, null, null);
      }
      if (!st.hasMoreTokens()) {
        return new KeyParts(rKey, null, null);
      }

      String t = st.nextToken();
      cKey = Base64.decode(t);
      if (cKey.length != 32)
        throw new MalformedURLException("Bad URI: Crypto key should be 32 bytes long");
      if (!st.hasMoreTokens()) {
        return new KeyParts(rKey, cKey, null);
      }
      extraBytes = Base64.decode(st.nextToken());
      return new KeyParts(rKey, cKey, extraBytes);
    } catch (IllegalBase64Exception e) {
      throw new MalformedURLException("Invalid Base64 quantity: " + e);
    }
  }

  /**
   * Construct a {@code USK} from components.
   *
   * @param pubKeyHash Public key hash (pkHash) used as the routing key (length may vary for
   *     insertable USKs).
   * @param cryptoKey Crypto key bytes, when provided must be 32 bytes.
   * @param extra Extra parameter bytes for USK.
   * @param siteName Site name (document name).
   * @param suggestedEdition2 Suggested edition number.
   * @throws IllegalArgumentException if {@code cryptoKey} is non-null and not 32 bytes.
   */
  public FreenetURI(
      byte[] pubKeyHash, byte[] cryptoKey, byte[] extra, String siteName, long suggestedEdition2) {
    // Construct USK from components
    this.keyType = "USK";
    this.routingKey = pubKeyHash;
    // Don't check routingKey as it could be an insertable USK
    this.cryptoKey = cryptoKey;
    if (cryptoKey != null && cryptoKey.length != 32)
      throw new IllegalArgumentException("Bad URI: Crypto key should be 32 bytes");
    this.extra = extra;
    this.docName = siteName;
    this.suggestedEdition = suggestedEdition2;
    metaStr = null;
    if (LOG.isDebugEnabled()) LOG.debug("Created from components (USK): {}", this);
  }

  /**
   * No-arg constructor for serialization frameworks only.
   *
   * <p>Not intended for direct use.
   */
  FreenetURI() {
    // For serialization only.
    this.metaStr = null;
    this.keyType = null;
    this.routingKey = null;
    this.cryptoKey = null;
    this.extra = null;
    this.docName = null;
    this.suggestedEdition = 0;
  }

  /**
   * Return the "guessable" part of the key, currently the document name.
   *
   * <p>Provided for compatibility with older code that used the term "guessable key".
   *
   * @return The document name, or {@code null} when absent.
   */
  @SuppressWarnings("unused")
  public String getGuessableKey() {
    return getDocName();
  }

  /**
   * Get the document name. For a KSK this is everything from the @ to the first slash or the end of
   * the key. For an SSK this is everything from the slash to the next slash or the end of the key.
   * CHKs don't have a doc name, they only have meta-strings.
   */
  public String getDocName() {
    return docName;
  }

  /**
   * Get the first meta-string. This is just after the main part of the key and the doc name.
   * Meta-strings are directory (manifest) lookups delimited by /'es after the main key and the doc
   * name, if any.
   */
  @SuppressWarnings("unused")
  public String getMetaString() {
    return ((metaStr == null) || (metaStr.length == 0)) ? null : metaStr[0];
  }

  /**
   * Get the last meta-string. Meta-strings are directory (manifest) lookups after the main key and
   * the doc name, if any. So the last meta-string, if there is one, is from the last / to the end
   * of the uri, i.e., usually the filename.
   */
  public String lastMetaString() {
    return ((metaStr == null) || (metaStr.length == 0)) ? null : metaStr[metaStr.length - 1];
  }

  /**
   * Get all the meta-strings. Meta-strings are directory (manifest) lookups after the main key and
   * the doc name, if any. Examples:
   *
   * <p>CHK@blah,blah,blah/filename
   *
   * <p>This has a routing key, a crypto key, extra bytes, no document name, and one meta string
   * "filename"
   *
   * <p>SSK@blah,blah,blah/docname/dir/subdir/filename
   *
   * <p>This has a routing key, a crypto key, extra bytes, a document name, and three meta strings
   * "dir", "subdir" and "filename". The SSK including the docname is turned into a low-level
   * Freenet key, which we fetch. This will produce a metadata document containing a manifest,
   * within which we look up "dir". This either gives us another metadata document directly or a
   * redirect if the dir is inserted separately. And so on. If it's a container, the files will be
   * stored, with the metadata, in the container (tar.bz2 or whatever); the metadata fetched by
   * SSK@blah,blah,blah/docname will say that there is a container and explain how to fetch it.
   *
   * <p>KSK@gpl.txt
   *
   * <p>This has no routing key, no crypto key, and no meta-strings (but KSKs *can* have
   * meta-strings), but it has a document name.
   */
  public String[] getAllMetaStrings() {
    return metaStr;
  }

  /** Are there any meta-strings? */
  public boolean hasMetaStrings() {
    return !(metaStr == null || metaStr.length == 0);
  }

  /**
   * Get the routing key. This is the first part of the key after the @ for CHKs, SSKs, and USKs.
   * For purposes of FreenetURI, KSKs do not have a routing key. For CHKs, this is ultimately
   * derived from the hash of the encrypted data; for SSKs it is the hash of the public key.
   */
  public byte[] getRoutingKey() {
    return routingKey;
  }

  /**
   * Get the crypto key. This is the second part of the key after the @ for CHKs, SSKs, and USKs.
   * For purposes of FreenetURI, KSKs do not have a crypto key. For CHKs, this is derived from the
   * hash of the *original* plaintext data; for SSKs it is a separate key for decryption. The crypto
   * key is kept on the requesting node and is not sent over the network - but of course many
   * freesites and other documents on the network include URIs which do include crypto keys.
   */
  public byte[] getCryptoKey() {
    return cryptoKey;
  }

  /** Get the key type. CHK, SSK, KSK, or USK. Upper case, we normally use the constants. */
  public String getKeyType() {
    return keyType;
  }

  /** Returns a copy of this URI with the first meta string removed. */
  public FreenetURI popMetaString() {
    String[] newMetaStr = null;
    if (metaStr != null) {
      final int metaStrLength = metaStr.length;
      if (metaStrLength > 1) {
        newMetaStr = Arrays.copyOf(metaStr, metaStr.length - 1);
      }
    }
    return setMetaString(newMetaStr);
  }

  /**
   * Create a new URI with the last few meta-strings dropped.
   *
   * @param i The number of meta-strings to drop.
   * @return A new FreenetURI with the specified number of meta-strings removed from the end.
   */
  public FreenetURI dropLastMetaStrings(int i) {
    String[] newMetaStr = null;
    if ((metaStr != null) && (metaStr.length > i)) {
      newMetaStr = Arrays.copyOf(metaStr, metaStr.length - i);
    }
    return setMetaString(newMetaStr);
  }

  /** Returns a copy of this URI with the given string appended as a meta-string. */
  public FreenetURI pushMetaString(String name) {
    String[] newMetaStr;
    if (name == null) throw new NullPointerException();
    if (metaStr == null) newMetaStr = new String[] {name};
    else {
      newMetaStr = Arrays.copyOf(metaStr, metaStr.length + 1);
      newMetaStr[metaStr.length] = name.intern();
    }
    return setMetaString(newMetaStr);
  }

  /** Returns a copy of this URI with these meta-strings appended. */
  public FreenetURI addMetaStrings(String[] strs) {
    if (strs == null) return this; // legal noop, since getMetaStrings can return null
    for (int i = 0; i < strs.length; i++)
      if (strs[i] == null)
        throw new NullPointerException("element " + i + " of " + strs.length + " is null");
    String[] newMetaStr;
    if (metaStr == null) return setMetaString(strs);
    else {
      newMetaStr = Arrays.copyOf(metaStr, metaStr.length + strs.length);
      System.arraycopy(strs, 0, newMetaStr, metaStr.length, strs.length);
      return setMetaString(newMetaStr);
    }
  }

  /** Returns a copy of this URI with these meta-strings appended. */
  public FreenetURI addMetaStrings(List<String> metaStrings) {
    return addMetaStrings(metaStrings.toArray(new String[0]));
  }

  /** Returns a copy of this URI with a new Document name set. */
  public FreenetURI setDocName(String name) {
    return new FreenetURI(keyType, name, metaStr, routingKey, cryptoKey, extra, suggestedEdition);
  }

  /** Returns a copy of this URI with new meta-strings. */
  public FreenetURI setMetaString(String[] newMetaStr) {
    return new FreenetURI(
        keyType, docName, newMetaStr, routingKey, cryptoKey, extra, suggestedEdition);
  }

  String toStringCache;

  /**
   * Return a cached string representation.
   *
   * <p>Equivalent to {@link #toString(boolean, boolean) toString(false, false)}. The result is
   * cached for repeated calls since URIs are immutable.
   */
  @Override
  public String toString() {
    if (toStringCache == null)
      toStringCache = toString(false, false) /* + "#"+super.toString()+"#"+uniqueHashCode*/;
    return toStringCache;
  }

  /**
   * Get the URI as a pure ASCII string.
   *
   * <p>All non-ASCII characters and reserved path characters are percent-encoded.
   *
   * @return The ASCII-only representation suitable for transport in ASCII-only contexts.
   */
  public String toASCIIString() {
    return toString(true, true);
  }

  /**
   * Get the URI as a string with configurable prefix and encoding.
   *
   * @param prefix If {@code true}, include the {@code freenet:} prefix.
   * @param pureAscii If {@code true}, percent-encode all non-ASCII characters. If {@code false},
   *     encode only characters that would otherwise break the path (e.g., slashes).
   * @return The string form of the URI.
   */
  public String toString(boolean prefix, boolean pureAscii) {
    if (keyType == null) {
      if (LOG.isDebugEnabled()) LOG.debug("Not activated?? in toString({},{})", prefix, pureAscii);
      return null;
    }
    StringBuilder b = prefix ? new StringBuilder("freenet:") : new StringBuilder();
    b.append(keyType).append('@');
    appendNonKskParts(b);
    appendDocAndEdition(b, pureAscii);
    appendMetaStrings(b, pureAscii);
    return b.toString();
  }

  private void appendNonKskParts(StringBuilder b) {
    if (!"KSK".equals(keyType)) {
      if (routingKey != null) b.append(Base64.encode(routingKey));
      if (cryptoKey != null) b.append(',').append(Base64.encode(cryptoKey));
      if (extra != null) b.append(',').append(Base64.encode(extra));
      if (docName != null) b.append('/');
    }
  }

  private void appendDocAndEdition(StringBuilder b, boolean pureAscii) {
    if (docName != null) b.append(URLEncoder.encode(docName, "/", pureAscii));
    if ("USK".equals(keyType)) {
      b.append('/').append(suggestedEdition);
    }
  }

  private void appendMetaStrings(StringBuilder b, boolean pureAscii) {
    if (metaStr == null) return;
    for (String s : metaStr) {
      b.append('/').append(URLEncoder.encode(s, "/", pureAscii));
    }
  }

  /**
   * Encode to a user-friendly, incomplete string with ... replacing some of the base64. Allow
   * spaces, foreign chars, etc.
   */
  public String toShortString() {
    StringBuilder b = new StringBuilder();

    b.append(keyType).append('@');

    if (!"KSK".equals(keyType)) {
      b.append("...");
      if (docName != null) b.append('/');
    }

    if (docName != null) b.append(URLEncoder.encode(docName, "/", false, " "));
    if (keyType.equals("USK")) {
      b.append('/');
      b.append(suggestedEdition);
    }
    if (metaStr != null)
      for (String s : metaStr) {
        b.append('/').append(URLEncoder.encode(s, "/", false, " "));
      }
    return b.toString();
  }

  /**
   * Get the extra parameter bytes.
   *
   * <p>For {@code SSK} and {@code CHK}, the bytes follow the second comma in the string form and
   * encode algorithm/mode choices and related parameters.
   *
   * @return The extra bytes, or {@code null} if not present.
   */
  public byte[] getExtra() {
    return extra;
  }

  /**
   * Get the meta-strings as a mutable list.
   *
   * @return A new list containing the meta-strings in order; never {@code null}.
   */
  public List<String> listMetaStrings() {
    if (metaStr != null) {
      ArrayList<String> l = new ArrayList<>(metaStr.length);
      Collections.addAll(l, metaStr);
      return l;
    } else return new ArrayList<>(0);
  }

  static final byte CHK = 1;
  static final byte SSK = 2;
  static final byte KSK = 3;

  @SuppressWarnings("unused")
  static final byte USK = 4;

  /**
   * Read a binary key preceded by a 16-bit length.
   *
   * <p>The payload format is equivalent to that read by {@link
   * #readFullBinaryKey(DataInputStream)}.
   *
   * @param dis Source stream.
   * @return The decoded URI.
   * @throws IOException On I/O errors or malformed input.
   */
  public static FreenetURI readFullBinaryKeyWithLength(DataInputStream dis) throws IOException {
    int len = dis.readShort();
    byte[] buf = new byte[len];
    dis.readFully(buf);
    if (LOG.isDebugEnabled()) LOG.debug("Read {} bytes for key", len);
    return fromFullBinaryKey(buf);
  }

  /**
   * Create a URI from its binary encoding.
   *
   * @param buf The binary encoding (without a preceding length).
   * @return The decoded URI.
   * @throws IOException If the buffer could not be parsed.
   */
  public static FreenetURI fromFullBinaryKey(byte[] buf) throws IOException {
    ByteArrayInputStream bais = new ByteArrayInputStream(buf);
    DataInputStream dis = new DataInputStream(bais);
    return readFullBinaryKey(dis);
  }

  private static int extraLengthForBinaryKeyType(byte type) {
    return switch (type) {
      case CHK -> chkExtraLength();
      case SSK -> sskExtraLength();
      default -> throw new IllegalArgumentException("Unsupported key type " + type);
    };
  }

  private static int chkExtraLength() {
    return ClientCHK.EXTRA_LENGTH;
  }

  private static int sskExtraLength() {
    return ClientSSK.EXTRA_LENGTH;
  }

  /**
   * Read a URI from its binary encoding (no length prefix).
   *
   * <p>Format:
   *
   * <ul>
   *   <li>1 byte type: {@code 1=CHK}, {@code 2=SSK}, {@code 3=KSK}
   *   <li>For {@code CHK}/{@code SSK}: 32 bytes routing key, 32 bytes crypto key, then
   *       type-specific {@code extra} bytes
   *   <li>{@code docName} as {@link DataInputStream#readUTF()}
   *   <li>{@code metaStr} as {@code int count} followed by {@code count} UTF strings
   * </ul>
   *
   * @param dis Source stream.
   * @return The decoded URI.
   * @throws MalformedURLException If the data is inconsistent or uses an unknown type.
   * @throws IOException If a read error occurs.
   */
  public static FreenetURI readFullBinaryKey(DataInputStream dis) throws IOException {
    byte type = dis.readByte();
    String keyType =
        switch (type) {
          case CHK -> "CHK";
          case SSK -> "SSK";
          case KSK -> "KSK";
          default -> throw new MalformedURLException("Unrecognized type " + type);
        };
    byte[] routingKey = null;
    byte[] cryptoKey = null;
    byte[] extra = null;
    if ((type == CHK) || (type == SSK)) {
      // routingKey is a hash, so is exactly 32 bytes
      routingKey = new byte[32];
      dis.readFully(routingKey);
      // cryptoKey is a 256-bit AES key, so likewise
      cryptoKey = new byte[32];
      dis.readFully(cryptoKey);
      // The number of bytes of extra depends on the key type
      int extraLen = extraLengthForBinaryKeyType(type);
      extra = new byte[extraLen];
      dis.readFully(extra);
    }
    String docName = null;
    if (type != CHK) docName = dis.readUTF();
    int count = dis.readInt();
    String[] metaStrings = new String[count];
    for (int i = 0; i < metaStrings.length; i++) metaStrings[i] = dis.readUTF();
    return new FreenetURI(keyType, docName, metaStrings, routingKey, cryptoKey, extra);
  }

  /**
   * Write a nullable URI with a 16-bit length prefix.
   *
   * <p>When {@code uri} is {@code null}, writes a zero length. Otherwise, delegates to {@link
   * #writeFullBinaryKeyWithLength(DataOutputStream)}.
   *
   * @param uri The URI to write, or {@code null}.
   * @param dos Destination stream.
   * @throws IOException On I/O errors.
   */
  @SuppressWarnings("unused")
  public static void writeNullableFullBinaryKeyWithLength(FreenetURI uri, DataOutputStream dos)
      throws IOException {
    if (uri == null) dos.writeShort((short) 0);
    else uri.writeFullBinaryKeyWithLength(dos);
  }

  /**
   * Write this URI with a 16-bit length prefix.
   *
   * <p>The binary body is produced by {@link #writeFullBinaryKey(DataOutputStream)} and then
   * emitted with its length as a {@code short}. The total size must fit in 16 bits.
   *
   * @param dos Destination stream.
   * @throws MalformedURLException If internal invariants are violated (e.g., wrong key lengths).
   * @throws IOException If an I/O error occurs.
   */
  public void writeFullBinaryKeyWithLength(DataOutputStream dos) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream ndos = new DataOutputStream(baos);
    writeFullBinaryKey(ndos);
    ndos.close();
    byte[] data = baos.toByteArray();
    if (data.length > Short.MAX_VALUE)
      throw new MalformedURLException("Full key too long: " + data.length + " - " + this);
    dos.writeShort((short) data.length);
    if (LOG.isDebugEnabled()) LOG.debug("Written {} bytes", data.length);
    dos.write(data);
  }

  /**
   * Write the binary body of this URI (no length prefix).
   *
   * @param dos Destination stream.
   * @throws MalformedURLException If the key cannot be written due to inconsistent or invalid
   *     fields.
   * @throws IOException If an I/O error occurs.
   */
  private void writeFullBinaryKey(DataOutputStream dos) throws IOException {
    writeTypeByteOrThrow(dos);
    if (!"KSK".equals(keyType)) {
      writeRoutingAndCryptoAndExtra(dos);
    }
    if (!"CHK".equals(keyType)) dos.writeUTF(docName);
    if (metaStr != null) {
      dos.writeInt(metaStr.length);
      for (String s : metaStr) dos.writeUTF(s);
    } else {
      dos.writeInt(0);
    }
  }

  private void writeTypeByteOrThrow(DataOutputStream dos) throws IOException {
    switch (keyType) {
      case "CHK" -> dos.writeByte(CHK);
      case "SSK" -> dos.writeByte(SSK);
      case "KSK" -> dos.writeByte(KSK);
      case "USK" -> throw new MalformedURLException("Cannot write USKs as binary keys");
      default ->
          throw new MalformedURLException(
              "Cannot write key of type " + keyType + " - do not know how");
    }
  }

  private void writeRoutingAndCryptoAndExtra(DataOutputStream dos) throws IOException {
    if (routingKey.length != 32)
      throw new MalformedURLException("Routing key must be of length 32");
    dos.write(routingKey);
    if (cryptoKey.length != 32) throw new MalformedURLException("Crypto key must be of length 32");
    dos.write(cryptoKey);
    if ("CHK".equals(keyType) && (extra.length != ClientCHK.EXTRA_LENGTH))
      throw new MalformedURLException("Wrong number of extra bytes for CHK");
    if ("SSK".equals(keyType) && (extra.length != ClientSSK.EXTRA_LENGTH))
      throw new MalformedURLException("Wrong number of extra bytes for SSK");
    dos.write(extra);
  }

  /**
   * Get the suggested edition (only valid for {@code USK}).
   *
   * @return The suggested edition.
   * @throws IllegalArgumentException if this URI is not a {@code USK}.
   */
  public long getSuggestedEdition() {
    if (keyType.equals("USK")) return suggestedEdition;
    else throw new IllegalArgumentException("Not a USK requesting suggested edition");
  }

  /**
   * Generate a suggested, sanitized filename for this URI.
   *
   * <p>The name is derived from relevant parts (e.g., document name, USK edition, and meta-string
   * segments). The result is already passed through {@link FileUtil#sanitize(String)}.
   *
   * @return A non-empty sanitized name when available; otherwise a fallback such as the Base64
   *     routing key or {@code "unknown"}.
   */
  public String getPreferredFilename() {
    if (LOG.isDebugEnabled()) LOG.debug("Getting preferred filename for {}", this);
    ArrayList<String> names = new ArrayList<>();
    collectBaseNames(names);
    appendMetaNames(names);
    String joined = buildSanitizedJoined(names);
    if (LOG.isDebugEnabled()) LOG.debug("out = {}", joined);
    if (joined.isEmpty()) {
      if (routingKey != null) {
        if (LOG.isDebugEnabled()) LOG.debug("Returning base64 encoded routing key");
        return Base64.encode(routingKey);
      }
      return "unknown"; // localize in a wrapper if needed
    }
    assert joined.equals(FileUtil.sanitize(joined))
        : ("Not sanitized? \"" + joined + "\" -> \"" + FileUtil.sanitize(joined)) + "\"";
    return joined;
  }

  private void collectBaseNames(List<String> names) {
    if (keyType == null) return;
    if (!("KSK".equals(keyType) || "SSK".equals(keyType) || "USK".equals(keyType))) return;
    if (LOG.isDebugEnabled()) LOG.debug("Adding docName: {}", docName);
    if (docName != null) {
      names.add(docName);
      if ("USK".equals(keyType)) names.add(Long.toString(suggestedEdition));
    } else if (!"SSK".equals(keyType)) {
      // "SSK@" is legal for an upload.
      throw new IllegalStateException("No docName for key of type " + keyType);
    }
  }

  private void appendMetaNames(List<String> names) {
    if (metaStr == null) return;
    for (String s : metaStr) {
      if (s == null || s.isEmpty()) {
        if (LOG.isDebugEnabled()) LOG.debug("metaString \"{}\": was null or empty", s);
        continue;
      }
      if (LOG.isDebugEnabled()) LOG.debug("Adding metaString \"{}\"", s);
      names.add(s);
    }
  }

  private static String buildSanitizedJoined(List<String> names) {
    StringBuilder out = new StringBuilder();
    for (String raw : names) {
      String s = FileUtil.sanitize(raw);
      if (!s.isEmpty()) {
        if (!out.isEmpty()) out.append('-');
        out.append(s);
      }
    }
    return out.toString();
  }

  /** Return a new URI with an updated suggested edition (for {@code USK}). */
  public FreenetURI setSuggestedEdition(long newEdition) {
    return new FreenetURI(keyType, docName, metaStr, routingKey, cryptoKey, extra, newEdition);
  }

  /** Return a new URI with a different key type. Usually invalid for production use. */
  public FreenetURI setKeyType(String newKeyType) {
    return new FreenetURI(
        newKeyType, docName, metaStr, routingKey, cryptoKey, extra, suggestedEdition);
  }

  /** Return a new URI with a different routing key. {@code KSK} does not use a routing key. */
  public FreenetURI setRoutingKey(byte[] newRoutingKey) {
    return new FreenetURI(
        keyType, docName, metaStr, newRoutingKey, cryptoKey, extra, suggestedEdition);
  }

  /**
   * Throw an InsertException if we have any meta-strings. They are not valid for inserts, you must
   * insert a directory to create a directory structure.
   */
  public void checkInsertURI() throws InsertException {
    if (metaStr != null && metaStr.length > 0)
      throw new InsertException(InsertExceptionMode.META_STRINGS_NOT_SUPPORTED, this);
  }

  /**
   * Throw an InsertException if the argument has any meta-strings. They are not valid for inserts,
   * you must insert a directory to create a directory structure.
   */
  @SuppressWarnings("unused")
  public static void checkInsertURIOrThrow(FreenetURI uri) throws InsertException {
    uri.checkInsertURI();
  }

  /**
   * Convert to a relative {@link URI} (e.g., {@code /KSK@gpl.txt}).
   *
   * <p>Uses the single-argument {@link URI#URI(String)} constructor to preserve encoded slashes in
   * the path.
   */
  public URI toRelativeURI() throws URISyntaxException {
    // Single-argument constructor preserves encoded slashes and other escaped characters.
    return new URI('/' + toString(false, false));
  }

  /** Convert to a relative {@link URI} with a custom base path (not necessarily {@code /}). */
  public URI toURI(String basePath) throws URISyntaxException {
    return new URI(basePath + toString(false, false));
  }

  /** Is this key an SSK? */
  public boolean isSSK() {
    return "SSK".equals(keyType);
  }

  /** Is this key a USK? */
  public boolean isUSK() {
    return "USK".equals(keyType);
  }

  /** Is this key a CHK? */
  public boolean isCHK() {
    return "CHK".equals(keyType);
  }

  /** Is this key a KSK? */
  public boolean isKSK() {
    return "KSK".equals(keyType);
  }

  /**
   * Convert a USK into an SSK by appending "-" and the suggested edition to the document name and
   * changing the key type.
   */
  public FreenetURI sskForUSK() {
    if (!keyType.equalsIgnoreCase("USK")) throw new IllegalStateException();
    long edition = Math.abs(suggestedEdition);
    if (edition == Long.MIN_VALUE) edition = Long.MAX_VALUE;
    return new FreenetURI("SSK", docName + "-" + edition, metaStr, routingKey, cryptoKey, extra, 0);
  }

  private static final Pattern docNameWithEditionPattern;

  static {
    docNameWithEditionPattern = Pattern.compile(".*-(\\d+)");
  }

  /**
   * Test whether this {@code SSK} likely originated from {@link #sskForUSK()}.
   *
   * <p>Heuristic: the document name ends with a dash followed by a decimal edition number.
   */
  public boolean isSSKForUSK() {
    return keyType.equalsIgnoreCase("SSK")
        && docName != null
        && docNameWithEditionPattern.matcher(docName).matches();
  }

  /** Convert an {@code SSK} into a {@code USK}, if the document name encodes an edition. */
  public FreenetURI uskForSSK() {
    if (!keyType.equalsIgnoreCase("SSK")) throw new IllegalStateException();
    Matcher matcher = docNameWithEditionPattern.matcher(docName);
    if (!matcher.matches()) throw new IllegalStateException();

    int offset = matcher.start(1) - 1;
    String siteName = docName.substring(0, offset);
    long edition = Long.parseLong(docName.substring(offset + 1));

    return new FreenetURI("USK", siteName, metaStr, routingKey, cryptoKey, extra, edition);
  }

  /**
   * Get the edition number for {@code USK} or for an {@code SSK} that encodes an edition.
   *
   * @return The edition number.
   * @throws IllegalStateException if the key type does not encode an edition.
   */
  public long getEdition() {
    if (keyType.equalsIgnoreCase("USK")) return suggestedEdition;
    else if (keyType.equalsIgnoreCase("SSK")) {
      if (docName == null) throw new IllegalStateException();

      Matcher matcher = docNameWithEditionPattern.matcher(docName);
      if (!matcher
          .matches()) /* Taken from uskForSSK; consider keeping logic consistent with isSSKForUSK(). */
        throw new IllegalStateException();

      return Long.parseLong(docName.substring(matcher.start(1)));
    } else throw new IllegalStateException();
  }

  /**
   * Compare this URI to another for ordering.
   *
   * <p>The comparison short-circuits on key type, routing/crypto keys, document name, extra,
   * meta-segments, and suggested edition, in that order. While worst-case cost is non-trivial, in
   * practice most comparisons terminate quickly.
   */
  @Override
  public int compareTo(@NotNull FreenetURI o) {
    if (this == o) return 0;
    int cmp = keyType.compareTo(o.keyType);
    if (cmp != 0) return cmp;
    cmp = compareBytesNullable(routingKey, o.routingKey);
    if (cmp != 0) return cmp;
    cmp = compareBytesNullable(cryptoKey, o.cryptoKey);
    if (cmp != 0) return cmp;
    cmp = compareNullableStrings(docName, o.docName);
    if (cmp != 0) return cmp;
    cmp = compareBytesNullable(extra, o.extra);
    if (cmp != 0) return cmp;
    cmp = compareMeta(metaStr, o.metaStr);
    if (cmp != 0) return cmp;
    return Long.compare(suggestedEdition, o.suggestedEdition);
  }

  private static int compareBytesNullable(byte[] a, byte[] b) {
    if (a == null && b == null) return 0;
    if (a == null) return -1;
    if (b == null) return 1;
    return Fields.compareBytes(a, b);
  }

  private static int compareNullableStrings(String a, String b) {
    if (a == null && b == null) return 0;
    if (a == null) return -1;
    if (b == null) return 1;
    return a.compareTo(b);
  }

  private static int compareMeta(String[] a, String[] b) {
    if (a == null && b == null) return 0;
    if (a == null) return -1;
    if (b == null) return 1;
    if (a.length != b.length) return Integer.compare(a.length, b.length);
    for (int i = 0; i < a.length; i++) {
      int c = a[i].compareTo(b[i]);
      if (c != 0) return c;
    }
    return 0;
  }

  /**
   * If this object is a USK/SSK insert URI, this function computes the request URI which belongs to
   * it. If it is a CHK/KSK, the original URI is returned as CHK/KSK do not have a private insert
   * URI, they are their own "insert URI".
   *
   * <p>If you want to give people access to content at a URI, you should always publish only the
   * request URI. Never give away the insert URI, this allows anyone to insert under your URI!
   *
   * @return The request URI, which belongs to this insert URI.
   * @throws MalformedURLException If this object is a USK/SSK, request URI already. NOT thrown for
   *     CHK/KSK URIs!
   */
  public FreenetURI deriveRequestURIFromInsertURI() throws MalformedURLException {
    final FreenetURI originalURI = this;

    if (originalURI.isCHK()) {
      return originalURI;
    } else if (originalURI.isSSK() || originalURI.isUSK()) {
      FreenetURI newURI = originalURI;
      if (originalURI.isUSK()) newURI = newURI.sskForUSK();
      InsertableClientSSK issk = InsertableClientSSK.create(newURI);
      newURI = issk.getURI();
      if (originalURI.isUSK()) {
        newURI = newURI.uskForSSK();
        newURI = newURI.setSuggestedEdition(originalURI.getSuggestedEdition());
      }
      // docName will be preserved.
      // Any meta-strings *should not* be preserved.
      return newURI;
    } else if (originalURI.isKSK()) {
      return originalURI;
    } else {
      throw new IllegalArgumentException("Not implemented yet for this key type: " + getKeyType());
    }
  }

  /**
   * Comparator that orders URIs primarily by {@link #hashCode()} and falls back to {@link
   * #compareTo(FreenetURI)} to break ties.
   */
  public static final Comparator<FreenetURI> FAST_COMPARATOR =
      (uri0, uri1) -> {
        // Unfortunately the hashCode's may not have been computed yet.
        // But it's still cheaper to recompute them in the long run.
        int hash0 = uri0.hashCode();
        int hash1 = uri1.hashCode();
        if (hash0 > hash1) {
          return 1;
        } else if (hash1 > hash0) {
          return -1;
        }
        return uri0.compareTo(uri1);
      };

  /**
   * Generate a random, syntactically valid {@code CHK} URI for testing.
   *
   * @param rand Source of randomness.
   * @return A new {@code CHK} URI with random routing and crypto keys and a valid {@code extra}
   *     field.
   */
  public static FreenetURI generateRandomCHK(Random rand) {
    byte[] rkey = new byte[32];
    rand.nextBytes(rkey);
    byte[] ckey = new byte[32];
    rand.nextBytes(ckey);
    byte[] extra = ClientCHK.getExtra(Key.ALGO_AES_CTR_256_SHA256, (short) -1, false);
    return new FreenetURI("CHK", null, rkey, ckey, extra);
  }

  // Potential extension: add an isUpdatable() convenience method that returns true for USK or
  // SSK converted from USK. Keep as a future consideration to avoid API churn now.
}
