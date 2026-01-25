package network.crypta.client.filter;

import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import network.crypta.client.filter.CharsetExtractor.BOMDetection;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Central coordinator for client-side content filtering.
 *
 * <p>This class does not perform low-level parsing itself; instead it maintains a registry of
 * supported MIME types and dispatches incoming data to the appropriate {@link FilterMIMEType}
 * handler. For types that expose a read filter, it resolves an effective character set (when
 * applicable), invokes the filter implementation, and coordinates callbacks that report discovered
 * links or request tag substitutions. For safe, byte-oriented types with no dedicated filter, it
 * streams the bytes unchanged to the destination.
 *
 * <p>Typical usage is to call one of the {@code filter(...)} overloads with an input stream, an
 * output stream, the declared MIME type, and the request context. The method returns a small {@link
 * FilterStatus} value describing the effective MIME/charset so that callers can persist or surface
 * that information. All methods are static, and the internal registry is shared; the class is
 * thread-safe for concurrent use. Registration occurs at class initialization and may be extended
 * via {@link #register(FilterMIMEType)} at startup.
 *
 * <ul>
 *   <li>Maintains a mapping from MIME types to filter handlers.
 *   <li>Detects or inherits charsets for text-like types when not explicitly provided.
 *   <li>Guards against unsafe or unknown content types by raising descriptive exceptions.
 * </ul>
 *
 * @see FilterMIMEType
 * @see FilterCallback
 * @see FoundURICallback
 * @see HTMLFilter
 */
public class ContentFilter {
  private static final Logger LOG = LoggerFactory.getLogger(ContentFilter.class);

  // Charset family constants used in detection/normalization
  private static final String CHARSET_UTF16 = "UTF-16";
  private static final String CHARSET_UTF32 = "UTF-32";

  // Use a concurrent map to avoid a legacy synchronized Hashtable
  static final ConcurrentMap<String, FilterMIMEType> mimeTypesByName = new ConcurrentHashMap<>();

  /** The HTML mime types are defined here to allow other modules to identify it */
  protected static final String[] HTML_MIME_TYPES =
      new String[] {
        "text/html", "application/xhtml+xml", "text/xml+xhtml", "text/xhtml", "application/xhtml"
      };

  private ContentFilter() {}

  static {
    init();
  }

  /**
   * Initialize and (re)populate the registry of known MIME types.
   *
   * <p>The method registers core image, audio, markup, and container formats along with their
   * filter implementations and safety characteristics. It is safe to call more than once; later
   * invocations will overwrite existing mappings with the same primary or alternate type keys.
   * Typical applications rely on the static initializer to invoke this during class loading.
   */
  public static void init() {
    // Register known MIME types

    // Plain text
    register(
        new FilterMIMEType(
            new FilterMIMETypeNames(
                "text/plain", "txt", new String[0], new String[] {"text", "pot"}),
            new FilterMIMETypeSafety(true, true, null, l10n("textPlainReadAdvice")),
            new FilterMIMETypeDangerousFlags(false, false, false, false, false, false),
            new FilterMIMETypeCharsetPolicy(true, "US-ASCII", null, false)));

    // Images
    // GIF - has a filter
    register(
        new FilterMIMEType(
            new FilterMIMETypeNames("image/gif", "gif", new String[0], new String[0]),
            new FilterMIMETypeSafety(true, false, new GIFFilter(), l10n("imageGifReadAdvice")),
            new FilterMIMETypeDangerousFlags(false, false, false, false, false, false),
            new FilterMIMETypeCharsetPolicy(false, null, null, false)));

    // JPEG - has a filter
    register(
        new FilterMIMEType(
            new FilterMIMETypeNames("image/jpeg", "jpeg", new String[0], new String[] {"jpg"}),
            new FilterMIMETypeSafety(
                true, false, new JPEGFilter(true, true), l10n("imageJpegReadAdvice")),
            new FilterMIMETypeDangerousFlags(false, false, false, false, false, false),
            new FilterMIMETypeCharsetPolicy(false, null, null, false)));

    // PNG - has a filter
    register(
        new FilterMIMEType(
            new FilterMIMETypeNames(
                "image/png", "png", new String[] {"image/x-png"}, new String[0]),
            new FilterMIMETypeSafety(
                true, false, new PNGFilter(true, true, true), l10n("imagePngReadAdvice")),
            new FilterMIMETypeDangerousFlags(false, false, false, false, true, false),
            new FilterMIMETypeCharsetPolicy(false, null, null, false)));

    // BMP - has a filter
    // Reference: http://filext.com/file-extension/BMP
    register(
        new FilterMIMEType(
            new FilterMIMETypeNames(
                "image/bmp",
                "bmp",
                new String[] {
                  "image/x-bmp",
                  "image/x-bitmap",
                  "image/x-xbitmap",
                  "image/x-win-bitmap",
                  "image/x-windows-bmp",
                  "image/ms-bmp",
                  "image/x-ms-bmp",
                  "application/bmp",
                  "application/x-bmp",
                  "application/x-win-bitmap"
                },
                new String[0]),
            new FilterMIMETypeSafety(true, false, new BMPFilter(), l10n("imageBMPReadAdvice")),
            new FilterMIMETypeDangerousFlags(false, false, false, false, true, false),
            new FilterMIMETypeCharsetPolicy(false, null, null, false)));

    // WEBP - has a filter
    register(
        new FilterMIMEType(
            new FilterMIMETypeNames(
                "image/webp", "webp", new String[] {"image/webp"}, new String[0]),
            new FilterMIMETypeSafety(true, false, new WebPFilter(), l10n("imageWebPReadAdvice")),
            new FilterMIMETypeDangerousFlags(false, false, false, false, true, false),
            new FilterMIMETypeCharsetPolicy(false, null, null, false)));

    // Audio
    /* Ogg - has a filter
     * Xiph's container format. Contains one or more logical bitstreams.
     * Each type of bitstream will likely require additional processing,
     * on top of that needed for the Ogg container itself.
     * Reference: http://xiph.org/ogg/doc/rfc3533.txt
     */
    register(
        new FilterMIMEType(
            new FilterMIMETypeNames(
                "application/ogg",
                "ogx",
                new String[] {"video/ogg", "audio/ogg"},
                new String[] {"ogg", "oga", "ogv"}),
            new FilterMIMETypeSafety(true, false, new OggFilter(), l10n("containerOggReadAdvice")),
            new FilterMIMETypeDangerousFlags(true, true, false, true, false, false),
            new FilterMIMETypeCharsetPolicy(false, null, null, false)));

    /* FLAC - has a filter
     * Lossless audio format. This data is sometimes encapsulated inside
     * ogg containers. It is, however, not currently supported and
     * is very dangerous, as it may specify URLs from which album art
     * will be downloaded from
     */
    register(
        new FilterMIMEType(
            new FilterMIMETypeNames(
                "audio/flac", "flac", new String[] {"application/x-flac"}, new String[0]),
            new FilterMIMETypeSafety(true, true, new FlacFilter(), l10n("audioFLACReadAdvice")),
            new FilterMIMETypeDangerousFlags(true, true, false, true, false, false),
            new FilterMIMETypeCharsetPolicy(false, null, null, false)));

    // M3U - strict filter
    register(
        new FilterMIMEType(
            new FilterMIMETypeNames(
                "audio/mpegurl",
                "m3u",
                new String[] {
                  "application/vnd.apple.mpegurl",
                  "application/mpegurl",
                  "application/x-mpegurl",
                  "audio/x-mpegurl"
                },
                new String[] {"m3u8"}),
            new FilterMIMETypeSafety(false, false, new M3UFilter(), l10n("audioM3UReadAdvice")),
            new FilterMIMETypeDangerousFlags(false, false, false, false, false, false),
            new FilterMIMETypeCharsetPolicy(false, "utf-8", null, false)));

    /* MP3
     *
     * Reference: http://www.mp3-tech.org/programmer/frame_header.html
     */
    register(
        new FilterMIMEType(
            new FilterMIMETypeNames(
                "audio/mpeg",
                "mp3",
                new String[] {
                  "audio/mp3",
                  "audio/x-mp3",
                  "audio/x-mpeg",
                  "audio/mpeg3",
                  "audio/x-mpeg3",
                  "audio/mpg",
                  "audio/x-mpg",
                  "audio/mpegaudio"
                },
                new String[0]),
            new FilterMIMETypeSafety(true, false, new MP3Filter(), l10n("audioMP3ReadAdvice")),
            new FilterMIMETypeDangerousFlags(true, true, false, true, false, false),
            new FilterMIMETypeCharsetPolicy(false, null, null, false)));

    // WAV - has a filter
    register(
        new FilterMIMEType(
            new FilterMIMETypeNames(
                "audio/vnd.wave",
                "wav",
                new String[] {"audio/x-wav", "audio/wav", "audio/wave"},
                new String[0]),
            new FilterMIMETypeSafety(true, true, new WAVFilter(), l10n("audioWAVReadAdvice")),
            new FilterMIMETypeDangerousFlags(false, false, false, false, false, false),
            new FilterMIMETypeCharsetPolicy(false, null, null, false)));

    // ICO needs filtering.
    // Format is not the same as BMP iirc.
    // DoS: http://www.kb.cert.org/vuls/id/290961
    // Remote code exec: http://www.microsoft.com/technet/security/bulletin/ms09-062.mspx

    // ICO is not currently handled; a dedicated filter may be added later.

    // PDF - very dangerous - ideally we would have a filter as this is a very common format.
    register(
        new FilterMIMEType(
            new FilterMIMETypeNames(
                "application/pdf", "pdf", new String[] {"application/x-pdf"}, new String[0]),
            new FilterMIMETypeSafety(false, false, null, l10n("applicationPdfReadAdvice")),
            new FilterMIMETypeDangerousFlags(true, true, true, false, true, true),
            new FilterMIMETypeCharsetPolicy(false, null, null, false)));

    // HTML - dangerous if not filtered
    register(
        new FilterMIMEType(
            new FilterMIMETypeNames(
                HTML_MIME_TYPES[0],
                "html",
                Arrays.copyOfRange(HTML_MIME_TYPES, 1, HTML_MIME_TYPES.length),
                new String[] {"htm"}),
            new FilterMIMETypeSafety(
                false, false /* maybe? */, new HTMLFilter(), l10n("textHtmlReadAdvice")),
            new FilterMIMETypeDangerousFlags(true, true, true, true, true, true),
            new FilterMIMETypeCharsetPolicy(true, "iso-8859-1", new HTMLFilter(), false)));

    // CSS - dangerous if not filtered, not sure about the filter
    register(
        new FilterMIMEType(
            new FilterMIMETypeNames("text/css", "css", new String[0], new String[0]),
            new FilterMIMETypeSafety(
                false, false /* unknown */, new CSSReadFilter(), l10n("textCssReadAdvice")),
            new FilterMIMETypeDangerousFlags(true, true, true, true, true, false),
            new FilterMIMETypeCharsetPolicy(true, "utf-8", new CSSReadFilter(), true)));
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("ContentFilter." + key);
  }

  /**
   * Register a {@link FilterMIMEType} under its primary and alternate names.
   *
   * <p>This associates the supplied handler with its {@code primaryMimeType} and any alternate
   * types so that later lookups via {@link #getMIMEType(String)} resolve to the same object.
   * Registration is idempotent with respect to keys; an existing mapping will be replaced.
   *
   * @param mimeType the handler describing capabilities, defaults, and filters for a MIME type; may
   *     not be {@code null}
   */
  public static void register(FilterMIMEType mimeType) {
    synchronized (mimeTypesByName) {
      mimeTypesByName.put(mimeType.primaryMimeType, mimeType);
      String[] alt = mimeType.alternateMimeTypes;
      if (alt != null) {
        for (String a : alt) mimeTypesByName.put(a, mimeType);
      }
    }
  }

  /**
   * Strip parameters from a MIME type string and return only the base type.
   *
   * <p>For example, {@code "text/html; charset=utf-8"} becomes {@code "text/html"}. Leading and
   * trailing whitespace is trimmed from the result. When the input is {@code null}, the method
   * returns {@code null}.
   *
   * @param mimeType a MIME type possibly containing {@code ;}-separated parameters; may be {@code
   *     null}
   * @return the base MIME type without parameters, or {@code null} when the input was {@code null}
   */
  public static String stripMIMEType(String mimeType) {
    if (mimeType == null) return null;
    int x;
    if ((x = mimeType.indexOf(';')) != -1) {
      mimeType = mimeType.substring(0, x).trim();
    }
    return mimeType;
  }

  /**
   * Look up a registered {@link FilterMIMEType} by name.
   *
   * <p>The name may include parameters; they are ignored using {@link #stripMIMEType(String)}
   * before lookup. The method returns {@code null} if the type is not known to the registry.
   *
   * @param mimeType primary or alternate MIME type name, optionally with parameters
   * @return the registered handler for the base type, or {@code null} if no mapping exists
   */
  public static FilterMIMEType getMIMEType(String mimeType) {
    if (mimeType == null) return null;
    return mimeTypesByName.get(stripMIMEType(mimeType));
  }

  /**
   * Filter content from an input stream and write the sanitized result to an output stream.
   *
   * <p>This legacy overload is retained for source compatibility. Prefer {@link
   * #filter(ContentFilterRequest, ContentFilterCallbacks)}.
   *
   * <p>The method chooses a handler based on {@code typeName}, resolves an effective charset when
   * needed, and invokes the handler's read filter. During processing, it may report discovered
   * links through {@code cb} and perform tag substitutions via {@code trc}. When the MIME type is
   * safe to read as-is and has no filter, the bytes are copied unchanged. The returned status
   * conveys the effective charset and MIME type observed for the stream.
   *
   * @param input source stream providing the original bytes; must remain readable for the duration
   *     of filtering; not closed by this method
   * @param output destination stream receiving filtered bytes; the method flushes but does not
   *     close it
   * @param typeName declared MIME type of {@code input}; parameters are allowed and will be parsed
   * @param baseURI base URI used to resolve relative references discovered during filtering
   * @param schemeHostAndPort request authority (scheme, host, and port) for same-origin checks and
   *     rewriting decisions
   * @param cb callback notified for each discovered URI; may be {@code null} to ignore discoveries
   * @param trc callback used to replace or rewrite markup tokens when supported by the handler; may
   *     be {@code null}
   * @param maybeCharset hint inherited from a referring document; used when the handler allows
   *     charset inference and no BOM or explicit declaration is present; may be {@code null}
   * @return a {@link FilterStatus} carrying the effective charset and MIME type chosen during
   *     processing
   * @throws IOException on I/O errors while reading, writing, or decoding the stream; specific
   *     {@link UnsafeContentTypeException} subclasses may be used to classify unsafe types
   * @throws IllegalStateException when input is structurally invalid and the handler cannot recover
   */
  @SuppressWarnings("java:S107")
  public static FilterStatus filter(
      InputStream input,
      OutputStream output,
      String typeName,
      URI baseURI,
      String schemeHostAndPort,
      FoundURICallback cb,
      TagReplacerCallback trc,
      String maybeCharset)
      throws IOException {
    return filter(input, output, typeName, baseURI, schemeHostAndPort, cb, trc, maybeCharset, null);
  }

  /**
   * Filter content with an optional provider for link-related exceptions.
   *
   * <p>This legacy overload is retained for source compatibility. Prefer {@link
   * #filter(ContentFilterRequest, ContentFilterCallbacks)}.
   *
   * <p>This overload is identical to {@link #filter(InputStream, OutputStream, String, URI, String,
   * FoundURICallback, TagReplacerCallback, String)} but additionally accepts a provider that
   * produces rich exceptions for link filtering failures. The provider is passed to the internal
   * {@link GenericReadFilterCallback} implementation and may influence error detail surfaced to
   * callers.
   *
   * @param input source stream providing the original bytes; must remain readable for the duration
   *     of filtering; not closed by this method
   * @param output destination stream receiving filtered bytes; the method flushes but does not
   *     close it
   * @param typeName declared MIME type of {@code input}; parameters are allowed and will be parsed
   * @param baseURI base URI used to resolve relative references discovered during filtering
   * @param schemeHostAndPort request authority (scheme, host, and port) for same-origin checks and
   *     rewriting decisions
   * @param cb callback notified for each discovered URI; may be {@code null} to ignore discoveries
   * @param trc callback used to replace or rewrite markup tokens when supported by the handler; may
   *     be {@code null}
   * @param maybeCharset hint inherited from a referring document; used when the handler allows
   *     charset inference and no BOM or explicit declaration is present; may be {@code null}
   * @param linkFilterExceptionProvider provider for constructing link-filter exceptions; may be
   *     {@code null}
   * @return a {@link FilterStatus} carrying the effective charset and MIME type chosen during
   *     processing
   * @throws IOException on I/O errors while reading, writing, or decoding the stream; specific
   *     {@link UnsafeContentTypeException} subclasses may be used to classify unsafe types
   * @throws IllegalStateException when input is structurally invalid and the handler cannot recover
   */
  @SuppressWarnings("java:S107")
  public static FilterStatus filter(
      InputStream input,
      OutputStream output,
      String typeName,
      URI baseURI,
      String schemeHostAndPort,
      FoundURICallback cb,
      TagReplacerCallback trc,
      String maybeCharset,
      LinkFilterExceptionProvider linkFilterExceptionProvider)
      throws IOException {
    ContentFilterRequest request =
        new ContentFilterRequest(input, output, typeName, maybeCharset, schemeHostAndPort, null);
    ContentFilterCallbacks callbacks =
        new ContentFilterCallbacks(baseURI, cb, trc, linkFilterExceptionProvider);
    return filter(request, callbacks);
  }

  /**
   * Filter content with a structured request and callbacks.
   *
   * <p>This overload mirrors {@link #filter(ContentFilterRequest)} but derives the {@link
   * FilterCallback} from the provided {@link ContentFilterCallbacks}.
   *
   * @param request immutable filtering request data
   * @param callbacks callback bundle for link discovery and tag replacement; may be {@code null}
   * @return a {@link FilterStatus} carrying the effective charset and MIME type chosen during
   *     processing
   * @throws IOException on I/O errors while reading, writing, or decoding the stream; specific
   *     {@link UnsafeContentTypeException} subclasses may be used to classify unsafe types
   * @throws IllegalStateException when input is structurally invalid and the handler cannot recover
   */
  public static FilterStatus filter(ContentFilterRequest request, ContentFilterCallbacks callbacks)
      throws IOException {
    FilterCallback filterCallback = callbacks == null ? null : callbacks.toFilterCallback();
    return filter(request.withFilterCallback(filterCallback));
  }

  /**
   * Core filtering entry point used by higher-level overloads.
   *
   * <p>Parses {@code typeName}, determines the appropriate handler, resolves a charset when
   * applicable, and either runs the handler's read filter or copies the bytes unchanged when marked
   * safe. The callback receives lifecycle notifications and any discovered links. The output stream
   * is flushed before returning but is not closed.
   *
   * @param input source stream providing the original bytes; must remain readable for the duration
   *     of filtering; not closed by this method
   * @param output destination stream receiving filtered bytes; the method flushes but does not
   *     close it
   * @param typeName declared MIME type of {@code input}; parameters are allowed and will be parsed
   * @param maybeCharset hint inherited from a referring document; used when the handler allows
   *     charset inference and no BOM or explicit declaration is present; may be {@code null}
   * @param schemeHostAndPort request authority (scheme, host, and port) for same-origin checks and
   *     rewriting decisions
   * @param filterCallback callback for link discovery, tag replacement, and completion; may be
   *     {@code null}
   * @return a {@link FilterStatus} carrying the effective charset and MIME type chosen during
   *     processing
   * @throws IOException on I/O errors while reading, writing, or decoding the stream; specific
   *     {@link UnsafeContentTypeException} subclasses may be used to classify unsafe types
   * @throws IllegalStateException when input is structurally invalid and the handler cannot recover
   */
  public static FilterStatus filter(
      InputStream input,
      OutputStream output,
      String typeName,
      String maybeCharset,
      String schemeHostAndPort,
      FilterCallback filterCallback)
      throws IOException {
    return filter(
        new ContentFilterRequest(
            input, output, typeName, maybeCharset, schemeHostAndPort, filterCallback));
  }

  /**
   * Core filtering entry point used by higher-level overloads.
   *
   * <p>Parses {@link ContentFilterRequest#typeName()}, determines the appropriate handler, resolves
   * a charset when applicable, and either runs the handler's read filter or copies the bytes
   * unchanged when marked safe. The callback receives lifecycle notifications and any discovered
   * links. The output stream is flushed before returning but is not closed.
   *
   * @param request immutable request describing the input/output streams and filtering context
   * @return a {@link FilterStatus} carrying the effective charset and MIME type chosen during
   *     processing
   * @throws IOException on I/O errors while reading, writing, or decoding the stream; specific
   *     {@link UnsafeContentTypeException} subclasses may be used to classify unsafe types
   * @throws IllegalStateException when input is structurally invalid and the handler cannot recover
   */
  public static FilterStatus filter(ContentFilterRequest request) throws IOException {
    if (LOG.isDebugEnabled()) LOG.debug("Filtering data of type{}", request.typeName());
    ParsedMime parsed = parseMimeType(request.typeName());
    BufferedInputStream buffered = new BufferedInputStream(request.input());
    OutputStream output = request.output();

    FilterMIMEType handler = getMIMEType(parsed.type);
    if (handler == null) throw new UnknownContentTypeException(request.typeName());

    if (handler.readFilter != null) {
      String charset = parsed.charset;
      if (handler.takesACharset && (charset == null || charset.isEmpty())) {
        charset = readCharsetIfNeeded(buffered, handler, request.maybeCharset());
      }
      ReadFilterRequest readFilterRequest =
          new ReadFilterRequest(
              buffered,
              output,
              charset,
              parsed.otherParams,
              request.schemeHostAndPort(),
              request.filterCallback());
      return runReadFilter(handler, readFilterRequest, request.typeName());
    }

    if (handler.safeToRead) {
      FileUtil.copy(buffered, output, -1);
      output.flush();
      return new FilterStatus(parsed.charset, request.typeName());
    }

    handler.throwUnsafeContentTypeException();
    return null; // unreachable
  }

  /**
   * Determine the most appropriate charset for the given byte prefix and handler.
   *
   * <p>The decision follows this order: explicit BOM, handler-specific extraction logic, inherited
   * {@code maybeCharset} hint (when enabled by the handler), then the handler's default. Only the
   * first {@code length} bytes of {@code input} are considered.
   *
   * @param input a buffer containing the beginning of the resource; not modified by this method
   * @param length the number of valid bytes in {@code input} to examine; must be {@code >= 0}
   * @param handler MIME handler that supplies extractor logic and default charset; must not be
   *     {@code null}
   * @param maybeCharset optional inherited charset hint from a referring document; may be {@code
   *     null}
   * @return the selected charset name such as {@code "UTF-8"}, or {@code null} when the handler
   *     does not require a charset
   * @throws IOException when extractor logic fails due to malformed declarations or unsupported
   *     encodings
   */
  public static String detectCharset(
      byte[] input, int length, FilterMIMEType handler, String maybeCharset) throws IOException {
    String charset = detectBOM(input, length);
    // If a BOM indicates a specific endianness but the caller provided a
    // family charset (e.g., "UTF-16" or "UTF-32") via maybeCharset, prefer
    // the family name to preserve the caller's intent. This matches tests that
    // expect an inherited "UTF-16" hint to be reflected verbatim even when a
    // BOM is present (which remains compatible as "UTF-16" honors BOM).
    if (charset != null && maybeCharset != null && !maybeCharset.isEmpty()) {
      if (maybeCharset.equalsIgnoreCase(CHARSET_UTF16)
          && charset.regionMatches(true, 0, CHARSET_UTF16, 0, CHARSET_UTF16.length())) {
        return CHARSET_UTF16;
      }
      if (maybeCharset.equalsIgnoreCase(CHARSET_UTF32)
          && charset.regionMatches(true, 0, CHARSET_UTF32, 0, CHARSET_UTF32.length())) {
        return CHARSET_UTF32;
      }
    }
    if (charset == null && handler.charsetExtractor != null) {
      charset = detectWithExtractor(handler, input, length);
    }
    if (charset != null) return charset;
    if (handler.useMaybeCharset && maybeCharset != null && !maybeCharset.isEmpty()) {
      return maybeCharset;
    }
    return handler.defaultCharset;
  }

  private static String detectWithExtractor(FilterMIMEType handler, byte[] input, int length)
      throws IOException {
    CharsetExtractor extractor = handler.charsetExtractor;
    String fromBom = detectFromBom(extractor, input, length);
    if (fromBom != null) return fromBom;

    String def = detectFromDefault(extractor, handler.defaultCharset, input, length);
    if (def != null) return def;

    return detectFromCommon(extractor, input, length);
  }

  private static String detectFromBom(CharsetExtractor extractor, byte[] input, int length)
      throws IOException {
    BOMDetection bom = extractor.getCharsetByBOM(input, length);
    if (bom == null || bom.charset == null) return null;
    String v = tryGetCharset(extractor, input, length, bom.charset);
    if (v != null) {
      if (LOG.isDebugEnabled()) LOG.debug("Detected charset from BOM: {}", v);
      return v;
    }
    if (bom.mustHaveCharset) throw new UndetectableCharsetException(bom.charset);
    return null;
  }

  private static String detectFromDefault(
      CharsetExtractor extractor, String defaultCharset, byte[] input, int length)
      throws IOException {
    if (defaultCharset == null) return null;
    String v = tryGetCharset(extractor, input, length, defaultCharset);
    if (v != null && LOG.isDebugEnabled()) LOG.debug("Detected charset from default: {}", v);
    return v;
  }

  private static String detectFromCommon(CharsetExtractor extractor, byte[] input, int length)
      throws IOException {
    String[] candidates = {"ISO-8859-1", "UTF-8", CHARSET_UTF16, CHARSET_UTF32};
    for (String c : candidates) {
      String v = tryGetCharset(extractor, input, length, c);
      if (v != null) return v;
    }
    return null;
  }

  private static String tryGetCharset(
      CharsetExtractor extractor, byte[] input, int length, String candidate) throws IOException {
    try {
      return extractor.getCharset(input, length, candidate);
    } catch (UnsupportedEncodingException _) {
      if (LOG.isDebugEnabled()) LOG.debug("{} not supported", candidate);
      return null;
    } catch (UnknownCharsetException | DataFilterException _) {
      return null;
    }
  }

  private static ParsedMime parseMimeType(String typeName) {
    String type = typeName;
    String charset = null;
    HashMap<String, String> otherParams = new LinkedHashMap<>();
    int idx = type.indexOf(';');
    if (idx != -1) {
      String options = type.substring(idx + 1);
      type = type.substring(0, idx);
      String[] rawOpts = options.split(";");
      for (String raw : rawOpts) {
        int eq = raw.indexOf('=');
        if (eq == -1) {
          LOG.error("idx = -1 for '=' on option: {} from {}", raw, typeName);
          continue;
        }
        String before = raw.substring(0, eq).trim();
        String after = raw.substring(eq + 1).trim();
        if (before.equals("charset")) charset = after;
        else otherParams.put(before, after);
      }
    }
    return new ParsedMime(type, charset, otherParams);
  }

  private static String readCharsetIfNeeded(
      BufferedInputStream input, FilterMIMEType handler, String maybeCharset) throws IOException {
    int bufferSize = handler.charsetExtractor.getCharsetBufferSize();
    input.mark(bufferSize);
    byte[] charsetBuffer = new byte[bufferSize];
    int bytesRead;
    int offset = 0;
    while (true) {
      int toread = bufferSize - offset;
      bytesRead = input.read(charsetBuffer, offset, toread);
      if (bytesRead == -1 || toread == 0) break;
      offset += bytesRead;
    }
    input.reset();
    return detectCharset(charsetBuffer, offset, handler, maybeCharset);
  }

  @SuppressWarnings("resource")
  private static FilterStatus runReadFilter(
      FilterMIMEType handler, ReadFilterRequest request, String typeName) throws IOException {
    try {
      handler.readFilter.readFilter(
          request.input(),
          request.output(),
          request.charset(),
          request.otherMimeTypeParams(),
          request.schemeHostAndPort(),
          request.filterCallback());
    } catch (EOFException e) {
      LOG.error("EOFException caught: {}", e, e);
      throw new DataFilterException(l10n("EOFMessage"), l10n("EOFMessage"), l10n("EOFDescription"));
    } finally {
      if (request.filterCallback() != null) request.filterCallback().onFinished();
    }
    request.output().flush();
    return new FilterStatus(request.charset(), typeName);
  }

  private record ParsedMime(String type, String charset, HashMap<String, String> otherParams) {}

  private record ReadFilterRequest(
      InputStream input,
      OutputStream output,
      String charset,
      HashMap<String, String> otherMimeTypeParams,
      String schemeHostAndPort,
      FilterCallback filterCallback) {}

  /**
   * Detect a Byte Order Mark, a sequence of bytes which identifies a document as encoded with a
   * specific charset.
   *
   * @param input the buffer containing the beginning of a document to inspect; only the first
   *     {@code length} bytes are considered
   * @param length number of valid bytes in {@code input} to examine; must be {@code >= 0}
   * @return the canonical charset name corresponding to a recognized BOM, or {@code null} when no
   *     known BOM is present in the inspected prefix
   * @throws IOException reserved for API parity with other charset detection helpers; this
   *     implementation performs no I/O and does not ordinarily throw it
   */
  private static String detectBOM(byte[] input, int length) throws IOException {
    if (startsWith(input, bomUtf8, length)) return "UTF-8";
    if (startsWith(input, bomUtf16Be, length)) return "UTF-16BE";
    if (startsWith(input, bomUtf16Le, length)) return "UTF-16LE";
    if (startsWith(input, bomUtf32Be, length)) return "UTF-32BE";
    if (startsWith(input, bomUtf32Le, length)) return "UTF-32LE";
    // We do NOT support UTF-32-2143 or UTF-32-3412
    // Java does not have charset support for them, and well,
    // very few people create web content on a PDP-11!

    if (startsWith(input, bomUtf322143, length))
      throw new UnsupportedCharsetInFilterException("UTF-32-2143");
    if (startsWith(input, bomUtf323412, length))
      throw new UnsupportedCharsetInFilterException("UTF-32-3412");

    if (startsWith(input, bomScsu, length)) return "SCSU";
    if (startsWith(input, bomUtf71, length)
        || startsWith(input, bomUtf72, length)
        || startsWith(input, bomUtf73, length)
        || startsWith(input, bomUtf74, length)
        || startsWith(input, bomUtf75, length)) return "UTF-7";
    if (startsWith(input, bomUtfEbcdic, length)) return "UTF-EBCDIC";
    if (startsWith(input, bomBocu1, length)) return "BOCU-1";
    return null;
  }

  // Byte Order Mark's - from Wikipedia. We keep all of them because an attacker might
  // deliberately use a rare encoding to confuse the filter. At present a charset is not
  // mandatory, and some browsers may pick these up anyway even if one is present.

  static byte[] bomUtf8 = new byte[] {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};
  static byte[] bomUtf16Be = new byte[] {(byte) 0xFE, (byte) 0xFF};
  static byte[] bomUtf16Le = new byte[] {(byte) 0xFF, (byte) 0xFE};
  static byte[] bomUtf32Be = new byte[] {(byte) 0, (byte) 0, (byte) 0xFE, (byte) 0xFF};
  static byte[] bomUtf32Le = new byte[] {(byte) 0xFF, (byte) 0xFE, (byte) 0, (byte) 0};
  static byte[] bomScsu = new byte[] {(byte) 0x0E, (byte) 0xFE, (byte) 0xFF};
  static byte[] bomUtf71 = new byte[] {(byte) 0x2B, (byte) 0x2F, (byte) 0x76, (byte) 0x38};
  static byte[] bomUtf72 = new byte[] {(byte) 0x2B, (byte) 0x2F, (byte) 0x76, (byte) 0x39};
  static byte[] bomUtf73 = new byte[] {(byte) 0x2B, (byte) 0x2F, (byte) 0x76, (byte) 0x2B};
  static byte[] bomUtf74 = new byte[] {(byte) 0x2B, (byte) 0x2F, (byte) 0x76, (byte) 0x2F};
  static byte[] bomUtf75 =
      new byte[] {(byte) 0x2B, (byte) 0x2F, (byte) 0x76, (byte) 0x38, (byte) 0x2D};
  static byte[] bomUtfEbcdic = new byte[] {(byte) 0xDD, (byte) 0x73, (byte) 0x66, (byte) 0x73};
  static byte[] bomBocu1 = new byte[] {(byte) 0xFB, (byte) 0xEE, (byte) 0x28};

  // These BOMs are invalid. That is, we do not support them, they will produce an unrecoverable
  // error, since we cannot decode them, but the browser might be able to, as e.g., the CSS spec
  // refers to them.
  static byte[] bomUtf322143 = new byte[] {(byte) 0x00, (byte) 0x00, (byte) 0xff, (byte) 0xfe};
  static byte[] bomUtf323412 = new byte[] {(byte) 0xfe, (byte) 0xff, (byte) 0x00, (byte) 0x00};

  /**
   * Test whether {@code data} begins with the byte sequence {@code cmp} within the first {@code
   * length} bytes.
   *
   * <p>This helper avoids out-of-bounds reads by failing fast when {@code cmp.length > length} and
   * performs a byte-for-byte comparison from index {@code 0}.
   *
   * @param data the candidate buffer to test; must contain at least {@code length} bytes
   * @param cmp the prefix to compare against from the start of {@code data}
   * @param length the maximum number of bytes from {@code data} to consider during comparison
   * @return {@code true} if {@code data} begins with {@code cmp} within the given limit; otherwise
   *     {@code false}
   */
  public static boolean startsWith(byte[] data, byte[] cmp, int length) {
    if (cmp.length > length) return false;
    for (int i = 0; i < cmp.length; i++) {
      if (data[i] != cmp[i]) return false;
    }
    return true;
  }

  /**
   * Infer a media MIME type from a URL/path by inspecting its extension.
   *
   * <p>The detection recognizes common audio and Ogg container extensions and returns a subtype
   * suitable for the HTML {@code <audio>/<video>} {@code src} attribute. Unknown or unrecognized
   * suffixes default to {@code audio/mpeg} for compatibility.
   *
   * @param uriold a URI or path that may include a query string; the detection logic ignores the
   *     query component
   * @return a best-effort MIME type such as {@code audio/ogg}, {@code application/ogg}, or a
   *     reasonable default when the extension is not recognized
   */
  public static String mimeTypeForSrc(String uriold) {
    String uriPath = uriold.contains("?") ? uriold.split("\\?")[0] : uriold;
    String subMimetype;
    if (uriPath.endsWith(".m3u") || uriPath.endsWith(".m3u8")) {
      subMimetype = "audio/mpegurl";
    } else if (uriPath.endsWith(".flac")) {
      subMimetype = "audio/flac";
    } else if (uriPath.endsWith(".oga")) {
      subMimetype = "audio/ogg";
    } else if (uriPath.endsWith(".ogv")) {
      subMimetype = "video/ogg";
    } else if (uriPath.endsWith(".ogg")) {
      subMimetype = "application/ogg";
    } else if (uriPath.endsWith(".wav")) {
      subMimetype = "audio/vnd.wave";
    } else { // force mp3 for anything we do not know
      subMimetype = "audio/mpeg";
    }
    return subMimetype;
  }

  /**
   * Outcome of a filtering operation, containing the effective charset and MIME type.
   *
   * <p>Instances are immutable value holders returned by {@code filter(...)}. They help callers
   * persist or display the resolved charset (which may differ from the declared one) alongside the
   * MIME type used to select the handler.
   */
  public static class FilterStatus {
    /**
     * The effective character set used to decode text during filtering. For binary formats this may
     * be {@code null}. The value reflects BOMs, in-document declarations, or inherited hints as
     * applied by the handler, and is safe to cache or display.
     */
    public final String charset;

    /**
     * The MIME type associated with the filtered content. This is the base type (parameters
     * removed) derived from the caller's {@code typeName} and may inform downstream rendering or
     * content handling decisions.
     */
    public final String mimeType;

    FilterStatus(String charset, String mimeType) {
      this.charset = charset;
      this.mimeType = mimeType;
    }
  }

  /**
   * Validate whether this filter system can handle a specific MIME type safely.
   *
   * <p>Intended for preflight checks before downloading content. If the type is unknown or marked
   * unsafe (for example, formats that cannot be sanitized reliably), the method returns an
   * exception describing the condition. A {@code null} return indicates the type is supported by a
   * read filter or is safe to pass through unchanged.
   *
   * @param expectedMIME the declared or inferred MIME type to check; parameters are allowed and are
   *     ignored during lookup
   * @return {@code null} when the type is acceptable; otherwise an {@link
   *     UnsafeContentTypeException} detailing the reason for rejection
   */
  public static UnsafeContentTypeException checkMIMEType(String expectedMIME) {
    FilterMIMEType handler = getMIMEType(expectedMIME);
    if (handler == null || (handler.readFilter == null && !handler.safeToRead)) {
      if (handler == null) {
        if (LOG.isDebugEnabled())
          LOG.debug("Unable to get filter handler for MIME type {}", expectedMIME);
        return new UnknownContentTypeException(expectedMIME);
      } else {
        if (LOG.isDebugEnabled()) LOG.debug("Unable to filter unsafe MIME type {}", expectedMIME);
        return new KnownUnsafeContentTypeException(handler);
      }
    }
    return null;
  }
}
