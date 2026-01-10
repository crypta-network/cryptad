package network.crypta.client.filter;

/**
 * Charset handling rules for a MIME type.
 *
 * <p>This record captures whether a charset parameter is accepted, what default to assume when none
 * is declared, and the optional extractor used for in-band detection.
 *
 * @param takesACharset whether the MIME type accepts a charset parameter
 * @param defaultCharset fallback charset when no explicit declaration is present
 * @param charsetExtractor optional extractor used to infer a charset from a byte prefix
 * @param useMaybeCharset whether to fall back to a referring document's charset hint
 */
public record FilterMIMETypeCharsetPolicy(
    boolean takesACharset,
    String defaultCharset,
    CharsetExtractor charsetExtractor,
    boolean useMaybeCharset) {}
