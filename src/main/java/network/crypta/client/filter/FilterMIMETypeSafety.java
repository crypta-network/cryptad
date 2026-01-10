package network.crypta.client.filter;

/**
 * Describes baseline safety characteristics for a MIME type.
 *
 * <p>This record captures whether a type is safe to read or write directly and the optional
 * sanitizing filter and description used for user-facing diagnostics.
 *
 * @param safeToRead whether bytes may be delivered without a filter
 * @param safeToWrite whether bytes may be persisted or emitted without additional handling
 * @param readFilter optional stream filter that sanitizes untrusted input
 * @param readDescription human-readable description of read-side handling
 */
public record FilterMIMETypeSafety(
    boolean safeToRead,
    boolean safeToWrite,
    ContentDataFilter readFilter,
    String readDescription) {}
