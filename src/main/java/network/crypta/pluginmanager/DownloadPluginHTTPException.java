package network.crypta.pluginmanager;

import java.io.Serial;

/**
 * Exception type used to represent an HTTP response that prompts a client download.
 *
 * <p>This class is a specialized {@link PluginHTTPException} that carries a binary payload together
 * with minimal metadata (a filename and a MIME type) so the HTTP layer can render a response that
 * is suitable for "download to disk" flows. Unlike error-oriented exceptions, this type represents
 * a successful response shape: {@link #code()} returns {@code 200}, and the constructor initializes
 * the base {@link PluginHTTPException#message} and {@link PluginHTTPException#location} fields to
 * fixed placeholder values.
 *
 * <p>Instances are immutable in the sense that all fields are {@code final}; however, the {@link
 * #data} array is not defensively copied and remains mutable by the caller. If the payload must not
 * change after construction, callers should pass an array that will not be modified.
 *
 * <ul>
 *   <li><b>Payload</b>: {@link #data} contains the bytes to serve to the client.
 *   <li><b>Metadata</b>: {@link #filename} and {@link #mimeType} describe the payload.
 *   <li><b>Status</b>: {@link #code()} returns {@code 200} for a successful response.
 * </ul>
 *
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 */
public class DownloadPluginHTTPException extends PluginHTTPException {
  @Serial private static final long serialVersionUID = -1;

  /**
   * Suggested filename associated with the payload for the HTTP response.
   *
   * <p>This value is stored exactly as provided to the constructor and is immutable thereafter. It
   * may be {@code null} if the caller does not provide a name; response-building code should
   * tolerate a missing filename and apply its own fallback if needed.
   */
  public final String filename;

  /**
   * MIME type describing the payload bytes for HTTP response rendering.
   *
   * <p>This value is stored exactly as provided to the constructor and is immutable thereafter. It
   * may be {@code null} if no explicit type is available; response-building code should handle a
   * missing value (for example by selecting a default content type).
   */
  public final String mimeType;

  /**
   * Raw payload bytes intended to be written as the HTTP response body.
   *
   * <p>The provided array reference is stored directly and is not defensively copied. Callers that
   * require immutability should pass an array that will not be modified after construction.
   */
  public final byte[] data;

  /**
   * Returns the HTTP status code associated with this exception instance.
   *
   * <p>This override returns {@code 200} to indicate a successful response that carries a payload
   * intended for download flows. The actual body and metadata are provided via {@link #data},
   * {@link #filename}, and {@link #mimeType}.
   *
   * @return the HTTP status code {@code 200} for a successful download response.
   */
  @Override
  public short code() {
    return 200; // OK
  }

  /**
   * Creates a new exception instance that carries a downloadable payload and related metadata.
   *
   * <p>This constructor stores the provided values as-is and delegates to {@link
   * PluginHTTPException#PluginHTTPException(String, String)} with fixed placeholders. It performs
   * no validation or copying: in particular, the {@code data} array reference is retained directly.
   * Callers should ensure that the array contents remain stable for as long as the exception may be
   * rendered into an HTTP response.
   *
   * <pre>{@code
   * byte[] bytes = ...;
   * throw new DownloadPluginHTTPException(bytes, "export.bin", "application/octet-stream");
   * }</pre>
   *
   * @param data payload bytes to expose as the HTTP response body; stored without copying.
   * @param filename suggested filename associated with the payload; may be {@code null}.
   * @param mimeType MIME type describing the payload; may be {@code null} if unknown.
   */
  public DownloadPluginHTTPException(byte[] data, String filename, String mimeType) {
    super("Ok", "none");
    this.data = data;
    this.filename = filename;
    this.mimeType = mimeType;
  }
}
