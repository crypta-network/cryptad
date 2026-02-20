package network.crypta.support.api;

import java.util.Collection;
import java.util.NoSuchElementException;
import javax.naming.SizeLimitExceededException;

/**
 * Represents a parsed HTTP request.
 *
 * <p>This interface provides access to the request path, method, headers, parameters, and
 * optionally submitted body data. Parameters originate either from the query string or from a POST
 * body encoded as {@code application/x-www-form-urlencoded}. Parts refer to items submitted via
 * {@code multipart/form-data} (including uploaded files) and are exposed as buckets.
 *
 * <p>Unless otherwise noted, methods prefer returning empty values (for example, an empty {@code
 * String} or empty array) over {@code null}. Callers should explicitly check return values and use
 * the "throwing" variants where they need strict failure signaling.
 *
 * <p>Resource management: implementations may spool multipart parts to disk. Call {@link
 * #freeParts()} when finished to release any associated resources; after freeing, part accessors
 * may throw {@link IllegalStateException}.
 *
 * <p>Thread-safety: implementations are not required to be thread-safe. Treat a given instance as
 * request-local and confine it to a single thread.
 */
public interface HTTPRequest {

  /**
   * Returns the request path.
   *
   * <p>The segment identifying the dispatched toadlet is already removed from this path.
   *
   * @return the normalized path component of the request URI
   */
  String getPath();

  /**
   * Indicates whether any parameters are present.
   *
   * <p>The result reflects the presence of parameters parsed from the URI (and, depending on the
   * implementation, potentially from {@code application/x-www-form-urlencoded} request bodies).
   *
   * @return {@code false} if no parameters were parsed, {@code true} otherwise
   */
  boolean hasParameters();

  /**
   * Tests whether a parameter is present, regardless of its value.
   *
   * @param name the parameter name
   * @return {@code true} if the parameter exists (even if its value is empty)
   */
  boolean isParameterSet(String name);

  /**
   * Returns the value of a parameter or an empty string if absent.
   *
   * <p>This method never returns {@code null}. If multiple values exist, the first value is
   * returned.
   *
   * <p><code>
   *   if (request.getParam(&quot;abc&quot;).equals(&quot;def&quot;))
   * </code>
   *
   * @param name the parameter name
   * @return the value or {@code ""} when missing or empty
   */
  String getParam(String name);

  /**
   * Returns the value of a parameter or the provided default when absent or empty.
   *
   * <p>If multiple values exist, the first value is returned.
   *
   * @param name the parameter name
   * @param defaultValue the value to return when missing or empty
   * @return the parameter value or {@code defaultValue}
   */
  String getParam(String name, String defaultValue);

  /**
   * Returns a parameter parsed as an {@code int}, defaulting to {@code 0} when absent or invalid.
   *
   * <p>If multiple values exist, the first value is used.
   *
   * @param name the parameter name
   * @return the parsed value or {@code 0} if missing, empty, or not an integer
   */
  @SuppressWarnings("unused")
  int getIntParam(String name);

  /**
   * Returns a parameter parsed as an {@code int}, defaulting to the provided value when absent or
   * invalid.
   *
   * <p>If multiple values exist, the first value is used.
   *
   * @param name the parameter name
   * @param defaultValue the value to return when missing, empty, or not an integer
   * @return the parsed value or {@code defaultValue}
   */
  int getIntParam(String name, int defaultValue);

  /**
   * Returns a part parsed as an {@code int}, defaulting when absent or invalid.
   *
   * <p>The part is read as UTF-8 text and parsed as a decimal integer.
   *
   * @param name the part name
   * @param defaultValue the value to return when missing or not an integer
   * @return the parsed value or {@code defaultValue}
   * @throws IllegalStateException if parts were freed via {@link #freeParts()}
   */
  int getIntPart(String name, int defaultValue);

  /**
   * Returns all values of a parameter.
   *
   * <p>The returned array is never {@code null}. If the parameter is absent the array is empty.
   *
   * @param name the parameter name
   * @return all values, which may include empty strings
   */
  @SuppressWarnings("unused")
  String[] getMultipleParam(String name);

  /**
   * Returns all values of a parameter parsed as {@code int}s.
   *
   * <p>Any values that cannot be parsed are ignored. The returned array is never {@code null}; when
   * no values are present the array is empty.
   *
   * @param name the parameter name
   * @return all successfully parsed integer values
   */
  @SuppressWarnings("unused")
  int[] getMultipleIntParam(String name);

  /**
   * Returns metadata for an uploaded file.
   *
   * <p>Only applicable to {@code multipart/form-data} requests. The returned object exposes the
   * original filename, content type, and a {@link Bucket} containing the file data.
   *
   * @param name the form field name
   * @return the uploaded file, or {@code null} if not present or no filename was supplied
   */
  HTTPUploadedFile getUploadedFile(String name);

  /**
   * Returns a multipart part as a {@link RandomAccessBucket}.
   *
   * <p>Parts may be large (for example, file uploads) and may be spooled to disk by the
   * implementation.
   *
   * @param name the part name
   * @return the part bucket, or {@code null} if not present
   * @throws IllegalStateException if parts were freed via {@link #freeParts()}
   */
  RandomAccessBucket getPart(String name);

  /**
   * Tests whether a multipart part with the given name exists.
   *
   * @param name the part name
   * @return {@code true} if present, otherwise {@code false}
   * @throws IllegalStateException if parts were freed via {@link #freeParts()}
   */
  boolean isPartSet(String name);

  /**
   * Returns a multipart part as a UTF-8 {@code String} with a maximum length.
   *
   * <p>If the named part is missing a {@link NoSuchElementException} is thrown. If its size exceeds
   * {@code maxlength} a {@link SizeLimitExceededException} is thrown. Implementations may throw
   * {@link IllegalStateException} if parts were freed via {@link #freeParts()}.
   *
   * @param name the part name
   * @param maxlength maximum number of characters to read
   * @return the content as text (possibly truncated to {@code maxlength})
   * @throws NoSuchElementException if the part is not present
   * @throws SizeLimitExceededException if the part exceeds {@code maxlength}
   * @throws IllegalStateException if parts were freed
   */
  String getPartAsStringThrowing(String name, int maxlength)
      throws NoSuchElementException, SizeLimitExceededException;

  /**
   * Returns up to {@code maxlength} characters from a part without throwing.
   *
   * <p>Characters beyond the limit are ignored. If the part is missing, an empty string is
   * returned.
   *
   * @param name the part name
   * @param maxlength maximum number of characters to read
   * @return the content as text, possibly truncated, or {@code ""} when missing
   * @throws IllegalStateException if parts were freed via {@link #freeParts()}
   */
  String getPartAsStringFailsafe(String name, int maxlength);

  /**
   * Returns a multipart part as a {@code byte[]} with a maximum length.
   *
   * <p>If the named part is missing a {@link NoSuchElementException} is thrown. If its size exceeds
   * {@code maxlength} a {@link SizeLimitExceededException} is thrown. Implementations may throw
   * {@link IllegalStateException} if parts were freed via {@link #freeParts()}.
   *
   * @param name the part name
   * @param maxlength maximum number of bytes to read
   * @return the content as bytes (possibly truncated to {@code maxlength})
   * @throws NoSuchElementException if the part is not present
   * @throws SizeLimitExceededException if the part exceeds {@code maxlength}
   * @throws IllegalStateException if parts were freed
   */
  @SuppressWarnings("UnusedReturnValue")
  byte[] getPartAsBytesThrowing(String name, int maxlength)
      throws NoSuchElementException, SizeLimitExceededException;

  /**
   * Returns up to {@code maxlength} bytes from a part without throwing.
   *
   * <p>Bytes beyond the limit are ignored. If the part is missing, an empty array is returned.
   *
   * @param name the part name
   * @param maxlength maximum number of bytes to read
   * @return the content as bytes, possibly truncated, or an empty array when missing
   * @throws IllegalStateException if parts were freed via {@link #freeParts()}
   */
  @SuppressWarnings("unused")
  byte[] getPartAsBytesFailsafe(String name, int maxlength);

  /**
   * Releases resources associated with multipart parts.
   *
   * <p>Implementations may store parts on disk or in temporary buffers. After this call, methods
   * that access parts may throw {@link IllegalStateException}.
   */
  void freeParts();

  /**
   * Returns a parameter parsed as a {@code long}, defaulting when absent or invalid.
   *
   * @param name the parameter name
   * @param defaultValue the value to return when missing or unparsable
   * @return the parsed value or {@code defaultValue}
   */
  long getLongParam(String name, long defaultValue);

  /**
   * Returns the HTTP method of the request (for example, {@code GET} or {@code POST}).
   *
   * @return the request method
   */
  String getMethod();

  /**
   * Returns the original request body as a {@link Bucket}.
   *
   * <p>For methods without an entity body (for example, {@code GET}) this may be {@code null}.
   *
   * @return the raw body bucket, or {@code null} if none
   */
  Bucket getRawData();

  /**
   * Returns the value of a specific request header.
   *
   * <p>Callers should pass header names in lower case; some implementations enforce this and may
   * reject mixed-case names.
   *
   * @param name the lower-case header name (for example, {@code "content-type"})
   * @return the first header value, or {@code null} if not present
   */
  String getHeader(String name);

  /**
   * Returns the {@code Content-Length} of the request, if known.
   *
   * @return the content length in bytes, or {@code -1} if unknown or not provided
   */
  @SuppressWarnings("unused")
  int getContentLength();

  /**
   * Returns the names of all multipart parts included with the request.
   *
   * <p>The returned array is never {@code null}. After {@link #freeParts()}, calling this method
   * may throw {@link IllegalStateException}.
   *
   * @return the part field names, possibly empty
   * @throws IllegalStateException if parts were freed via {@link #freeParts()}
   */
  String[] getParts();

  /**
   * Returns the names of all parameters.
   *
   * @return The names of all parameters
   */
  Collection<String> getParameterNames();

  /**
   * Indicates whether {@code incognito=true} is present as a parameter.
   *
   * <p>This checks only the presence and boolean value of the parameter and does not validate any
   * broader runtime mode.
   *
   * @return {@code true} if {@code incognito} is present and set to {@code true}
   */
  boolean isIncognito();

  /**
   * Indicates whether the client appears to be Chrome based on the {@code User-Agent} header.
   *
   * <p>This is a best-effort heuristic.
   *
   * @return {@code true} if the {@code User-Agent} contains {@code "Chrome"}
   */
  boolean isChrome();
}
