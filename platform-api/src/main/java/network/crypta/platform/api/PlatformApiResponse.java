package network.crypta.platform.api;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.json.PlatformApiJsonWriter;

/**
 * JSON response value returned by the transport-neutral Platform API router.
 *
 * <p>The current Platform API surface always emits JSON, so this response carries only the status
 * code, reason phrase, optional headers, and serialized body. A transport-specific bridge remains
 * responsible only for writing these values through its native protocol APIs.
 *
 * @param statusCode transport-level status code, using HTTP-style values such as {@code 200} or
 *     {@code 404}
 * @param reasonPhrase short reason phrase associated with {@code statusCode}
 * @param headers response headers keyed by name
 * @param body serialized JSON response body
 */
public record PlatformApiResponse(
    int statusCode, String reasonPhrase, Map<String, String> headers, String body) {
  /**
   * Creates an immutable platform API response.
   *
   * @throws IllegalArgumentException if {@code statusCode} is outside the HTTP status-code range
   * @throws NullPointerException if {@code reasonPhrase}, {@code headers}, or {@code body} is
   *     {@code null}
   */
  public PlatformApiResponse {
    if (statusCode < 100 || statusCode > 599) {
      throw new IllegalArgumentException("statusCode must be a valid HTTP status code");
    }
    Objects.requireNonNull(reasonPhrase, "reasonPhrase");
    headers = immutableHeaders(headers);
    Objects.requireNonNull(body, "body");
  }

  /**
   * Builds a successful JSON response for the supplied body value.
   *
   * @param value JSON-compatible body value to serialize
   * @return {@code 200 OK} response carrying the serialized body
   */
  public static PlatformApiResponse ok(Object value) {
    return json(200, Map.of(), value);
  }

  /**
   * Builds a {@code 201 Created} JSON response for the supplied body value.
   *
   * @param value JSON-compatible body value to serialize
   * @return {@code 201 Created} response carrying the serialized body
   */
  public static PlatformApiResponse created(Object value) {
    return json(201, Map.of(), value);
  }

  /**
   * Builds a JSON error response using the standard Platform API error shape.
   *
   * @param statusCode transport-level status code to return
   * @param errorCode stable machine-readable error code
   * @param message human-readable error message
   * @return JSON error response using the standard {@code {"error": ...}} shape
   */
  public static PlatformApiResponse error(int statusCode, String errorCode, String message) {
    return error(statusCode, Map.of(), errorCode, message);
  }

  /**
   * Builds a JSON error response using the standard Platform API error shape with explicit headers.
   *
   * @param statusCode transport-level status code to return
   * @param headers response headers to include
   * @param errorCode stable machine-readable error code
   * @param message human-readable error message
   * @return JSON error response using the standard {@code {"error": ...}} shape
   */
  public static PlatformApiResponse error(
      int statusCode, Map<String, String> headers, String errorCode, String message) {
    LinkedHashMap<String, Object> errorBody = LinkedHashMap.newLinkedHashMap(1);
    LinkedHashMap<String, Object> error = LinkedHashMap.newLinkedHashMap(2);
    error.put("code", Objects.requireNonNull(errorCode, "errorCode"));
    error.put("message", Objects.requireNonNull(message, "message"));
    errorBody.put("error", error);
    return json(statusCode, headers, errorBody);
  }

  @Override
  public Map<String, String> headers() {
    return immutableHeaders(this.headers);
  }

  /**
   * Returns the standard reason phrase for one HTTP-style status code.
   *
   * @param statusCode transport-level status code
   * @return standard reason phrase used in serialized Platform API responses
   */
  static String reasonPhrase(int statusCode) {
    return switch (statusCode) {
      case 201 -> "Created";
      case 200 -> "OK";
      case 400 -> "Bad Request";
      case 403 -> "Forbidden";
      case 404 -> "Not Found";
      case 405 -> "Method Not Allowed";
      case 409 -> "Conflict";
      case 500 -> "Internal Server Error";
      default -> "Platform API";
    };
  }

  /**
   * Serializes one JSON-compatible value into a complete Platform API response.
   *
   * @param statusCode transport-level status code to emit
   * @param headers response headers to include
   * @param value JSON-compatible value to serialize as the body
   * @return immutable Platform API response with a serialized JSON body
   */
  private static PlatformApiResponse json(
      int statusCode, Map<String, String> headers, Object value) {
    return new PlatformApiResponse(
        statusCode, reasonPhrase(statusCode), headers, PlatformApiJsonWriter.write(value));
  }

  /**
   * Copies response headers into an immutable encounter-order-preserving map.
   *
   * @param source source header map supplied by a caller
   * @return immutable copy of {@code source}
   * @throws NullPointerException if the map, a key, or a value is {@code null}
   */
  private static Map<String, String> immutableHeaders(Map<String, String> source) {
    Objects.requireNonNull(source, "headers");
    if (source.isEmpty()) {
      return Map.of();
    }
    LinkedHashMap<String, String> copy = LinkedHashMap.newLinkedHashMap(source.size());
    for (Map.Entry<String, String> entry : source.entrySet()) {
      copy.put(
          Objects.requireNonNull(entry.getKey(), "headers key"),
          Objects.requireNonNull(entry.getValue(), "headers value"));
    }
    return Collections.unmodifiableMap(copy);
  }
}
