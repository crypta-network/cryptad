package network.crypta.platform.api;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Transport-neutral request metadata passed into the Platform API router.
 *
 * <p>The record intentionally captures only the small amount of information that the current API
 * needs: the HTTP-style method, the relative path split into path segments beneath {@link
 * PlatformApiPaths#API_V1_PREFIX}, and the decoded query parameters with all supplied values.
 * Bridges remain responsible for any transport-specific parsing, authentication, or header handling
 * before constructing this request.
 *
 * @param method request method name such as {@code GET}
 * @param pathSegments relative path segments beneath the API v1 mount point
 * @param queryParameters decoded query parameters in encounter order
 */
public record PlatformApiRequest(
    String method, List<String> pathSegments, Map<String, List<String>> queryParameters) {
  /**
   * Creates an immutable platform API request descriptor.
   *
   * <p>The constructor normalizes the method name to the upper case using the root locale and
   * copies path segments and query parameters into encounter-order-preserving immutable
   * collections.
   *
   * @throws NullPointerException if any component, path segment, query key, or query value is
   *     {@code null}
   */
  public PlatformApiRequest {
    method = Objects.requireNonNull(method, "method").toUpperCase(Locale.ROOT);
    pathSegments =
        List.copyOf(
            Objects.requireNonNull(pathSegments, "pathSegments").stream()
                .map(segment -> Objects.requireNonNull(segment, "pathSegments value"))
                .toList());
    queryParameters = immutableQueryParameters(queryParameters);
  }

  /**
   * Returns all values supplied for one decoded query parameter.
   *
   * @param name parameter name to look up
   * @return decoded parameter values, or an empty list when the parameter is absent
   */
  @SuppressWarnings("unused")
  public List<String> queryValues(String name) {
    Objects.requireNonNull(name, "name");
    return queryParameters.getOrDefault(name, List.of());
  }

  @Override
  public Map<String, List<String>> queryParameters() {
    return immutableQueryParameters(this.queryParameters);
  }

  /**
   * Copies query parameters into an immutable encounter-order-preserving map.
   *
   * @param source decoded query parameter map supplied by the transport bridge
   * @return immutable copy of {@code source} with immutable value lists
   * @throws NullPointerException if the map, a key, a value list, or a value element is {@code
   *     null}
   */
  private static Map<String, List<String>> immutableQueryParameters(
      Map<String, List<String>> source) {
    Objects.requireNonNull(source, "queryParameters");
    if (source.isEmpty()) {
      return Map.of();
    }
    LinkedHashMap<String, List<String>> copy = LinkedHashMap.newLinkedHashMap(source.size());
    for (Map.Entry<String, List<String>> entry : source.entrySet()) {
      copy.put(
          Objects.requireNonNull(entry.getKey(), "queryParameters key"),
          List.copyOf(
              Objects.requireNonNull(entry.getValue(), "queryParameters value").stream()
                  .map(value -> Objects.requireNonNull(value, "queryParameters item"))
                  .toList()));
    }
    return java.util.Collections.unmodifiableMap(copy);
  }
}
