package network.crypta.platform.api;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Shared query-parameter parsing helpers for Platform API endpoints.
 *
 * <p>The helpers in this package convert the small set of supported boolean and enum query
 * parameters into strongly typed values while preserving a consistent {@code 400} mapping when a
 * request is malformed.
 */
public final class PlatformApiParameters {
  private static final String QUERY_PARAMETER_PREFIX = "Query parameter '";

  /** Prevents instantiation of this static helper type. */
  private PlatformApiParameters() {}

  /**
   * Reads one boolean query parameter, defaulting when the parameter is absent.
   *
   * @param queryParameters decoded query parameter map
   * @param name parameter name to read
   * @param defaultValue value to return when the parameter is absent
   * @return parsed boolean value
   */
  public static boolean readBoolean(
      Map<String, List<String>> queryParameters, String name, boolean defaultValue) {
    String raw = readSingle(queryParameters, name);
    if (raw == null) {
      return defaultValue;
    }
    if ("true".equalsIgnoreCase(raw)) {
      return true;
    }
    if ("false".equalsIgnoreCase(raw)) {
      return false;
    }
    throw invalidQuery(queryParameter(name) + " must be either 'true' or 'false'.");
  }

  /**
   * Reads one required enum query parameter using the enum's exact {@link Enum#name()} values.
   *
   * @param queryParameters decoded query parameter map
   * @param name parameter name to read
   * @param enumType target enum type
   * @return parsed enum value
   * @param <E> enum type
   */
  public static <E extends Enum<E>> E requireEnum(
      Map<String, List<String>> queryParameters, String name, Class<E> enumType) {
    String raw = readSingle(queryParameters, name);
    if (raw == null || raw.isBlank()) {
      throw invalidQuery("Missing required query parameter '" + name + "'.");
    }
    return parseEnum(name, raw, enumType);
  }

  /**
   * Reads a comma-separated enum query parameter using exact enum names.
   *
   * @param queryParameters decoded query parameter map
   * @param name parameter name to read
   * @param enumType target enum type
   * @param defaultValue value to return when the parameter is absent
   * @return parsed enum set
   * @param <E> enum type
   */
  public static <E extends Enum<E>> Set<E> readCommaSeparatedEnums(
      Map<String, List<String>> queryParameters,
      String name,
      Class<E> enumType,
      Set<E> defaultValue) {
    String raw = readSingle(queryParameters, name);
    if (raw == null) {
      return copyEnumSet(enumType, defaultValue);
    }
    if (raw.isBlank()) {
      throw invalidQuery(queryParameter(name) + " must not be empty.");
    }

    EnumSet<E> values = EnumSet.noneOf(enumType);
    for (String part : raw.split(",", -1)) {
      String trimmed = part.trim();
      if (trimmed.isEmpty()) {
        throw invalidQuery(queryParameter(name) + " must not contain empty enum values.");
      }
      values.add(parseEnum(name, trimmed, enumType));
    }
    return values;
  }

  /**
   * Reads exactly one query parameter value when it is present.
   *
   * @param queryParameters decoded query parameter map
   * @param name parameter name to read
   * @return single supplied value, or {@code null} when the parameter is absent
   * @throws PlatformApiException if the parameter was repeated
   */
  private static String readSingle(Map<String, List<String>> queryParameters, String name) {
    List<String> values = queryParameters.get(name);
    if (values == null || values.isEmpty()) {
      return null;
    }
    if (values.size() > 1) {
      throw invalidQuery(queryParameter(name) + " must not be repeated.");
    }
    return values.getFirst();
  }

  /**
   * Parses one enum value using the enum constant names exposed by the Platform API.
   *
   * @param name parameter name being validated
   * @param raw raw query value supplied by the caller
   * @param enumType target enum type
   * @return parsed enum constant matching {@code raw}
   * @param <E> enum type
   * @throws PlatformApiException if {@code raw} does not match one of the allowed enum names
   */
  private static <E extends Enum<E>> E parseEnum(String name, String raw, Class<E> enumType) {
    try {
      return Enum.valueOf(enumType, raw);
    } catch (IllegalArgumentException _) {
      throw invalidQuery(
          queryParameter(name)
              + "' must be one of "
              + Arrays.toString(enumType.getEnumConstants())
              + ".");
    }
  }

  /**
   * Copies an enum set into a new mutable set while preserving the empty-set element type.
   *
   * @param enumType enum type represented by the set
   * @param source source set to copy
   * @return copied enum set suitable for further mutation by the caller
   * @param <E> enum type
   */
  private static <E extends Enum<E>> EnumSet<E> copyEnumSet(Class<E> enumType, Set<E> source) {
    if (source.isEmpty()) {
      return EnumSet.noneOf(enumType);
    }
    return EnumSet.copyOf(source);
  }

  private static String queryParameter(String name) {
    return QUERY_PARAMETER_PREFIX + name + "'";
  }

  /**
   * Creates the standard {@code 400 invalid_query_parameter} exception.
   *
   * @param message human-readable validation failure
   * @return platform API exception carrying the standard invalid-query error mapping
   */
  private static PlatformApiException invalidQuery(String message) {
    return new PlatformApiException(400, "invalid_query_parameter", message);
  }
}
