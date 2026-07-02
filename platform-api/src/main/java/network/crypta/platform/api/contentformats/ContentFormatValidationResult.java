package network.crypta.platform.api.contentformats;

import java.util.List;
import java.util.Objects;

/**
 * Redaction-safe result for content profile metadata validation.
 *
 * <p>The result contains only stable codes and summary messages. It intentionally does not keep
 * document text, fetched bodies, signatures, app-data values, URIs, or filesystem paths.
 *
 * @param accepted whether the checked metadata may be processed as the requested profile
 * @param errors blocking validation failures
 * @param warnings non-blocking warnings such as deprecated-but-accepted profile versions
 */
public record ContentFormatValidationResult(
    boolean accepted,
    List<ContentFormatValidationError> errors,
    List<ContentFormatValidationError> warnings) {
  /** Creates one immutable result with copied error and warning lists. */
  public ContentFormatValidationResult {
    errors = List.copyOf(Objects.requireNonNull(errors, "errors"));
    warnings = List.copyOf(Objects.requireNonNull(warnings, "warnings"));
    if (accepted && !errors.isEmpty()) {
      throw new IllegalArgumentException("Accepted validation results cannot contain errors.");
    }
  }

  /**
   * Returns an accepted result with no warnings.
   *
   * @return successful validation result
   */
  public static ContentFormatValidationResult acceptedResult() {
    return new ContentFormatValidationResult(true, List.of(), List.of());
  }

  /**
   * Returns a rejected result with one blocking error.
   *
   * @param code stable error code
   * @param profileId profile id associated with the error
   * @param message redaction-safe summary
   * @return rejected validation result
   */
  public static ContentFormatValidationResult rejected(
      String code, String profileId, String message) {
    return new ContentFormatValidationResult(
        false, List.of(new ContentFormatValidationError(code, profileId, message)), List.of());
  }

  /**
   * Returns an accepted result with one warning.
   *
   * @param code stable warning code
   * @param profileId profile id associated with the warning
   * @param message redaction-safe summary
   * @return accepted validation result carrying a warning
   */
  public static ContentFormatValidationResult acceptedWithWarning(
      String code, String profileId, String message) {
    return new ContentFormatValidationResult(
        true, List.of(), List.of(new ContentFormatValidationError(code, profileId, message)));
  }
}
