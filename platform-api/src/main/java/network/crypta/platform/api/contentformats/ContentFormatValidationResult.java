package network.crypta.platform.api.contentformats;

import java.util.List;
import java.util.Objects;

/**
 * Redaction-safe result for content profile metadata validation.
 *
 * <p>The result contains only stable codes and summary messages. It intentionally does not keep
 * document text, fetched bodies, signatures, app-data values, URIs, or filesystem paths. Callers
 * can return it from parsers, route validators, app import previews, or deterministic release
 * probes without introducing another channel for raw content.
 *
 * <p>An accepted result may contain warnings, but it cannot contain blocking errors. Rejected
 * results may contain one or more errors and should stop further parsing, signing, or trust-score
 * annotation until the caller has handled the failure.
 *
 * @param accepted whether the checked metadata may be processed as the requested profile
 * @param errors blocking validation failures with redaction-safe messages
 * @param warnings non-blocking warnings such as deprecated-but-accepted profile versions
 */
public record ContentFormatValidationResult(
    boolean accepted,
    List<ContentFormatValidationError> errors,
    List<ContentFormatValidationError> warnings) {
  /**
   * Creates one immutable result with copied error and warning lists.
   *
   * <p>The constructor snapshots the supplied lists so callers cannot mutate diagnostics after the
   * result has been shared with a route response or release evidence summary. It also enforces the
   * invariant that accepted results never carry blocking errors.
   */
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
   * <p>Use this helper when profile metadata is supported, within byte limits, and not deprecated.
   * The result is safe to reuse because it contains no caller-supplied content and no mutable
   * lists.
   *
   * @return successful validation result with no errors or warnings
   */
  public static ContentFormatValidationResult acceptedResult() {
    return new ContentFormatValidationResult(true, List.of(), List.of());
  }

  /**
   * Returns a rejected result with one blocking error.
   *
   * <p>The helper is intended for common metadata failures such as oversized documents or
   * unsupported profile versions. The message must be safe to emit in logs, app UI, and release
   * artifacts because this type does not perform content redaction.
   *
   * @param code stable error code used by callers to classify the failure
   * @param profileId profile id associated with the validation failure
   * @param message redaction-safe summary suitable for diagnostics and evidence
   * @return rejected validation result containing one blocking error
   */
  public static ContentFormatValidationResult rejected(
      String code, String profileId, String message) {
    return new ContentFormatValidationResult(
        false, List.of(new ContentFormatValidationError(code, profileId, message)), List.of());
  }

  /**
   * Returns an accepted result with one warning.
   *
   * <p>This is used for cases where the document may still be processed, such as a known deprecated
   * profile version whose policy permits import. Callers should surface the warning without echoing
   * raw document bodies or signatures.
   *
   * @param code stable warning code used by callers to classify the warning
   * @param profileId profile id associated with the validation warning
   * @param message redaction-safe summary suitable for diagnostics and evidence
   * @return accepted validation result carrying one non-blocking warning
   */
  public static ContentFormatValidationResult acceptedWithWarning(
      String code, String profileId, String message) {
    return new ContentFormatValidationResult(
        true, List.of(), List.of(new ContentFormatValidationError(code, profileId, message)));
  }
}
