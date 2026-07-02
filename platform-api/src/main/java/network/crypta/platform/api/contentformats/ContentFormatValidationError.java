package network.crypta.platform.api.contentformats;

import java.util.Objects;

/**
 * Stable validation code and redaction-safe message for content profile checks.
 *
 * <p>Messages must describe the profile-level failure without echoing raw document bytes, raw
 * message bodies, raw trust statements, signatures, tokens, private insert URIs, or local paths.
 * The record is intentionally small so routes, apps, and release tools can serialize the same
 * outcome without depending on parser-specific exception types.
 *
 * <p>Use stable {@code code} values for automation and concise {@code message} text for operator
 * summaries. Neither field should contain caller-supplied raw content; include only profile ids,
 * byte-limit categories, or lifecycle labels that are already public metadata.
 *
 * @param code machine-readable validation outcome code used by callers and tests
 * @param profileId content profile id that produced the validation outcome
 * @param message redaction-safe human-readable summary suitable for diagnostics
 */
public record ContentFormatValidationError(String code, String profileId, String message) {
  /**
   * Creates a validation error with all fields present.
   *
   * <p>The constructor trims fields and rejects blank text. It does not attempt to sanitize raw
   * content because callers must provide redaction-safe messages before constructing the record.
   */
  public ContentFormatValidationError {
    code = requireText("code", code);
    profileId = requireText("profileId", profileId);
    message = requireText("message", message);
  }

  private static String requireText(String name, String value) {
    String text = Objects.requireNonNull(value, name).trim();
    if (text.isEmpty()) {
      throw new IllegalArgumentException(name + " must not be blank.");
    }
    return text;
  }
}
