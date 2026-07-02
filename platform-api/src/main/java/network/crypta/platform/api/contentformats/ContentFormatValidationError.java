package network.crypta.platform.api.contentformats;

import java.util.Objects;

/**
 * Stable validation code and redaction-safe message for content profile checks.
 *
 * <p>Messages must describe the profile-level failure without echoing raw document bytes, raw
 * message bodies, raw trust statements, signatures, tokens, private insert URIs, or local paths.
 *
 * @param code machine-readable validation outcome code
 * @param profileId content profile id that produced the outcome
 * @param message redaction-safe human-readable summary
 */
public record ContentFormatValidationError(String code, String profileId, String message) {
  /** Creates a validation error with all fields present. */
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
