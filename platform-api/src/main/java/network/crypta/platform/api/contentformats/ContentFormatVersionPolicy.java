package network.crypta.platform.api.contentformats;

import java.util.Objects;

/**
 * Version, unknown-field, and deprecation behavior for one content profile.
 *
 * <p>The profile registry uses short policy labels so Java tests, SDK mirrors, and release
 * certification can compare behavior without importing parser-specific classes. The current v1
 * profiles use the conservative policy: signed and canonical documents reject unknown fields,
 * future major versions are not accepted as v1, and deprecated versions produce explicit validation
 * output.
 *
 * <p>The policy is descriptive metadata, not a JSON parser. Route-specific validators and reference
 * apps still enforce required fields, allowed fields, byte limits, and signature checks. Keeping
 * the labels in one record gives tests a stable way to detect drift between documentation, SDK
 * mirrors, and implementation behavior.
 *
 * @param unknownFieldPolicy policy label for fields outside the profile schema
 * @param futureVersionPolicy policy label for future major or compatible minor versions
 * @param deprecationPolicy policy label for known deprecated versions and replacements
 */
public record ContentFormatVersionPolicy(
    String unknownFieldPolicy, String futureVersionPolicy, String deprecationPolicy) {
  /**
   * Conservative v1 behavior for signed and canonical app ecosystem profiles.
   *
   * <p>This policy rejects unknown fields, rejects unknown major versions, and requires explicit
   * warning or rejection for deprecated versions. It is the default for the PR-276 first-party
   * content profile set.
   */
  public static final ContentFormatVersionPolicy CONSERVATIVE_V1 =
      new ContentFormatVersionPolicy(
          "reject_unknown_fields",
          "reject_unknown_major_accept_known_minor_only",
          "explicit_warning_or_reject");

  /**
   * Creates one immutable policy after checking every label is present.
   *
   * <p>Labels are trimmed and must remain non-blank because release evidence and SDK mirrors
   * compare them as stable identifiers. The constructor does not interpret the labels beyond this
   * basic validation.
   */
  public ContentFormatVersionPolicy {
    unknownFieldPolicy = requireLabel("unknownFieldPolicy", unknownFieldPolicy);
    futureVersionPolicy = requireLabel("futureVersionPolicy", futureVersionPolicy);
    deprecationPolicy = requireLabel("deprecationPolicy", deprecationPolicy);
  }

  private static String requireLabel(String name, String value) {
    String label = Objects.requireNonNull(value, name).trim();
    if (label.isEmpty()) {
      throw new IllegalArgumentException(name + " must not be blank.");
    }
    return label;
  }
}
