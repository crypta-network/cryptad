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
 * @param unknownFieldPolicy policy label for fields outside the profile schema
 * @param futureVersionPolicy policy label for future major/minor versions
 * @param deprecationPolicy policy label for known deprecated versions
 */
public record ContentFormatVersionPolicy(
    String unknownFieldPolicy, String futureVersionPolicy, String deprecationPolicy) {
  /** Conservative v1 behavior for signed/canonical app ecosystem profiles. */
  public static final ContentFormatVersionPolicy CONSERVATIVE_V1 =
      new ContentFormatVersionPolicy(
          "reject_unknown_fields",
          "reject_unknown_major_accept_known_minor_only",
          "explicit_warning_or_reject");

  /** Creates one immutable policy after checking every label is present. */
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
