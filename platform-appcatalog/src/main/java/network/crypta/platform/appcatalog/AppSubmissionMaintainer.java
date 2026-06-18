package network.crypta.platform.appcatalog;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Public maintainer contact metadata included in a submission package.
 *
 * <p>The values are bounded single-line strings so a submission cannot smuggle extra JSON fields or
 * descriptor lines through maintainer metadata. Contact text should be a public address such as a
 * {@code mailto:} URI, not a private account token or local path.
 *
 * <p>This record is intentionally small because submission packages are portable review artifacts,
 * not account profiles. The maintainer identity helps reviewers route follow-up questions and lets
 * catalog candidates preserve basic support metadata. It does not establish reviewer trust, signing
 * authority, or ownership of the app id; those decisions remain bound to bundle signatures, review
 * receipts, trusted reviewer registries, and catalog policy.
 *
 * @param name public maintainer display name shown in review metadata
 * @param contact public maintainer contact URI or address suitable for audit records
 */
public record AppSubmissionMaintainer(String name, String contact) {
  private static final int MAX_NAME_CHARS = 128;
  private static final int MAX_CONTACT_CHARS = 256;

  /**
   * Creates validated maintainer metadata.
   *
   * <p>Both fields must be present as bounded single-line strings. The constructor does not contact
   * the maintainer address or validate a mailbox; it only enforces descriptor-safe text before the
   * value can be embedded in deterministic submission JSON.
   */
  public AppSubmissionMaintainer {
    name =
        AppCatalogSidecars.requireBoundedSingleLine(
            name, "maintainer.name", AppCatalogSidecars.INVALID_CATALOG_ENTRY, MAX_NAME_CHARS);
    contact =
        AppCatalogSidecars.requireBoundedSingleLine(
            contact,
            "maintainer.contact",
            AppCatalogSidecars.INVALID_CATALOG_ENTRY,
            MAX_CONTACT_CHARS);
  }

  Map<String, Object> toJsonValue() {
    Map<String, Object> value = new LinkedHashMap<>();
    value.put("name", name);
    value.put("contact", contact);
    return value;
  }

  static AppSubmissionMaintainer fromJsonValue(Object value) {
    Map<String, Object> object = AppSubmissionJson.requireObject(value, "maintainer");
    return new AppSubmissionMaintainer(
        AppSubmissionJson.requireString(object, "name", "maintainer.name"),
        AppSubmissionJson.requireString(object, "contact", "maintainer.contact"));
  }
}
