package network.crypta.platform.appcatalog;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Production channel, support, deprecation, and advisory metadata for a catalog entry.
 *
 * <p>This record groups the signed metadata that lets catalog publishers separate ordinary stable
 * releases from beta, nightly, maintenance, deprecated, unsupported, or security-advisory-bearing
 * entries. Catalog parsers attach it to {@link AppCatalogEntry} instances, writers use it to decide
 * whether v3 catalog properties must be emitted, and Platform API handlers expose it to clients
 * that need operator-facing release state.
 *
 * <p>The metadata is authenticated by the signed catalog when present, but it remains advisory.
 * Non-stable channels do not become eligible for automatic update actions unless local policy
 * permits them, and deprecated or unsupported entries do not bypass catalog signature, bundle
 * digest, signed bundle, review receipt, or compatibility checks. Instances are immutable and safe
 * to share after construction; collection components are copied into deterministic order.
 *
 * @param channel release channel for the catalog entry, defaulted to {@code stable} when omitted by
 *     legacy callers
 * @param supportStatus operator-facing support status, defaulted to {@code supported} when omitted
 *     by legacy callers
 * @param deprecationStatus deprecation lifecycle status, defaulted to {@code none} when omitted by
 *     legacy callers
 * @param deprecationMessage optional bounded single-line deprecation message shown to operators
 * @param replacementAppId optional normalized replacement app id for migration or retirement flows
 * @param securityAdvisories advisory references preserved in deterministic catalog order
 * @param declared whether catalog or descriptor input explicitly declared production metadata
 */
public record AppCatalogProductionMetadata(
    AppCatalogChannel channel,
    AppCatalogSupportStatus supportStatus,
    AppCatalogDeprecationStatus deprecationStatus,
    Optional<String> deprecationMessage,
    Optional<String> replacementAppId,
    List<AppCatalogSecurityAdvisory> securityAdvisories,
    boolean declared) {
  private static final int MAX_DEPRECATION_MESSAGE_CHARS = 512;

  /**
   * Backward-compatible defaults for catalogs and descriptors without production metadata.
   *
   * <p>The default represents a supported stable entry with no deprecation message, replacement
   * app, or security advisory references. Its {@code declared} flag is {@code false}, so writers
   * can omit v3 production properties unless another value differs from these defaults.
   */
  public static final AppCatalogProductionMetadata DEFAULT =
      new AppCatalogProductionMetadata(
          AppCatalogChannel.STABLE,
          AppCatalogSupportStatus.SUPPORTED,
          AppCatalogDeprecationStatus.NONE,
          Optional.empty(),
          Optional.empty(),
          List.of(),
          false);

  /**
   * Creates validated production metadata.
   *
   * <p>The canonical constructor applies legacy defaults for nullable enum components, validates
   * the optional deprecation message as a bounded single line, normalizes replacement app ids
   * through the same rules used by catalog entries, and rejects duplicate security advisory ids.
   * Advisory order is preserved so writers and API summaries remain deterministic.
   *
   * @param channel release channel, defaulting to {@code stable} when {@code null}
   * @param supportStatus support status, defaulting to {@code supported} when {@code null}
   * @param deprecationStatus deprecation status, defaulting to {@code none} when {@code null}
   * @param deprecationMessage optional bounded deprecation message for operator-facing summaries
   * @param replacementAppId optional app id normalized for replacement or migration guidance
   * @param securityAdvisories advisory references in deterministic catalog order
   * @param declared whether the metadata was explicitly present in catalog or descriptor input
   * @throws NullPointerException if an optional or advisory-list component is {@code null}
   * @throws AppCatalogException if bounded text, replacement app id, or advisory ids are invalid
   */
  public AppCatalogProductionMetadata {
    channel = Objects.requireNonNullElse(channel, AppCatalogChannel.STABLE);
    supportStatus = Objects.requireNonNullElse(supportStatus, AppCatalogSupportStatus.SUPPORTED);
    deprecationStatus =
        Objects.requireNonNullElse(deprecationStatus, AppCatalogDeprecationStatus.NONE);
    Objects.requireNonNull(deprecationMessage, "deprecationMessage");
    deprecationMessage =
        deprecationMessage.map(
            value ->
                AppCatalogSidecars.requireBoundedSingleLine(
                    value,
                    "deprecation.message",
                    AppCatalogSidecars.INVALID_CATALOG_ENTRY,
                    MAX_DEPRECATION_MESSAGE_CHARS));
    Objects.requireNonNull(replacementAppId, "replacementAppId");
    replacementAppId = replacementAppId.map(AppCatalogEntry::normalizeAppId);
    securityAdvisories = normalizeSecurityAdvisories(securityAdvisories);
  }

  /**
   * Returns whether this metadata should force catalog schema v3 serialization.
   *
   * <p>Writers call this before emitting production fields. A value of {@code false} means the
   * record is equivalent to legacy stable/supported/no-deprecation metadata and can be omitted
   * without changing reader behavior. A value of {@code true} preserves explicit declarations as
   * well as any value that differs from the default set.
   *
   * @return {@code true} when production metadata was explicitly declared or differs from defaults
   */
  public boolean hasCatalogFields() {
    return declared
        || channel != AppCatalogChannel.STABLE
        || supportStatus != AppCatalogSupportStatus.SUPPORTED
        || deprecationStatus != AppCatalogDeprecationStatus.NONE
        || deprecationMessage.isPresent()
        || replacementAppId.isPresent()
        || !securityAdvisories.isEmpty();
  }

  /**
   * Returns whether automatic update policy must never treat this as an ordinary candidate.
   *
   * <p>This is a conservative policy helper for app-update selection. It blocks automatic handling
   * when the entry is on the deprecated channel, has any non-{@code none} deprecation lifecycle
   * status, or is marked deprecated or unsupported by support metadata. The result does not hide
   * the entry from catalog APIs and does not prevent explicit operator review where higher-level
   * services allow that workflow.
   *
   * @return {@code true} when production metadata makes the entry ineligible for routine automation
   */
  public boolean deprecatedForAutomaticUpdates() {
    return channel == AppCatalogChannel.DEPRECATED
        || deprecationStatus != AppCatalogDeprecationStatus.NONE
        || supportStatus == AppCatalogSupportStatus.DEPRECATED
        || supportStatus == AppCatalogSupportStatus.UNSUPPORTED;
  }

  private static List<AppCatalogSecurityAdvisory> normalizeSecurityAdvisories(
      List<AppCatalogSecurityAdvisory> advisories) {
    Objects.requireNonNull(advisories, "securityAdvisories");
    Map<String, AppCatalogSecurityAdvisory> normalized = new LinkedHashMap<>();
    for (AppCatalogSecurityAdvisory advisory : advisories) {
      AppCatalogSecurityAdvisory checked = Objects.requireNonNull(advisory, "security advisory");
      AppCatalogSecurityAdvisory previous = normalized.putIfAbsent(checked.id(), checked);
      if (previous != null) {
        throw AppCatalogSidecars.invalidEntry("duplicate security advisory id: " + checked.id());
      }
    }
    return List.copyOf(normalized.values());
  }
}
