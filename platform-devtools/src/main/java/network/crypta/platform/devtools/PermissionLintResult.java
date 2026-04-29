package network.crypta.platform.devtools;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Result of checking manifest permissions against the Platform API capability registry.
 *
 * <p>The bundle manifest parser already validates permission syntax. This lint result adds a
 * developer-facing check for names that are syntactically valid but not currently recognized by the
 * Platform API authorization matrix. Validation commands can therefore warn about likely typos
 * without changing the manifest format or rejecting forward-looking permission names by default.
 *
 * <p>Unknown permission names are sorted and de-duplicated by the lint operation so CLI
 * diagnostics, strict-mode failures, and tests remain deterministic regardless of the order used in
 * the manifest. The result is immutable and contains no reference to the registry used to produce
 * it.
 *
 * @param unknownPermissions sorted permissions that are not known Platform API capabilities
 */
public record PermissionLintResult(List<String> unknownPermissions) {
  /**
   * Creates an immutable lint result.
   *
   * <p>The caller is expected to provide names in diagnostic order. The constructor defensively
   * copies the list so later mutations to caller-owned collections cannot change CLI output.
   *
   * @param unknownPermissions sorted permissions that are not known Platform API capabilities
   */
  public PermissionLintResult {
    unknownPermissions = List.copyOf(unknownPermissions);
  }

  /**
   * Lints manifest permissions against a known capability set.
   *
   * <p>This method assumes the input came from a successfully parsed bundle manifest, so it does
   * not perform syntax validation. It only compares names with the known capability vocabulary and
   * records values missing from that set.
   *
   * @param permissions manifest permissions from a parsed app bundle
   * @param knownCapabilities recognized Platform API capability names
   * @return lint result with sorted, de-duplicated unknown permission names
   */
  public static PermissionLintResult lint(
      Collection<String> permissions, Set<String> knownCapabilities) {
    TreeSet<String> unknown = new TreeSet<>();
    for (String permission : permissions) {
      if (!knownCapabilities.contains(permission)) {
        unknown.add(permission);
      }
    }
    return new PermissionLintResult(List.copyOf(unknown));
  }

  /**
   * Returns whether the manifest declares any unknown capability names.
   *
   * @return {@code true} when at least one unknown permission was found
   */
  public boolean hasUnknownPermissions() {
    return !unknownPermissions.isEmpty();
  }
}
