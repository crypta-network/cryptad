package network.crypta.platform.devtools;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import network.crypta.platform.api.PlatformApiCapabilityDescriptor;
import network.crypta.platform.api.PlatformApiCapabilityRegistry;
import network.crypta.platform.api.PlatformApiContract;
import network.crypta.platform.api.PlatformApiStabilityLevel;

/**
 * Developer-tooling capability vocabulary that includes app-vault capability names.
 *
 * <p>The Platform API contract remains the runtime source of truth for route authorization. The
 * developer CLI also needs to recognize app-vault capability names while app-vault work is staged
 * across platform modules, so this class supplements the current contract vocabulary for offline
 * manifest linting and built-in compatibility checks. Explicit contract snapshots supplied with
 * {@code crypta-app compat verify --contract ...} are not modified; those checks continue to
 * compare exactly against the selected target snapshot.
 *
 * <p>The supplemental descriptors are intentionally small and local to devtools. They keep manifest
 * validation, scaffold examples, and static UI linting aligned with the capabilities documented for
 * PR-219 without giving devtools its own route-authorization policy. When the shared contract
 * already includes the vault capabilities, this class returns it unchanged.
 */
final class DevtoolsCapabilityVocabulary {
  /** Contract version used for supplemental app-vault capability descriptors. */
  private static final int APP_VAULT_CONTRACT_VERSION =
      PlatformApiContract.CURRENT_CONTRACT_VERSION;

  /** Supplemental vault descriptors used when an older in-process contract snapshot lacks them. */
  private static final List<PlatformApiCapabilityDescriptor> APP_VAULT_DESCRIPTORS =
      List.of(
          capability(
              "vault.identities.create",
              "Create app-owned identities in the local identity vault."),
          capability(
              "vault.identities.manage",
              "Manage app-owned identities and operator-granted shared identity access."),
          capability(
              "vault.identities.read",
              "Read app-granted identity metadata and public identity material."),
          capability(
              "vault.identities.use",
              "Use an app-granted identity without exporting private identity material."),
          capability(
              "vault.secrets.read",
              "Read app-granted secret metadata and values from the local app vault."),
          capability(
              "vault.secrets.write",
              "Create, update, rotate, or delete app-owned secret values in the local app vault."));

  /** Prevents construction of this static vocabulary helper. */
  private DevtoolsCapabilityVocabulary() {}

  /**
   * Returns capability names recognized by developer manifest validation.
   *
   * <p>The returned set is sorted for deterministic diagnostics and includes both the shared
   * Platform API registry and any supplemental vault names needed by local devtools validation.
   *
   * @return immutable sorted capability names, including app-vault capabilities
   */
  static Set<String> knownCapabilities() {
    TreeSet<String> names = new TreeSet<>(PlatformApiCapabilityRegistry.knownCapabilities());
    for (PlatformApiCapabilityDescriptor descriptor : APP_VAULT_DESCRIPTORS) {
      names.add(descriptor.name());
    }
    return Collections.unmodifiableSet(names);
  }

  /**
   * Returns the built-in contract used by devtools validation and default compatibility checks.
   *
   * <p>If the runtime contract already contains the app-vault descriptors, the shared contract is
   * returned unchanged. Otherwise, a detached contract instance is built with the supplemental
   * capability descriptors and the same endpoint descriptors.
   *
   * @return current validation contract with app-vault capabilities present
   */
  static PlatformApiContract currentValidationContract() {
    return withAppVaultCapabilities(PlatformApiContract.current());
  }

  /**
   * Returns a detached contract with app-vault capabilities added when necessary.
   *
   * @param contract base contract used by devtools validation
   * @return original contract when complete, otherwise a copy with supplemental descriptors
   */
  private static PlatformApiContract withAppVaultCapabilities(PlatformApiContract contract) {
    Set<String> baseNames = contract.capabilityNames();
    if (baseNames.containsAll(
        APP_VAULT_DESCRIPTORS.stream().map(PlatformApiCapabilityDescriptor::name).toList())) {
      return contract;
    }
    List<PlatformApiCapabilityDescriptor> capabilities = new ArrayList<>(contract.capabilities());
    for (PlatformApiCapabilityDescriptor descriptor : APP_VAULT_DESCRIPTORS) {
      if (!baseNames.contains(descriptor.name())) {
        capabilities.add(descriptor);
      }
    }
    return new PlatformApiContract(
        contract.apiVersion(),
        contract.contractVersion(),
        contract.generatedBy(),
        contract.stabilityPolicy(),
        capabilities,
        contract.endpoints());
  }

  /**
   * Creates one supplemental app-vault capability descriptor.
   *
   * @param name stable manifest capability name
   * @param description developer-facing capability description
   * @return descriptor used by the built-in validation contract
   */
  private static PlatformApiCapabilityDescriptor capability(String name, String description) {
    return new PlatformApiCapabilityDescriptor(
        name, PlatformApiStabilityLevel.STABLE, APP_VAULT_CONTRACT_VERSION, null, description);
  }
}
