package network.crypta.platform.api;

import java.util.Objects;

/**
 * Describes one manifest capability recognized by the Platform API contract.
 *
 * <p>Capability descriptors are the public vocabulary that app manifests, signed catalogs,
 * developer tooling, and release certification compare against. The descriptor intentionally
 * contains only stable review metadata: the normalized capability name, its support state, the
 * contract version where it first appeared, optional deprecation timing, and a short
 * operator-facing description. It does not grant the capability to an app, and it does not expose
 * any token, process, or local-host detail.
 *
 * <p>Instances are immutable value objects. Construction trims text fields and rejects blank names
 * or descriptions so contract JSON remains deterministic and useful in review reports.
 *
 * @param name normalized manifest capability name as it appears in {@code app.permissions}
 * @param stability stability classification used by compatibility verifiers and review UI
 * @param sinceContractVersion first positive Platform API contract version containing the
 *     capability
 * @param deprecation optional deprecation or removal schedule metadata, or {@code null}
 * @param description short human-readable description suitable for contract snapshots
 */
public record PlatformApiCapabilityDescriptor(
    String name,
    PlatformApiStabilityLevel stability,
    int sinceContractVersion,
    PlatformApiDeprecation deprecation,
    String description) {
  /**
   * Creates a validated immutable capability descriptor.
   *
   * <p>The constructor performs only structural validation. It keeps policy decisions in the
   * contract builder and verifier, while guaranteeing that a descriptor emitted to JSON has a
   * non-empty capability name, a non-empty description, and a positive {@code sinceContractVersion}
   * value.
   */
  public PlatformApiCapabilityDescriptor {
    name = requireText(name, "name");
    Objects.requireNonNull(stability, "stability");
    if (sinceContractVersion <= 0) {
      throw new IllegalArgumentException("sinceContractVersion must be a positive integer");
    }
    description = requireText(description, "description");
  }

  private static String requireText(String value, String fieldName) {
    String text = Objects.requireNonNull(value, fieldName).trim();
    if (text.isEmpty()) {
      throw new IllegalArgumentException(fieldName + " must not be blank");
    }
    return text;
  }
}
