package network.crypta.platform.api;

import java.util.Objects;

/**
 * Version identifiers for one Platform API compatibility contract.
 *
 * <p>The Platform API has two version dimensions. {@code apiVersion} names the URL namespace, such
 * as {@code v1} in {@code /api/v1}. {@code contractVersion} is the integer compatibility value app
 * manifests, catalogs, developer tooling, and release certification compare when deciding whether
 * an app was built and tested for the current API surface.
 *
 * <p>This record carries the pair without implying that both values change together. A future
 * Cryptad build can revise the compatibility contract while still serving the same URL API version,
 * and tooling can report that distinction clearly.
 *
 * @param apiVersion URL API version such as {@code v1}, trimmed during construction
 * @param contractVersion positive integer compatibility contract version for app metadata
 */
public record PlatformApiContractVersion(String apiVersion, int contractVersion) {
  /**
   * Creates a validated API/contract version pair.
   *
   * <p>The constructor performs only structural validation: the URL API version must be present and
   * the compatibility contract version must be positive. Policy about minimum and maximum-tested
   * app ranges belongs to {@link PlatformApiContractVerifier}.
   */
  public PlatformApiContractVersion {
    apiVersion = Objects.requireNonNull(apiVersion, "apiVersion").trim();
    if (apiVersion.isEmpty()) {
      throw new IllegalArgumentException("apiVersion must not be blank");
    }
    if (contractVersion <= 0) {
      throw new IllegalArgumentException("contractVersion must be a positive integer");
    }
  }
}
