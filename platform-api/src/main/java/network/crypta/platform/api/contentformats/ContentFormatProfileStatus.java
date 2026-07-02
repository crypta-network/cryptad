package network.crypta.platform.api.contentformats;

/**
 * Lifecycle status for a Crypta app ecosystem content profile.
 *
 * <p>The status describes the content format contract, not the stability of a Platform API route.
 * Experimental and beta content profiles may still be used by first-party apps while remaining
 * outside the Platform API 1.0 stable baseline. Release certification serializes these values into
 * evidence so operators can see when a reference app depends on an evolving content format.
 */
public enum ContentFormatProfileStatus {
  /**
   * Profile is part of the stable app ecosystem content contract.
   *
   * <p>Stable content profiles are expected to retain their v1 parsing and generation behavior
   * unless a documented migration or replacement profile is introduced.
   */
  STABLE("stable"),

  /**
   * Profile is supported for first-party beta workflows and may still evolve conservatively.
   *
   * <p>Beta profiles are usable by reference apps, but they remain outside the stable Platform API
   * route guarantee and should keep explicit version metadata in generated documents.
   */
  BETA("beta"),

  /**
   * Profile is available for experimental apps and is not a stable compatibility promise.
   *
   * <p>Experimental profiles are appropriate for first-party preview workflows. Third-party apps
   * should treat them as discoverable metadata rather than long-term compatibility promises.
   */
  EXPERIMENTAL("experimental"),

  /**
   * Profile is retired according to its replacement and deprecation policy.
   *
   * <p>Deprecated profiles should produce explicit validation warnings or rejections according to
   * their policy, preferably with a replacement profile id when one exists.
   */
  DEPRECATED("deprecated");

  private final String jsonValue;

  ContentFormatProfileStatus(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the lowercase status value used in SDK mirrors, docs, and release evidence.
   *
   * <p>The returned text is stable serialization metadata, not a localized display label. SDK
   * mirrors and deterministic certification probes compare this value directly.
   *
   * @return lowercase serialized status label for evidence and SDK metadata
   */
  public String jsonValue() {
    return jsonValue;
  }
}
