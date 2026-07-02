package network.crypta.platform.api.contentformats;

/**
 * Lifecycle status for a Crypta app ecosystem content profile.
 *
 * <p>The status describes the content format contract, not the stability of a Platform API route.
 * Experimental and beta content profiles may still be used by first-party apps while remaining
 * outside the Platform API 1.0 stable baseline.
 */
public enum ContentFormatProfileStatus {
  /** Profile is part of the stable app ecosystem content contract. */
  STABLE("stable"),

  /** Profile is supported for first-party beta workflows and may still evolve conservatively. */
  BETA("beta"),

  /** Profile is available for experimental apps and is not a stable compatibility promise. */
  EXPERIMENTAL("experimental"),

  /** Profile is retired according to its replacement and deprecation policy. */
  DEPRECATED("deprecated");

  private final String jsonValue;

  ContentFormatProfileStatus(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the lowercase status value used in SDK mirrors, docs, and release evidence.
   *
   * @return stable serialized status label
   */
  public String jsonValue() {
    return jsonValue;
  }
}
