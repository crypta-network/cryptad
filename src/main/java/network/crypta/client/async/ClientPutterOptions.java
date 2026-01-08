package network.crypta.client.async;

/**
 * Optional settings for constructing a {@link ClientPutter}.
 *
 * <p>This record bundles optional filename hints, binary-blob behavior, splitfile crypto overrides,
 * and metadata thresholding. All fields are optional and are stored without validation so the
 * putter preserves the behavior of legacy constructors.
 *
 * @param targetFilename optional manifest filename for single-file inserts; may be {@code null}.
 * @param binaryBlob when {@code true}, use the binary-blob insertion path.
 * @param overrideSplitfileCrypto optional 32-byte key overriding random splitfile key generation.
 * @param metadataThreshold when greater than zero, return compact metadata instead of a URI when
 *     the encoded metadata length is below this threshold; units are bytes.
 */
public record ClientPutterOptions(
    String targetFilename,
    boolean binaryBlob,
    byte[] overrideSplitfileCrypto,
    long metadataThreshold) {

  /**
   * Returns default options with all optional settings disabled.
   *
   * @return a {@link ClientPutterOptions} instance with defaults applied.
   */
  public static ClientPutterOptions defaults() {
    return new ClientPutterOptions(null, false, null, -1);
  }
}
