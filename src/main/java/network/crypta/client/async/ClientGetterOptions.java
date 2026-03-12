package network.crypta.client.async;

import network.crypta.support.api.Bucket;

/**
 * Optional settings for constructing a {@link ClientGetter}.
 *
 * <p>This record bundles optional bucket destinations, binary blob recording behavior, initial
 * metadata, and MIME extension constraints. All fields are optional and are stored without
 * validation so the getter preserves the original behavior of the legacy constructor.
 *
 * @param returnBucket optional destination bucket for the final data; {@code null} means allocate a
 *     temporary bucket.
 * @param binaryBlobWriter optional writer that records accessed keys into a binary blob.
 * @param dontFinalizeBlobWriter whether the caller finalizes the blob writer lifecycle.
 * @param initialMetadata optional metadata bucket to seed the request.
 * @param forceCompatibleExtension optional extension used by MIME filtering; may be {@code null}.
 */
public record ClientGetterOptions(
    Bucket returnBucket,
    BinaryBlobWriter binaryBlobWriter,
    boolean dontFinalizeBlobWriter,
    Bucket initialMetadata,
    String forceCompatibleExtension) {

  /**
   * Returns default options with all optional settings disabled.
   *
   * @return a {@link ClientGetterOptions} instance with all fields set to their defaults.
   */
  public static ClientGetterOptions defaults() {
    return new ClientGetterOptions(null, null, false, null, null);
  }

  /**
   * Returns options that only specify a return bucket.
   *
   * @param returnBucket destination bucket for the final data; may be {@code null}.
   * @return a {@link ClientGetterOptions} instance with the return bucket configured.
   */
  public static ClientGetterOptions withReturnBucket(Bucket returnBucket) {
    return new ClientGetterOptions(returnBucket, null, false, null, null);
  }

  /**
   * Returns options that specify a return bucket and binary blob writer.
   *
   * @param returnBucket destination bucket for the final data; may be {@code null}.
   * @param binaryBlobWriter writer that records accessed keys; may be {@code null}.
   * @return a {@link ClientGetterOptions} instance with binary blob recording configured.
   */
  public static ClientGetterOptions withBinaryBlobWriter(
      Bucket returnBucket, BinaryBlobWriter binaryBlobWriter) {
    return new ClientGetterOptions(returnBucket, binaryBlobWriter, false, null, null);
  }

  /**
   * Returns options that specify a return bucket, binary blob writer, and initial metadata.
   *
   * @param returnBucket destination bucket for the final data; may be {@code null}.
   * @param binaryBlobWriter writer that records accessed keys; may be {@code null}.
   * @param initialMetadata metadata bucket used to seed the request; may be {@code null}.
   * @return a {@link ClientGetterOptions} instance with initial metadata configured.
   */
  public static ClientGetterOptions withInitialMetadata(
      Bucket returnBucket, BinaryBlobWriter binaryBlobWriter, Bucket initialMetadata) {
    return new ClientGetterOptions(returnBucket, binaryBlobWriter, false, initialMetadata, null);
  }
}
