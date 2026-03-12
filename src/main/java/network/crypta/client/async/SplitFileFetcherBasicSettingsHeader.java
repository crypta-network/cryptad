package network.crypta.client.async;

import java.util.List;
import network.crypta.client.ClientMetadata;
import network.crypta.client.Metadata.SplitfileAlgorithm;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;

/**
 * Holds the decoded basic header fields for splitfile fetcher persistence.
 *
 * <p>This package-private carrier groups the fixed header values that are read from or written to
 * the splitfile storage footer. It is typically constructed by the settings codec during parsing
 * and then passed into {@link ParsedBasicSettings}, which combines these values with offsets and
 * block counts. The holder keeps the values as provided by the caller and does not validate them,
 * leaving structural checks to the parser that produced the data.
 *
 * <p>The instance is immutable but may reference mutable collaborators such as the metadata object
 * and decompressor list. Callers should treat those references as read-only within the resume path
 * and avoid sharing across threads without external coordination.
 *
 * <ul>
 *   <li>Captures algorithm identifiers and per-file crypto settings.
 *   <li>Records final and decompressed lengths as stored in the footer.
 *   <li>Preserves client metadata and decompressor ordering for later use.
 * </ul>
 *
 * @see SplitFileFetcherStorageSettingsCodec
 * @see ParsedBasicSettings
 */
@SuppressWarnings({"java:S6206", "ClassCanBeRecord"})
final class SplitFileFetcherBasicSettingsHeader {
  /** Algorithm identifier persisted in the splitfile header. */
  private final SplitfileAlgorithm splitfileType;

  /** Crypto algorithm code stored as a single header byte. */
  private final byte splitfileSingleCryptoAlgorithm;

  /** Optional shared crypto key bytes associated with the header. */
  private final byte[] splitfileSingleCryptoKey;

  /** Final length value in bytes as stored in the header. */
  private final long finalLength;

  /** Decompressed length value in bytes as stored in the header. */
  private final long decompressedLength;

  /** Client metadata decoded from the header, or {@code null} if absent. */
  private final ClientMetadata clientMetadata;

  /** Ordered decompressor identifiers recorded in the header, or {@code null}. */
  private final List<COMPRESSOR_TYPE> decompressors;

  /**
   * Creates a header holder from already-parsed settings values.
   *
   * <p>The constructor copies the provided references and scalar values without validation. It is
   * intended for use by parsing code that has already validated lengths, offsets, and identifiers.
   * The resulting instance is a simple data carrier that preserves the order and identity of the
   * supplied metadata and decompressor list for later consumption.
   *
   * @param splitfileType algorithm identifier for the splitfile storage format; may be {@code
   *     null}.
   * @param splitfileSingleCryptoAlgorithm crypto algorithm code stored in the header byte field.
   * @param splitfileSingleCryptoKey optional shared crypto key bytes; may be {@code null}.
   * @param finalLength the final persisted length in bytes as stored in the header.
   * @param decompressedLength expected decompressed length in bytes; non-negative in valid data.
   * @param clientMetadata client metadata as decoded from the header; may be {@code null}.
   * @param decompressors ordered list of decompressor identifiers; may be {@code null}.
   */
  SplitFileFetcherBasicSettingsHeader(
      SplitfileAlgorithm splitfileType,
      byte splitfileSingleCryptoAlgorithm,
      byte[] splitfileSingleCryptoKey,
      long finalLength,
      long decompressedLength,
      ClientMetadata clientMetadata,
      List<COMPRESSOR_TYPE> decompressors) {
    this.splitfileType = splitfileType;
    this.splitfileSingleCryptoAlgorithm = splitfileSingleCryptoAlgorithm;
    this.splitfileSingleCryptoKey = splitfileSingleCryptoKey;
    this.finalLength = finalLength;
    this.decompressedLength = decompressedLength;
    this.clientMetadata = clientMetadata;
    this.decompressors = decompressors;
  }

  /**
   * Returns the splitfile algorithm identifier stored in the header.
   *
   * @return algorithm identifier as decoded from the persisted header fields.
   */
  SplitfileAlgorithm splitfileType() {
    return splitfileType;
  }

  /**
   * Returns the crypto algorithm code stored in the header.
   *
   * @return raw algorithm code byte persisted in the storage header.
   */
  byte splitfileSingleCryptoAlgorithm() {
    return splitfileSingleCryptoAlgorithm;
  }

  /**
   * Returns the shared crypto key bytes or {@code null} when absent.
   *
   * @return key byte array reference, or {@code null} if the header had no key.
   */
  byte[] splitfileSingleCryptoKey() {
    return splitfileSingleCryptoKey;
  }

  /**
   * Returns the final length value recorded in the header, in bytes.
   *
   * @return the final length in bytes as decoded from the header.
   */
  long finalLength() {
    return finalLength;
  }

  /**
   * Returns the decompressed length value recorded in the header, in bytes.
   *
   * @return decompressed length in bytes as decoded from the header.
   */
  long decompressedLength() {
    return decompressedLength;
  }

  /**
   * Returns the client metadata decoded from the header, or {@code null} if unavailable.
   *
   * @return client metadata reference, or {@code null} when the header had none.
   */
  ClientMetadata clientMetadata() {
    return clientMetadata;
  }

  /**
   * Returns the ordered list of decompressor identifiers, or {@code null} if absent.
   *
   * @return ordered decompressor list reference, or {@code null} when not present.
   */
  List<COMPRESSOR_TYPE> decompressors() {
    return decompressors;
  }
}
