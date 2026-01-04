package network.crypta.client;

import network.crypta.client.ArchiveManager.ARCHIVE_TYPE;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;

/**
 * Holds the payload description for a splitfile metadata entry.
 *
 * <p>This record bundles the content-facing attributes that accompany a splitfile when constructing
 * {@link Metadata}. It is used alongside {@link SplitfileParams} and {@link MetadataTopLayerInfo}
 * so that splitfile layout details, top-layer sizing, and payload metadata remain clearly grouped.
 * Typical usage is to populate this record from the insert pipeline and pass it to {@link
 * Metadata#Metadata(SplitfileParams, SplitfilePayload, MetadataTopLayerInfo)} as a simple carrier
 * object. The record itself does not validate values or enforce constraints; it preserves the
 * inputs exactly as provided by callers.
 *
 * <p>Instances are immutable, but note that {@link ClientMetadata} and any referenced types may be
 * mutable in their own right. Callers should treat the referenced values as stable for the lifetime
 * of the metadata construction path to avoid inconsistent serialization or logging. The record also
 * does not copy or normalize values, so nullability and defaults should be handled by the caller or
 * the consuming constructor.
 *
 * <ul>
 *   <li>Captures payload length and decompressed length in bytes.
 *   <li>Encodes whether the payload itself is metadata.
 *   <li>Associates archive and compression settings when applicable.
 * </ul>
 *
 * @param clientMetadata client-provided metadata such as MIME type; may be {@code null}.
 * @param dataLength byte length of the splitfile payload; non-negative, in bytes.
 * @param archiveType archive container type for the payload; {@code null} when not archived.
 * @param compressionCodec compression codec applied to the payload; {@code null} for none.
 * @param decompressedLength payload length after decompression; zero when unknown or unused.
 * @param isMetadata {@code true} when payload represents nested metadata rather than content.
 * @see Metadata
 * @see SplitfileParams
 * @see MetadataTopLayerInfo
 */
public record SplitfilePayload(
    ClientMetadata clientMetadata,
    long dataLength,
    ARCHIVE_TYPE archiveType,
    COMPRESSOR_TYPE compressionCodec,
    long decompressedLength,
    boolean isMetadata) {}
