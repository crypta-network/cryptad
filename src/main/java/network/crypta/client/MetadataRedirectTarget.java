package network.crypta.client;

import network.crypta.client.ArchiveManager.ARCHIVE_TYPE;
import network.crypta.client.Metadata.DocumentType;
import network.crypta.keys.FreenetURI;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;

/**
 * Carries the target details for redirect-style {@link Metadata} entries.
 *
 * <p>This record groups the values needed to construct redirect-like metadata, including the
 * document type, optional archive and compression context, the target {@link FreenetURI}, and
 * client-provided metadata such as MIME type. It is typically created by insert or manifest
 * building code and passed to {@link Metadata#Metadata(MetadataRedirectTarget,
 * MetadataTopLayerInfo)}. The record is intentionally simple: it preserves the caller's inputs and
 * does not enforce validation or normalization beyond what the consuming constructor performs.
 *
 * <p>Instances are immutable, but referenced objects may not be. Callers should treat the supplied
 * {@link FreenetURI} and {@link ClientMetadata} as stable for the duration of metadata creation to
 * avoid inconsistencies during serialization or logging. Nullability is allowed where a field does
 * not apply (for example, {@code archiveType} on non-archive redirects).
 *
 * <ul>
 *   <li>Identifies the redirect-style document type.
 *   <li>Captures archive and compression context when relevant.
 *   <li>Associates a single target URI and optional client metadata.
 * </ul>
 *
 * @param documentType redirect-like document type; must match the intended metadata variant.
 * @param archiveType archive container type for archive redirects; {@code null} when unused.
 * @param compressionCodec compression codec for archive payloads; {@code null} when not applicable.
 * @param uri target URI referenced by the metadata entry; must not be {@code null}.
 * @param clientMetadata client metadata such as MIME type; may be {@code null}.
 * @see Metadata
 * @see MetadataTopLayerInfo
 */
public record MetadataRedirectTarget(
    DocumentType documentType,
    ARCHIVE_TYPE archiveType,
    COMPRESSOR_TYPE compressionCodec,
    FreenetURI uri,
    ClientMetadata clientMetadata) {}
