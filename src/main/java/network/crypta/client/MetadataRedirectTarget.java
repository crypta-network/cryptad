package network.crypta.client;

import network.crypta.client.ArchiveManager.ARCHIVE_TYPE;
import network.crypta.client.Metadata.DocumentType;
import network.crypta.keys.FreenetURI;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;

/**
 * Parameter bundle describing a redirect-style metadata target.
 *
 * <p>Used to construct {@link Metadata} instances that point to a single target URI. The {@code
 * documentType} should be a redirect-like type, such as {@link
 * Metadata.DocumentType#SIMPLE_REDIRECT} or {@link Metadata.DocumentType#ARCHIVE_MANIFEST}.
 */
public record MetadataRedirectTarget(
    DocumentType documentType,
    ARCHIVE_TYPE archiveType,
    COMPRESSOR_TYPE compressionCodec,
    FreenetURI uri,
    ClientMetadata clientMetadata) {}
