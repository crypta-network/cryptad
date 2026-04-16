package network.crypta.clients.fcp;

import network.crypta.keys.FreenetURI;

/**
 * Carries the detached, wire-facing state for one flattened manifest entry in a persistent
 * directory insert.
 *
 * <p>{@link PersistentPutDir} serializes directory inserts as a flat {@code Files.N} field set, but
 * the live request path holds richer runtime-owned manifest trees and bucket wrappers. This record
 * is the adapter-owned boundary object between those two representations. Bridge/runtime code
 * classifies each live entry into one of the supported FCP upload-source forms and records only the
 * data that the wire format actually needs. The adapter can then replay persistent directory
 * requests without depending directly on runtime-owned manifest classes.
 *
 * <p>The fields intentionally allow sparse combinations because the FCP wire format itself is
 * sparse. Redirect entries use {@link #targetUri()} and ignore filename data. Disk-backed entries
 * use {@link #filename()} to preserve the original on-disk source path. Direct entries omit both.
 * When the bridge cannot represent an upload source faithfully, it may leave {@link #uploadFrom()}
 * as {@code null} so the serializer can omit the field instead of inventing a misleading value.
 *
 * @param name flattened manifest path relative to the directory root, for example {@code
 *     "subdir/file.txt"}
 * @param uploadFrom FCP upload-source classification for this entry, or {@code null} when the
 *     serializer should omit the field rather than misclassify the source
 * @param dataLength source payload length in bytes, or {@code -1} for redirect-style entries that
 *     do not carry file payload data
 * @param filename original disk filename for {@link ClientPutBase.UploadFrom#DISK} entries, or
 *     {@code null} when the entry is not represented as a disk-backed upload
 * @param mimeTypeOverride explicit MIME override that should become {@code Metadata.ContentType},
 *     or {@code null} when the wire output should omit that field
 * @param targetUri redirect destination for {@link ClientPutBase.UploadFrom#REDIRECT} entries, or
 *     {@code null} when the entry is not a redirect
 */
public record PersistentPutDirEntrySnapshot(
    String name,
    ClientPutBase.UploadFrom uploadFrom,
    long dataLength,
    String filename,
    String mimeTypeOverride,
    FreenetURI targetUri) {}
