/**
 * I/O utilities and concrete implementations of data <em>buckets</em> used by the Crypta node.
 *
 * <p>This package provides disk and stream utilities together with multiple implementations of the
 * core {@link network.crypta.support.api.Bucket} and {@link
 * network.crypta.support.api.RandomAccessBucket} abstractions. Implementations cover a range of
 * storage strategies, including in-memory buffers, temporary files, file slices, read-only views,
 * padding wrappers, and helper factories for creating random-access buffers. Many classes also
 * include helpers for counting bytes, reading lines, checking free disk space, and working with
 * filenames and file metadata.
 *
 * <h2>Semantics</h2>
 *
 * <ul>
 *   <li>Buckets model temporary or ephemeral storage and typically expose a single {@code
 *       OutputStream} that writes from the beginning; appending is not part of the standard
 *       contract. See {@link network.crypta.support.api.Bucket#getOutputStream()}.
 *   <li>Reading may return {@code null} when the bucket is empty. See {@link
 *       network.crypta.support.api.Bucket#getInputStream()}.
 *   <li>Resources must be released by calling {@link network.crypta.support.api.Bucket#free()} or
 *       closing the bucket (buckets are {@link java.lang.AutoCloseable}). Some implementations
 *       delete backing files on free.
 *   <li>Random-access use cases convert a bucket via {@link
 *       network.crypta.support.api.RandomAccessBucket#toRandomAccessBuffer()} to obtain a {@link
 *       network.crypta.support.api.LockableRandomAccessBuffer} without copying.
 *   <li>Sizes and offsets are in bytes unless stated otherwise.
 *   <li>Unless otherwise documented, types in this package are not thread-safe. Coordinate access
 *       externally when sharing instances across threads.
 * </ul>
 *
 * <h2>Exceptions</h2>
 *
 * <p>Common exceptions thrown by classes in this package include:
 *
 * <ul>
 *   <li>{@link java.io.IOException} for general I/O errors.
 *   <li>{@link network.crypta.support.io.InsufficientDiskSpaceException} when a writing cannot
 *       proceed due to low disk space.
 *   <li>{@link network.crypta.support.io.FileExistsException} / {@link
 *       network.crypta.support.io.FileDoesNotExistException} for file state mismatches.
 *   <li>{@link network.crypta.support.io.StorageFormatException} and {@link
 *       network.crypta.support.io.TooLongException} for malformed or oversized inputs.
 *   <li>{@link network.crypta.support.io.ResumeFailedException} when resuming persisted state fails
 *       during {@link network.crypta.support.api.Bucket#onResume(
 *       network.crypta.client.async.ClientContext)}.
 * </ul>
 *
 * <h2>Usage Notes</h2>
 *
 * <ul>
 *   <li>Always close streams obtained from buckets (prefer try-with-resources) and call {@code
 *       free()} on buckets you own.
 *   <li>Use {@link network.crypta.support.io.DiskSpaceCheckingOutputStream} and related factories
 *       to proactively prevent running out of disk space during writes.
 *   <li>For temporary or persistent file-backed storage, see {@link
 *       network.crypta.support.io.FileBucket}, {@link network.crypta.support.io.TempFileBucket},
 *       and {@link network.crypta.support.io.PersistentTempFileBucket}. Read-only slices are
 *       provided by {@link network.crypta.support.io.ReadOnlyFileSliceBucket}.
 *   <li>For buffered random-access backed by pooled files, see {@link
 *       network.crypta.support.io.PooledFileRandomAccessBuffer} and {@link
 *       network.crypta.support.io.PooledFileRandomAccessBufferFactory}.
 *   <li>General file helpers live in {@link network.crypta.support.io.FileUtil}; datastore sizing
 *       heuristics are in {@link network.crypta.support.io.DatastoreUtil}.
 *   <li>Null stream implementations (e.g., {@link network.crypta.support.io.NullInputStream},
 *       {@link network.crypta.support.io.NullOutputStream}) can simplify edge-case handling.
 *   <li>Use {@link network.crypta.support.api.Bucket#createShadow()} to create read-only shallow
 *       copies that share underlying storage when supported.
 * </ul>
 *
 * <h2>Side Effects</h2>
 *
 * <p>Some implementations allocate files, preallocate space (see {@link
 * network.crypta.support.io.Fallocate}), or remove temporary files when freed. Ensure callers
 * handle these lifecycle events appropriately.
 *
 * <h2>See Also</h2>
 *
 * @see network.crypta.support.api.Bucket
 * @see network.crypta.support.api.RandomAccessBucket
 * @see network.crypta.support.api.LockableRandomAccessBuffer
 * @see network.crypta.support.io.FileUtil
 * @see network.crypta.support.io.DatastoreUtil
 */
package network.crypta.support.io;
