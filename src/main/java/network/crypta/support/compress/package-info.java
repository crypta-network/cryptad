/**
 * Compression utilities and abstractions for single-file data streams.
 *
 * <p>This package does not implement low-level codecs itself; instead it exposes a common
 * interface, helpers, and orchestration for codec implementations. Concrete algorithms (for
 * example, GZIP, BZIP2, and LZMA variants) live in classes that implement {@link
 * network.crypta.support.compress.Compressor}. The scope is single-file compression (like {@code
 * gzip} or {@code bzip2}), not archive formats (such as {@code zip} or {@code tar}).
 *
 * <h2>Key types</h2>
 *
 * <ul>
 *   <li>{@link network.crypta.support.compress.Compressor} — main abstraction for streaming
 *       compression and decompression; see {@link
 *       network.crypta.support.compress.Compressor#compress(java.io.InputStream,
 *       java.io.OutputStream, long, long)} and {@link
 *       network.crypta.support.compress.Compressor#decompress(java.io.InputStream,
 *       java.io.OutputStream, long, long)}.
 *   <li>{@link network.crypta.support.compress.Compressor.COMPRESSOR_TYPE} — selection and
 *       descriptor utilities; provides ready-to-use codec instances and parsing of user-provided
 *       codec lists.
 *   <li>{@link network.crypta.support.compress.DecompressorThreadManager} — builds and executes a
 *       chain of decompressors on background threads, wiring stages with {@link
 *       java.io.PipedInputStream}/{@link java.io.PipedOutputStream}.
 *   <li>Implementations: {@link network.crypta.support.compress.GzipCompressor}, {@link
 *       network.crypta.support.compress.Bzip2Compressor}, {@link
 *       network.crypta.support.compress.NewLZMACompressor}, and the legacy {@link
 *       network.crypta.support.compress.OldLZMACompressor} (kept only for reinserting historical
 *       data; not recommended for new content).
 * </ul>
 *
 * <h2>Behavior and contracts</h2>
 *
 * <ul>
 *   <li>Unless otherwise documented, all byte counts are in bytes; limits are inclusive. Callers
 *       should pass sensible {@code maxReadLength}/{@code maxWriteLength} bounds to defend against
 *       unbounded growth and denial-of-service inputs.
 *   <li>Stream ownership: implementations generally do not close the input or output streams.
 *       Closing/flush behavior can vary by codec; consult the concrete class if lifecycle matters
 *       in your use case.
 *   <li>Nullability: passing a {@code null} compressor descriptor to the parsing helpers in {@link
 *       network.crypta.support.compress.Compressor.COMPRESSOR_TYPE} selects the default set of
 *       codecs (currently all but legacy {@code LZMA}).
 *   <li>Ordering: when using {@link network.crypta.support.compress.DecompressorThreadManager},
 *       decompressors are applied in reverse list order; the last element in the list runs first.
 * </ul>
 *
 * <h2>Threading</h2>
 *
 * <p>{@link network.crypta.support.compress.DecompressorThreadManager} starts one worker thread per
 * stage, connects them via pipes, and returns the final {@link java.io.PipedInputStream} for the
 * caller to read uncompressed bytes. Public methods are synchronized to serialize state transitions
 * and error delivery. The manager signals completion via {@link
 * network.crypta.support.compress.DecompressorThreadManager#onFinish()} and exposes the first
 * terminal failure via {@link
 * network.crypta.support.compress.DecompressorThreadManager#getError()}. Instances of individual
 * compressor implementations are not guaranteed to be thread-safe; prefer one instance per active
 * pipeline.
 *
 * <h2>Exceptions</h2>
 *
 * <p>In addition to {@link java.io.IOException}, codecs and helpers may throw the following
 * package-specific exceptions:
 *
 * <ul>
 *   <li>{@link network.crypta.support.compress.CompressionOutputSizeException} — the compressed or
 *       decompressed output would exceed a configured limit or buffer capacity.
 *   <li>{@link network.crypta.support.compress.CompressionInputSizeException} — input exceeds a
 *       configured limit.
 *   <li>{@link network.crypta.support.compress.CompressionRatioException} — a minimum compression
 *       effectiveness check failed.
 *   <li>{@link network.crypta.support.compress.InvalidCompressedDataException} — input is malformed
 *       or violates codec-specific invariants.
 *   <li>{@link network.crypta.support.compress.InvalidCompressionCodecException} — a codec
 *       identifier or descriptor is unknown or invalid.
 *   <li>{@link network.crypta.support.compress.TooBigDictionaryException} — dictionary parameters
 *       are too large for the LZMA family.
 * </ul>
 *
 * <h2>Usage examples</h2>
 *
 * <p>Compress to an {@link java.io.OutputStream} with bounds:
 *
 * <pre>{@code
 * long written = Compressor.COMPRESSOR_TYPE.GZIP.compress(
 *     inputStream, outputStream, maxReadBytes, maxWriteBytes);
 * }</pre>
 *
 * <p>Decompress a pipeline of codecs using {@link
 * network.crypta.support.compress.DecompressorThreadManager}:
 *
 * <pre>{@code
 * // Build the pipeline in the order the data was compressed (outermost first).
 * var codecs = new java.util.ArrayList<Compressor>();
 * codecs.add(Compressor.COMPRESSOR_TYPE.BZIP2);
 * codecs.add(Compressor.COMPRESSOR_TYPE.GZIP);
 *
 * var head = new PipedInputStream();
 * var feeder = new PipedOutputStream(head); // application writes compressed bytes here
 * var manager = new DecompressorThreadManager(head, codecs, expectedMaxUncompressed);
 * PipedInputStream plain = manager.execute();
 * // ...read from plain... then surface late errors:
 * manager.waitFinished();
 * }</pre>
 *
 * <h2>Compatibility</h2>
 *
 * <p>The legacy {@code LZMA} implementation is retained solely for reinserting historical content
 * and is ignored when mixed with other codecs in a descriptor. Prefer {@link
 * network.crypta.support.compress.NewLZMACompressor} for any new data.
 *
 * @see network.crypta.client.async.InsertCompressor
 */
package network.crypta.support.compress;
