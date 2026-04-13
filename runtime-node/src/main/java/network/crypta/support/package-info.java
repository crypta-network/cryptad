/**
 * General-purpose utilities shared across the project.
 *
 * <p>This package collects reusable building blocks that do not depend on Crypta's networking
 * protocols. It focuses on data structures, small algorithms, encoding/decoding, lightweight
 * executors and timing helpers, and assorted support code that can be reused by other projects.
 *
 * <p>Highlights include:
 *
 * <ul>
 *   <li>Data structures and primitives: {@link network.crypta.support.LRUMap}, {@link
 *       network.crypta.support.LRUCache}, {@link network.crypta.support.BloomFilter}, {@link
 *       network.crypta.support.CountingBloomFilter}, {@link network.crypta.support.BitArray},
 *       {@link network.crypta.support.IdentityHashSet}.
 *   <li>Concurrency and scheduling helpers: {@link network.crypta.support.PooledExecutor}, {@link
 *       network.crypta.support.PriorityAwareExecutor}, {@link
 *       network.crypta.support.PrioritizedSerialExecutor}, {@link network.crypta.support.Ticker}
 *       and related tickers.
 *   <li>Encoding and text utilities: {@link network.crypta.support.Base64}, {@link
 *       network.crypta.support.HTMLEncoder}, {@link network.crypta.support.HTMLDecoder}, {@link
 *       network.crypta.support.URLEncoder}.
 *   <li>Containers and measurement helpers: {@link network.crypta.support.SizeUtil}.
 *   <li>Streams and wrappers: {@link network.crypta.support.ByteBufferInputStream} and related
 *       small utilities.
 * </ul>
 *
 * <p>Related subpackages:
 *
 * <ul>
 *   <li>{@link network.crypta.support.io} — file and buffer abstractions, disk-space checking, and
 *       random-access utilities.
 *   <li>{@link network.crypta.support.compress} — compression/decompression APIs and
 *       implementations (e.g., GZIP, BZip2, LZMA).
 *   <li>{@link network.crypta.support.transport.ip} — host/IP parsing and utilities.
 * </ul>
 *
 * <h2>Usage notes</h2>
 *
 * <ul>
 *   <li><strong>Thread-safety:</strong> Threading guarantees are documented per type. Do not assume
 *       concurrent use is safe unless stated; prefer external synchronization or concurrent
 *       collections where appropriate.
 *   <li><strong>Nullability:</strong> Unless an API explicitly documents support for {@code null},
 *       inputs are expected to be non-null and may raise {@link java.lang.NullPointerException}
 *       when violated.
 *   <li><strong>Units and limits:</strong> Byte sizes are in bytes unless a method states
 *       otherwise. Algorithmic complexity and bounds are described on the individual classes when
 *       notable.
 *   <li><strong>Independence:</strong> The code here avoids dependencies on node-specific logic to
 *       keep it broadly reusable.
 * </ul>
 *
 * @since 2
 */
package network.crypta.support;
