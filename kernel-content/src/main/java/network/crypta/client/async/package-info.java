/**
 * Compile-neutral async utility and value types used by the client/content layer.
 *
 * <p>This package holds the small leaf-safe subset of the asynchronous client helpers that can be
 * compiled in {@code :kernel-content} without depending on the runtime node body. The leaf keeps
 * shared binary-blob helpers, lightweight option/value types, and the async block-set abstraction
 * here while the request engines and runtime-only coordination remain in {@code :runtime-node}.
 */
package network.crypta.client.async;
