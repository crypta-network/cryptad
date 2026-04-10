/**
 * Compile-neutral client content helpers extracted into {@code :kernel-content}.
 *
 * <p>This package owns leaf-safe client value and failure types, including the fetch/insert
 * exception surface and failure-code tracking helpers that higher layers can use without pulling in
 * the runtime-node request engine.
 */
package network.crypta.client;
