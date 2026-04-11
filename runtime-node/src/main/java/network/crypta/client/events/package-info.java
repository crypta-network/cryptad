/**
 * Runtime-owned residue in the client event layer.
 *
 * <p>The compile-neutral event contracts, helper listeners, simple producer, and progress helpers
 * now live in {@code :kernel-content}. This runtime package currently retains only the
 * compatibility-mode event that still depends on runtime-owned content context types.
 */
package network.crypta.client.events;
