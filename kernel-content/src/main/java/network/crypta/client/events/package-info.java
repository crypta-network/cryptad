/**
 * Compile-neutral client event contracts and value types extracted into {@code :kernel-content}.
 *
 * <p>This package owns the listener/producer contracts, the simple in-process producer and helper
 * listeners, the narrow dispatch seam used during event delivery, and the leaf-safe event value
 * subset that stays free of runtime-node, adapter, and root-composition dependencies. That subset
 * now includes the detached splitfile compatibility event and its detached compatibility-mode enum.
 */
package network.crypta.client.events;
