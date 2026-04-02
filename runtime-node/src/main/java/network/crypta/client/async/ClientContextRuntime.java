package network.crypta.client.async;

import java.util.Random;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;

/**
 * Bundles runtime services and random/crypto state needed to execute client operations.
 *
 * <p>This record groups the executors, schedulers, and randomness sources that power client-layer
 * tasks. It keeps high-frequency dependencies together so {@link ClientContext} construction can
 * stay focused and call sites can reuse a shared parameter object.
 *
 * @param jobRunner persistence-aware job runner used for durable work queues
 * @param mainExecutor priority-aware executor for client-layer scheduling
 * @param memoryLimitedJobRunner runner for memory-intensive tasks such as in-RAM FEC work
 * @param ticker time source and scheduler for timed jobs
 * @param strongRandom cryptographically strong random source for protocol-level randomness
 * @param fastWeakRandom non-cryptographic random source for jitter and lightweight decisions
 * @param cryptoSecretTransient transient master secret used for runtime crypto operations
 */
public record ClientContextRuntime(
    ClientLayerPersister jobRunner,
    PriorityAwareExecutor mainExecutor,
    MemoryLimitedJobRunner memoryLimitedJobRunner,
    Ticker ticker,
    RandomSource strongRandom,
    Random fastWeakRandom,
    MasterSecret cryptoSecretTransient) {}
