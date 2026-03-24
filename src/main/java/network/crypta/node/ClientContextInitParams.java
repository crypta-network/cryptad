package network.crypta.node;

import java.util.Random;
import network.crypta.client.FetchContext;
import network.crypta.client.InsertContext;
import network.crypta.client.async.ClientLayerPersister;
import network.crypta.client.async.DatastoreChecker;
import network.crypta.client.async.USKManager;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.runtime.endpoints.NodeClientCoreInit;
import network.crypta.runtime.endpoints.NodeClientPersistence;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.compress.RealCompressor;
import network.crypta.support.io.FileRandomAccessBufferFactory;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.MaybeEncryptedRandomAccessBufferFactory;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.TempBucketFactory;

/**
 * Bundles inputs required to build a client {@link network.crypta.client.async.ClientContext}.
 *
 * <p>This record captures the dependencies that {@link NodeClientPersistence#createClientContext}
 * needs when wiring a fully configured client context during node startup. It provides a single,
 * immutable carrier for runtime services, storage factories, and default request templates so call
 * sites can assemble the prerequisites once and pass them through without repeating a long argument
 * list. Instances are typically created during {@link NodeClientCore} construction and remain
 * stable for the life of the client context they configure.
 *
 * <p>All references are stored as provided. The record performs no validation or defensive copying,
 * so callers must ensure consistency between fields (for example, matching factory and filename
 * generator pairs). Thread-safety and lifecycle management are inherited from the referenced
 * collaborators. Because the record is immutable, it is safe to share across threads once
 * constructed, but the referenced objects may still require external synchronization.
 *
 * <ul>
 *   <li>Groups runtime scheduling, randomness, and encryption inputs.
 *   <li>Collects storage factories and filename generators for transient and persistent data.
 *   <li>Provides default fetch/insert contexts and configuration linkage.
 * </ul>
 *
 * @param clientLayerPersister runner that serializes durable client jobs; must match the node.
 * @param executor priority-aware executor that schedules core client-layer tasks and callbacks.
 * @param resources archive manager and healing queue bundle used by client services.
 * @param persistentTempBucketFactory factory for persistent temp buckets and file tracking.
 * @param tempBucketFactory factory for transient temp buckets and in-memory limits.
 * @param uskManager manager coordinating USK updates and background maintenance.
 * @param random strong random source for cryptographic and protocol-critical operations.
 * @param fastWeakRandom fast non-cryptographic random source used for jitter and sampling.
 * @param ticker scheduler that queues timed client jobs; must align with the executor.
 * @param memoryLimitedJobRunner runner constraining memory-intensive background operations.
 * @param tempFilenameGenerator generator for transient temp filenames and identifier tokens.
 * @param persistentFilenameGenerator generator for persistent on-disk temp filenames.
 * @param tempRafFactory factory for transient random-access buffers; typically unencrypted.
 * @param persistentRafFactory factory for persistent random-access buffers, optionally encrypted.
 * @param fileRafTransient file-backed RAF factory for transient allocations and streaming.
 * @param compressor compressor implementation used for client-side data pipelines.
 * @param storeChecker datastore checker for verification and background checking operations.
 * @param cryptoSecretTransient transient master secret for encrypting the process-lifetime buffers.
 * @param init initialization bundle providing configuration and toadlet container access.
 * @param defaultFetchContext default fetch context template for persistent requests.
 * @param defaultInsertContext default insert context template for persistent requests.
 * @see NodeClientPersistence#createClientContext
 * @see ClientContextResources
 * @see NodeClientCoreInit
 */
public record ClientContextInitParams(
    ClientLayerPersister clientLayerPersister,
    PriorityAwareExecutor executor,
    ClientContextResources resources,
    PersistentTempBucketFactory persistentTempBucketFactory,
    TempBucketFactory tempBucketFactory,
    USKManager uskManager,
    RandomSource random,
    Random fastWeakRandom,
    Ticker ticker,
    MemoryLimitedJobRunner memoryLimitedJobRunner,
    FilenameGenerator tempFilenameGenerator,
    FilenameGenerator persistentFilenameGenerator,
    LockableRandomAccessBufferFactory tempRafFactory,
    MaybeEncryptedRandomAccessBufferFactory persistentRafFactory,
    FileRandomAccessBufferFactory fileRafTransient,
    RealCompressor compressor,
    DatastoreChecker storeChecker,
    MasterSecret cryptoSecretTransient,
    NodeClientCoreInit init,
    FetchContext defaultFetchContext,
    InsertContext defaultInsertContext) {}
