package network.crypta.clients.fcp;

import network.crypta.client.events.ClientEventListener;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;

/**
 * Detached execution descriptor used to create a live GET fetcher behind the adapter-owned seam.
 *
 * <p>This record is the last adapter-owned representation before control passes into {@link
 * FcpFetchRuntimeSupport}. It collects the request-scoped values that the bridge needs to build a
 * concrete runtime fetcher while keeping the adapter independent of daemon-owned execution classes.
 * The descriptor is intentionally immutable, so persistence, restart, and constructor code can hand
 * the same logical state to the runtime bridge without worrying about concurrent mutation while the
 * live execution is being assembled.
 *
 * <p>Several fields are related and should be read together. {@code returnBucket} is the caller's
 * chosen payload bucket when ordinary return data is expected. {@code discardData} signals the
 * special FCP mode where ordinary payload bytes should be thrown away. {@code binaryBlob} indicates
 * that Binary Blob recording is active, in which case the runtime may use {@code returnBucket} for
 * blob output or allocate equivalent storage itself. {@code persistenceForever} carries the bucket
 * allocation policy that must remain compatible with the existing persistent GET behavior.
 *
 * @param request owning request that receives fetch callbacks and lifecycle updates from the live
 *     execution.
 * @param uri target key that the runtime fetcher should request.
 * @param priorityClass scheduler priority class that should be applied to the runtime fetcher.
 * @param fetchConfig detached fetch configuration snapshot for this request attempt.
 * @param returnBucket caller-selected bucket for returned data, or {@code null} when no ordinary
 *     payload bucket is needed yet.
 * @param discardData whether ordinary payload data should be discarded instead of being returned to
 *     the caller.
 * @param binaryBlob whether Binary Blob recording is enabled for this execution attempt.
 * @param persistenceForever whether runtime bucket allocation should use the forever-persistent
 *     policy instead of transient or reboot-only storage.
 * @param initialMetadata optional initial metadata bucket that should be presented to the runtime
 *     fetcher before network activity begins.
 * @param extensionCheck optional extension hint used by filtered disk-return handling.
 * @param eventListener listener that should receive fetch-context events emitted by the runtime
 *     fetcher.
 */
public record ClientGetExecutionSpec(
    ClientGet request,
    FreenetURI uri,
    short priorityClass,
    ClientGetFetchConfig fetchConfig,
    Bucket returnBucket,
    boolean discardData,
    boolean binaryBlob,
    boolean persistenceForever,
    Bucket initialMetadata,
    String extensionCheck,
    ClientEventListener eventListener) {}
