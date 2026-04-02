package network.crypta.runtime.updater;

import network.crypta.keys.FreenetURI;

/**
 * Immutable parameter bundle for constructing a {@link NodeUpdater} instance.
 *
 * <p>This record carries a concise snapshot of update-related settings that are already resolved by
 * the calling {@link NodeUpdateManager}. It keeps the update target URI alongside the current node
 * build and the allowed deployment range so the updater can decide what to fetch without consulting
 * configuration again. Callers typically assemble these values once during updater startup and pass
 * the record straight into the constructor, keeping the contract explicit and reducing the chance
 * of stale reads.
 *
 * <p>The record is immutable and thread-safe to share between components. It does not validate
 * ranges itself, so callers should ensure {@code min} and {@code max} reflect allowable versions
 * and that {@code current} is the active build number at the moment of creation.
 *
 * <ul>
 *   <li>Captures the update coordinator used for callbacks and lifecycle control.
 *   <li>Defines version boundaries used to accept or reject deployments.
 *   <li>Provides the blob file name prefix for persistent update artifacts.
 * </ul>
 *
 * @param manager update manager coordinating state, alerts, and policy decisions.
 * @param updateUri base URI used to resolve the update USK target.
 * @param current current build number supplied to compute suggested editions.
 * @param min minimum acceptable deployment build number for this node.
 * @param max maximum acceptable deployment build number for this node.
 * @param blobFilenamePrefix prefix for update blob filenames stored on disk.
 * @param subscribeEditionSeed initial USK edition used when subscribing for update discovery.
 * @see NodeUpdateManager
 * @see NodeUpdater
 */
public record NodeUpdaterParams(
    NodeUpdateManager manager,
    FreenetURI updateUri,
    int current,
    int min,
    int max,
    String blobFilenamePrefix,
    int subscribeEditionSeed) {}
