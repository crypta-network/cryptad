package network.crypta.client.async;

import network.crypta.client.async.persistence.PersistentRequestCoordinator;
import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.node.ClientContextResources;
import network.crypta.support.compress.RealCompressor;

/**
 * Collects shared services wired into {@link ClientContext} beyond storage and executors.
 *
 * <p>This record keeps related service collaborators together, including archive/healing resources
 * and managers that are consulted by client operations.
 *
 * @param resources archive manager and healing queue bundle
 * @param uskManager manager for USK coordination and updates
 * @param compressor compressor implementation used in client pipelines
 * @param checker datastore checker used for verification work
 * @param persistentRequestCoordinator persistent request coordinator for durable request ownership
 * @param linkFilterExceptionProvider provider for link filter exceptions
 */
public record ClientContextServices(
    ClientContextResources resources,
    USKManager uskManager,
    RealCompressor compressor,
    DatastoreChecker checker,
    PersistentRequestCoordinator persistentRequestCoordinator,
    LinkFilterExceptionProvider linkFilterExceptionProvider) {}
