package network.crypta.clients.fcp;

import java.io.File;
import network.crypta.clients.fcp.ClientGet.ReturnType;
import network.crypta.keys.FreenetURI;

/**
 * Prepared request specification used when attempting a persistent global fetch registration.
 *
 * @param fetchURI URI representing the resource to fetch.
 * @param filterData whether to filter the fetched data before exposure to the client.
 * @param persistRebootOnly whether the request should persist only across reboots.
 * @param returnType return handling mode.
 * @param identifier identifier selected for the request.
 * @param returnFilename filename used when returning data to disk.
 * @param realTimeFlag whether the request should be treated as real-time.
 */
record PersistentGlobalRequestSpec(
    FreenetURI fetchURI,
    boolean filterData,
    boolean persistRebootOnly,
    ReturnType returnType,
    String identifier,
    File returnFilename,
    boolean realTimeFlag) {}
