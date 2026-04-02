package network.crypta.clients.fcp;

import java.io.File;
import network.crypta.keys.FreenetURI;

/**
 * Parameter bundle describing a global persistent fetch request.
 *
 * <p>The record groups the request inputs so callers can reuse a single configuration when
 * scheduling or enqueuing global requests.
 *
 * @param fetchURI URI identifying the resource to fetch.
 * @param filterData whether to filter the fetched data before exposing it to clients.
 * @param expectedMimeType optional MIME hint used when deriving disk filenames.
 * @param persistenceType string describing the persistence policy.
 * @param returnType string describing where the result should be delivered.
 * @param realTimeFlag whether the request should be treated as real-time.
 * @param downloadsDir target directory for disk returns; may be {@code null} when not used.
 */
public record PersistentGlobalRequestParams(
    FreenetURI fetchURI,
    boolean filterData,
    String expectedMimeType,
    String persistenceType,
    String returnType,
    boolean realTimeFlag,
    File downloadsDir) {}
