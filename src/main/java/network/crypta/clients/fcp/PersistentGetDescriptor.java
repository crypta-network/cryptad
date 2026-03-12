package network.crypta.clients.fcp;

import java.io.File;
import network.crypta.clients.fcp.ClientGet.ReturnType;

/**
 * Immutable metadata describing the return handling and status of a persistent get request.
 *
 * @param returnType delivery strategy for the request payload
 * @param targetFile disk destination used when {@link ReturnType#DISK} is selected
 * @param started whether the request has already been scheduled or begun transfer
 * @param maxRetries maximum retries allowed before the node abandons the request
 * @param binaryBlob whether binary blob tracking is enabled for the response
 * @param maxSize upper bound in bytes for the payload the client accepts
 */
public record PersistentGetDescriptor(
    ReturnType returnType,
    File targetFile,
    boolean started,
    int maxRetries,
    boolean binaryBlob,
    long maxSize) {}
