package network.crypta.clients.fcp;

import network.crypta.client.FetchContext;
import network.crypta.support.api.Bucket;

/**
 * Immutable constructor bundle for a validated {@link ClientGet}.
 *
 * <p>The factory resolves the fetch context, return plan, optional metadata bucket, and runtime
 * support before invoking the request constructor, then stores that assembly state in this record.
 * This keeps request wiring distinct from the request's own lifecycle code, which only needs to
 * consume already-validated inputs. The record is package-local because it exists only to simplify
 * construction flow inside {@code clients.fcp}; it is not part of the FCP protocol surface.
 *
 * <p>The values are intended to be complete and final for a single request instance. Callers do not
 * mutate or enrich the record later, so a {@link ClientGet} can treat each component as the
 * authoritative setup decided by the factory stage.
 *
 * @param fetchContext fully prepared fetch context that should be used by the request
 * @param returnSetup resolved return-handling plan, including any bucket or target file
 * @param returnType requested return mode that controls how fetched data is exposed
 * @param binaryBlob whether the request should produce Binary Blob output
 * @param initialMetadata optional metadata bucket supplied by the caller before the fetch starts
 * @param fetchRuntimeSupport runtime support seam used for getter creation and request start
 */
record ClientGetSetup(
    FetchContext fetchContext,
    ClientGetReturnPlanner.ReturnSetup returnSetup,
    ClientGet.ReturnType returnType,
    boolean binaryBlob,
    Bucket initialMetadata,
    FcpFetchRuntimeSupport fetchRuntimeSupport) {}
