/**
 * Local app-to-app service discovery, grant, and mediated invocation support.
 *
 * <p>The package parses optional signed manifest service metadata, stores operator-approved local
 * grants, and dispatches calls only to built-in bounded adapters. It intentionally does not expose
 * generic RPC, arbitrary localhost proxying, provider app-data access, process tokens, private
 * insert URIs, raw request bodies, or local filesystem paths.
 *
 * <p>The package is organized around three small surfaces:
 *
 * <ul>
 *   <li>Manifest descriptors, represented by {@link
 *       network.crypta.platform.api.appservices.AppServiceDescriptor} and {@link
 *       network.crypta.platform.api.appservices.AppServiceRequestDescriptor}.
 *   <li>Durable grant and audit records, represented by {@link
 *       network.crypta.platform.api.appservices.AppServiceGrant} and {@link
 *       network.crypta.platform.api.appservices.AppServiceAuditEvent}.
 *   <li>Explicit platform adapters, represented by {@link
 *       network.crypta.platform.api.appservices.AppServiceAdapter}.
 * </ul>
 *
 * <p>The coordinator recomputes installed service availability from AppHost state and checks the
 * stored grant at invocation time. A grant id is local metadata, not a bearer token. Revocation,
 * provider uninstall, provider manifest changes, and consumer permission changes therefore affect
 * future calls without trusting a browser's cached view of service status.
 *
 * <p>Context semantics are deliberately strict. A provider descriptor with contexts is a contextual
 * service and requires explicit grant and invocation contexts. A descriptor without contexts is
 * unscoped and accepts only unscoped grants. Empty context lists are never used as a wildcard for a
 * contextual service.
 */
package network.crypta.platform.api.appservices;
