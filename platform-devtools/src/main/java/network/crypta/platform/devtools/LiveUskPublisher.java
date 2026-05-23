package network.crypta.platform.devtools;

import java.io.IOException;

/**
 * Inserts validated catalog sidecars through a configured live-node workflow.
 *
 * <p>The interface keeps the live insertion boundary injectable. Production uses the localhost
 * Platform API queue route, while tests can provide an in-memory implementation that records the
 * sanitized request shape without contacting a daemon. The request necessarily carries sensitive
 * one-call insertion material and a local staging directory; the response is the point where that
 * material must be reduced to sanitized status labels, public fetch metadata, and bounded warnings.
 * Implementations must not log, stringify, or return private insert URIs, form passwords, local
 * staging paths, request bodies, or node response bodies.
 */
@FunctionalInterface
interface LiveUskPublisher {
  /**
   * Publishes catalog and signature sidecars.
   *
   * @param request live insertion request carrying credentials and staged sidecars for this call
   *     only
   * @return sanitized publication status reported by the insertion workflow
   * @throws IOException when the configured live-node endpoint cannot be reached or the adapter
   *     cannot complete its configured I/O
   */
  LiveUskPublishResponse publish(LiveUskPublishRequest request) throws IOException;
}
