/**
 * Probe request handling, listener dispatch, and probe-local aggregation helpers.
 *
 * <p>This package contains the runtime logic behind node probes: the classes that accept probe
 * work, track counters, and notify listeners about probe-specific activity. The data types that
 * define probe wire-level categories stay in the narrower interoperability layer, while this
 * package keeps the daemon-backed execution and bookkeeping that depend on the live node state.
 *
 * <p>The package remains adjacent to the main node runtime because probes are part of node
 * introspection and operational visibility, not a detached adapter API. It should stay focused on
 * executing and reporting probe flows rather than rendering operator-facing output.
 */
package network.crypta.node.probe;
