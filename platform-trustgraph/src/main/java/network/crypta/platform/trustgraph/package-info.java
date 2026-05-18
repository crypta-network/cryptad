/**
 * Local Trust Graph Preview model, validation, and deterministic scoring.
 *
 * <p>This package owns the bounded trust-statement document shape used by the app-platform preview.
 * It is intentionally independent of daemon runtime, routing, datastore, FCP, FNP, and legacy WoT
 * implementation classes. Trust data is represented as Crypta content documents and local
 * process-owned anchors; scoring is deterministic and deliberately small.
 *
 * <p>The model supports direct statements, signature verification with inline public issuer keys,
 * local trust anchors, bounded evidence summaries, and confidence-weighted scoring for exact
 * subject/context queries. It does not crawl the network, discover keys, compute transitive
 * reputation, hide content, or publish anchor changes automatically. Those limits are part of the
 * preview contract and keep the trust layer outside the daemon/network core.
 */
package network.crypta.platform.trustgraph;
