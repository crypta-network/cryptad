/**
 * Runtime-owned FCP endpoint bootstrap glue.
 *
 * <p>This package adapts daemon- and runtime-backed services to the narrow runtime-support seams
 * defined in {@code network.crypta.clients.fcp}. The types here exist to keep remaining {@code
 * NodeClientCore}-backed FCP bootstrap, persistence-bridge, and queue download/insert/completion
 * SPI wiring under runtime ownership while preserving the current protocol behavior and without
 * widening {@code runtime-spi}.
 */
package network.crypta.runtime.endpoints.fcp;
