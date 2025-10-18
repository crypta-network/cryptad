/**
 * Transfer layer for block and bulk data plus parts of congestion control.
 *
 * <p>A "block" is a CHK, typically 32 KiB split into 1 KiB packets. "Bulk" refers to other payloads
 * such as opennet node references and friend-to-friend file transfers. The original block-transfer
 * code was derived from Dijjer, but it has since been substantially rewritten as the lower layers
 * provide guaranteed delivery of {@link network.crypta.io.comm.Message} instances. Additional
 * congestion-control components live under {@link network.crypta.node}.
 */
package network.crypta.io.xfer;
