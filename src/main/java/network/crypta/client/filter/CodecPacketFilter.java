package network.crypta.client.filter;

import java.io.IOException;

/**
 * Defines a pluggable validator/normalizer that inspects a single codec packet and optionally
 * returns a refined representation. Implementations are typically chained so each filter can
 * perform a small, well-bounded check before handing the packet to the next stage.
 *
 * <p>The primary responsibility of a {@code CodecPacketFilter} is to perform minimal structural and
 * semantic validation of a packet produced by a codec or demuxer. Typical call patterns involve
 * receiving a {@link CodecPacket} from an upstream component, verifying header fields, length, or
 * basic invariants, and either returning the same packet, returning a logically equivalent packet,
 * or signaling failure via an exception. Implementations should avoid expensive transformations;
 * deeper parsing and decoding belong to higher-level components.
 *
 * <p>Unless otherwise documented by a concrete implementation, instances are expected to be
 * stateless and thus thread-safe. Filters should not mutate the supplied packet unless the class of
 * the packet clearly documents such behavior; returning a new {@link CodecPacket} instance is often
 * preferred to preserve isolation between stages.
 *
 * <ul>
 *   <li>Responsibility: perform fast, early validation of packet shape and size.
 *   <li>Error handling: report malformed input using {@link IOException} with a descriptive
 *       message.
 *   <li>Typical usage: assemble a pipeline of filters that each enforce a specific invariant.
 * </ul>
 *
 * @author sajack
 * @see CodecPacket
 */
public interface CodecPacketFilter {

  /**
   * Validates and optionally normalizes a single packet from a coded stream.
   *
   * <p>Implementations should perform lightweight checks such as verifying basic header structure,
   * ensuring lengths are within acceptable bounds, or rejecting obviously malformed input. On
   * success the method returns a packet instance that can be passed to subsequent components; it
   * may be the original instance or a newly created, logically equivalent packet. When a fatal
   * condition is detected, the method throws an {@link IOException} describing the failure.
   * Implementations should not perform heavy decoding or re-encoding work here.
   *
   * <pre>{@code
   * // Example: invoke a filter before consumption
   * CodecPacket validated = filter.parse(rawPacket);
   * consume(validated);
   * }</pre>
   *
   * @param packet the input packet from the coded stream; must not be {@code null}; contents are
   *     expected to represent a single, self-contained frame or unit as defined by the codec
   * @return a validated packet suitable for downstream processing; may be the same reference or a
   *     new instance preserving the original payload semantics
   * @throws IOException if the packet is structurally invalid, violates basic invariants, or cannot
   *     be safely forwarded to the next processing stage
   */
  CodecPacket parse(CodecPacket packet) throws IOException;
}
