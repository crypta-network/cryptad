package network.crypta.clients.fcp;

import java.util.Objects;

/**
 * Immutable outcome of resolving an FCP node identifier through the adapter-runtime seam.
 *
 * <p>This value object captures exactly the peer lookup distinctions that the residual FCP message
 * handlers need to preserve their pre-refactor behavior. A lookup may fail entirely, may resolve a
 * peer that exists but cannot participate in darknet-only feed operations, or may resolve a darknet
 * peer that is safe to expose through the narrow {@link FcpDarknetPeerHandle} contract. By making
 * those states explicit, the adapter can keep its protocol branching readable without importing
 * runtime-owned peer types back into {@code :adapter-fcp}.
 *
 * <p>The class is intentionally small and immutable. Unknown and non-darknet outcomes are shared
 * singleton instances because they carry no per-request state. Darknet outcomes wrap a validated
 * handle supplied by the bridge layer. Callers usually inspect {@link #kind()} or one of the
 * convenience predicates and then either emit the existing protocol response or continue with feed
 * delivery. The result does not cache peer metadata beyond what the message layer already needs.
 *
 * <ul>
 *   <li>{@link Kind#UNKNOWN} still maps naturally to {@link UnknownNodeIdentifierMessage}.
 *   <li>{@link Kind#NON_DARKNET} still leads to the existing {@code DARKNET_ONLY} protocol error.
 *   <li>{@link Kind#DARKNET} exposes only the feed operations the message layer may invoke.
 * </ul>
 *
 * @see FcpMessageRuntimeSupport#findPeer(String)
 * @see FcpDarknetPeerHandle
 */
public final class FcpPeerLookupResult {

  /**
   * High-level categories of peer lookup outcomes visible to the message layer.
   *
   * <p>The enum mirrors protocol-visible behavior instead of daemon internals. It lets callers make
   * explicit decisions about reply handling without depending on concrete runtime peer classes.
   * Most call sites should branch on these values only at the outer protocol boundary and then use
   * the convenience methods or {@link #requireDarknetPeerHandle()} for the happy path.
   */
  public enum Kind {
    /** No currently known peer matched the supplied FCP node identifier. */
    UNKNOWN,
    /** A matching peer exists but does not support darknet-only feed operations. */
    NON_DARKNET,
    /** A matching darknet peer was found and exposed as an adapter-owned handle. */
    DARKNET
  }

  private static final FcpPeerLookupResult UNKNOWN_RESULT =
      new FcpPeerLookupResult(Kind.UNKNOWN, null);
  private static final FcpPeerLookupResult NON_DARKNET_RESULT =
      new FcpPeerLookupResult(Kind.NON_DARKNET, null);

  private final Kind kind;
  private final FcpDarknetPeerHandle darknetPeerHandle;

  private FcpPeerLookupResult(Kind kind, FcpDarknetPeerHandle darknetPeerHandle) {
    this.kind = Objects.requireNonNull(kind);
    if (kind == Kind.DARKNET) {
      this.darknetPeerHandle = Objects.requireNonNull(darknetPeerHandle);
    } else if (darknetPeerHandle != null) {
      throw new IllegalArgumentException("Only darknet lookup results may carry a peer handle");
    } else {
      this.darknetPeerHandle = null;
    }
  }

  /**
   * Returns the shared lookup result representing an unknown peer identifier.
   *
   * <p>This outcome means the current peer table does not contain any matching identifier at the
   * time of lookup. Callers typically translate it into {@link UnknownNodeIdentifierMessage}
   * instead of throwing because the condition is protocol-visible and not exceptional.
   *
   * @return immutable singleton result indicating that the peer identifier could not be resolved.
   */
  public static FcpPeerLookupResult unknown() {
    return UNKNOWN_RESULT;
  }

  /**
   * Returns the shared lookup result representing a known non-darknet peer.
   *
   * <p>This outcome means the identifier resolved to a live peer, but the peer does not satisfy the
   * darknet-only requirement enforced by the relevant FCP message. Callers generally preserve the
   * existing protocol behavior by reporting a {@code DARKNET_ONLY} error instead of attempting any
   * feed delivery through the resolved peer.
   *
   * @return immutable singleton result indicating that a peer exists but is not eligible for
   *     darknet-only feed operations.
   */
  public static FcpPeerLookupResult nonDarknet() {
    return NON_DARKNET_RESULT;
  }

  /**
   * Creates a lookup result for a resolved darknet peer handle.
   *
   * <p>This factory is used when lookup succeeded, and the bridge layer has already confirmed that
   * the peer supports the feed operations that the FCP message layer may invoke. The supplied
   * handle is retained as-is and becomes the only peer-facing object visible to adapter-owned
   * message code.
   *
   * @param darknetPeerHandle adapter-owned handle exposing the permitted darknet peer feed
   *     operations and never {@code null}.
   * @return immutable lookup result wrapping the supplied handle for the successful darknet path.
   * @throws NullPointerException if {@code darknetPeerHandle} is {@code null}, because a darknet
   *     result without a usable handle would be internally inconsistent.
   */
  public static FcpPeerLookupResult darknet(FcpDarknetPeerHandle darknetPeerHandle) {
    return new FcpPeerLookupResult(Kind.DARKNET, darknetPeerHandle);
  }

  /**
   * Returns the coarse lookup category represented by this result.
   *
   * <p>This method is the most explicit way to branch on protocol-visible peer state. Callers
   * should prefer it when a switch expression clarifies the resulting control flow than a chain of
   * predicate calls.
   *
   * @return non-null category describing whether the peer was unknown, non-darknet, or darknet at
   *     lookup time.
   */
  public Kind kind() {
    return kind;
  }

  /**
   * Reports whether the lookup failed to resolve any current peer.
   *
   * <p>This predicate is a convenience wrapper around {@link #kind()} for call sites that only care
   * whether the identifier was missing and do not need to distinguish the other outcomes inline.
   *
   * @return {@code true} when no matching peer was found in the current runtime peer table; {@code
   *     false} otherwise.
   */
  public boolean isUnknown() {
    return kind == Kind.UNKNOWN;
  }

  /**
   * Reports whether the lookup resolved a non-darknet peer.
   *
   * <p>This is a convenience wrapper for the intermediate failure case where the identifier exists,
   * but the peer is not eligible for darknet-only feed delivery.
   *
   * @return {@code true} when a peer was found but does not support darknet-only feed operations;
   *     {@code false} otherwise.
   */
  @SuppressWarnings("unused")
  public boolean isNonDarknet() {
    return kind == Kind.NON_DARKNET;
  }

  /**
   * Reports whether the lookup resolved a darknet peer handle.
   *
   * <p>This predicate is typically used before calling {@link #requireDarknetPeerHandle()} when the
   * caller prefers simple guard-style code instead of switching on {@link #kind()}.
   *
   * @return {@code true} when a validated darknet peer handle is available for feed delivery;
   *     {@code false} otherwise.
   */
  public boolean isDarknet() {
    return kind == Kind.DARKNET;
  }

  /**
   * Returns the resolved darknet peer handle when this result represents a darknet peer.
   *
   * <p>Callers should invoke this only after checking {@link #isDarknet()} or branching on {@link
   * #kind()}. The method throws for unknown and non-darknet outcomes to prevent the message layer
   * from silently assuming a handle exists when protocol branching should occur instead. In other
   * words, this accessor is deliberately strict: a failed lookup should remain explicit in the
   * caller's control flow rather than degrading into a late {@code null}-handling bug.
   *
   * @return non-null handle exposing the permitted darknet peer operations for the successful
   *     lookup case.
   * @throws IllegalStateException if this lookup result does not represent a darknet peer and
   *     therefore has no valid peer handle to return.
   */
  public FcpDarknetPeerHandle requireDarknetPeerHandle() {
    if (!isDarknet()) {
      throw new IllegalStateException("Lookup result does not contain a darknet peer handle");
    }
    return darknetPeerHandle;
  }
}
