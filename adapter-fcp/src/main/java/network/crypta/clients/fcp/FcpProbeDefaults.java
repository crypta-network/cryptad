package network.crypta.clients.fcp;

/**
 * Adapter-owned defaults for FCP probe message handling.
 *
 * <p>This helper holds the small set of literal defaults that the FCP adapter must preserve even
 * after the probe-facing seam moved away from runtime-owned types. At the moment it contains only
 * the fallback hop budget used by {@link ProbeRequest}, but keeping that constant in an
 * adapter-owned class still matters because it documents which values are part of adapter-visible
 * behavior rather than an incidental implementation detail of the runtime probe package.
 *
 * <p>The intent is compatibility, not policy expansion. When an inbound probe request omits {@code
 * HopsToLive}, the adapter should continue to behave exactly as it did before the seam refactor.
 * Centralizing the default here makes that relationship obvious and avoids reintroducing runtime
 * probe imports solely to fetch a single fallback constant.
 */
final class FcpProbeDefaults {
  /**
   * Default hop budget used when an inbound {@code ProbeRequest} omits {@code HopsToLive}.
   *
   * <p>The value intentionally stays aligned with the daemon's current probe default so that
   * adapter-side requests keep their established reach and reply characteristics when clients leave
   * the field unspecified.
   */
  static final byte MAX_HTL = 70;

  /**
   * Prevents instantiation of this constants-only helper.
   *
   * <p>The class exists solely as a namespace for adapter-owned probe defaults and is not intended
   * to participate in object lifecycles.
   */
  private FcpProbeDefaults() {
    throw new AssertionError("No instances");
  }
}
