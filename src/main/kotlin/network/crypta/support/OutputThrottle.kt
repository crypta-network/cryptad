package network.crypta.support

/**
 * Wrapper around the legacy [TokenBucket] that exposes the small subset of behaviour the node
 * relies on without forcing callers to touch the deprecated type directly.
 */
class OutputThrottle(maxTokens: Long, nanosPerTick: Long, initialTokens: Long) {

  @Suppress("DEPRECATION")
  private val delegate = TokenBucket(maxTokens, nanosPerTick, initialTokens)

  fun changeNanosAndBucketSize(nanosPerTick: Long, newMaxTokens: Long) {
    @Suppress("DEPRECATION") delegate.changeNanosAndBucketSize(nanosPerTick, newMaxTokens)
  }

  fun forceGrab(tokens: Long) {
    @Suppress("DEPRECATION") delegate.forceGrab(tokens)
  }

  fun getCount(): Long {
    @Suppress("DEPRECATION")
    return delegate.getCount()
  }

  fun getNanosPerTick(): Long {
    @Suppress("DEPRECATION")
    return delegate.nanosPerTick
  }
}
