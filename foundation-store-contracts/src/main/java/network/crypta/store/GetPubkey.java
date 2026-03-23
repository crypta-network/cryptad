package network.crypta.store;

/**
 * Lookup and caching facade for public keys or similar verification material.
 *
 * <p>Implementations resolve key material by hash and may cache or promote the result across
 * multiple storage layers. Methods do not declare checked exceptions; implementations typically
 * return {@code null} on lookup failure and suppress write failures after logging.
 *
 * @param <P> key material type returned and cached by the implementation
 */
public interface GetPubkey<P> {

  /**
   * Returns key material for a given hash.
   *
   * @param hash key hash
   * @param canReadClientCache whether the client cache may be consulted
   * @param forULPR hint allowing the implementation to use an alternate cache path
   * @param meta optional metadata sink that may be updated during lookup; may be {@code null}
   * @return resolved key material, or {@code null} if not found
   */
  P getKey(byte[] hash, boolean canReadClientCache, boolean forULPR, BlockMetadata meta);

  /**
   * Caches key material and, when permitted, promotes it to deeper storage.
   *
   * @param hash key hash
   * @param key key material to cache
   * @param deep whether to promote it to deep storage rather than only cache layers
   * @param canWriteClientCache whether the client cache may be written
   * @param canWriteDatastore whether normal datastore writes are allowed
   * @param forULPR hint allowing writes to an alternate cache path
   * @param writeLocalToDatastore whether local writes may bypass normal datastore restrictions
   */
  void cacheKey(
      byte[] hash,
      P key,
      boolean deep,
      boolean canWriteClientCache,
      boolean canWriteDatastore,
      boolean forULPR,
      boolean writeLocalToDatastore);
}
