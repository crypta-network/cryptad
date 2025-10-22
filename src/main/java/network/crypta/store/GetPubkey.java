package network.crypta.store;

import network.crypta.crypt.DSAPublicKey;

/**
 * Public-key lookup and caching facade.
 *
 * <p>Implementations resolve DSA public keys by their hash and optionally cache or promote the
 * result across several layers (client cache, main cache, persistent datastore, and an optional
 * "slashdot" cache used for specific routing paths). Methods in this interface never declare
 * checked exceptions; implementations typically return {@code null} on I/O errors or when a key is
 * not present.
 */
public interface GetPubkey {

  /**
   * Returns the public key for a given hash.
   *
   * <p>Implementations may consult multiple stores based on the provided flags. When {@code
   * canReadClientCache} is {@code true}, the per-client cache may be queried. When {@code forULPR}
   * is {@code true}, an implementation may also consult a specialized "slashdot" cache if
   * available. The {@code meta} container may be populated with properties describing the origin of
   * the block (for example, whether it should be treated as an "old" block for promotion logic).
   *
   * @param hash the hash of the public key (typically {@link DSAPublicKey#HASH_LENGTH} bytes as
   *     used by SSKs).
   * @param canReadClientCache whether the local client cache may be consulted.
   * @param forULPR hint allowing the implementation to consult the optional "slashdot" cache.
   * @param meta optional metadata container that the implementation may update; may be {@code
   *     null}.
   * @return the matching public key, or {@code null} if not found or on error.
   */
  DSAPublicKey getKey(byte[] hash, boolean canReadClientCache, boolean forULPR, BlockMetadata meta);

  /**
   * Caches a public key and, optionally, promotes it to the persistent datastore.
   *
   * <p>Writes are directed to one or more layers depending on the flags:
   *
   * <ul>
   *   <li>When {@code deep} is {@code true}, the key may be written to the persistent datastore;
   *       otherwise only to the main cache.
   *   <li>When {@code canWriteClientCache} is {@code true} and promotion to the datastore is
   *       disallowed, the key may be written to the per-client cache.
   *   <li>When {@code forULPR} is {@code true} and promotion is disallowed, the key may be written
   *       to a specialized "slashdot" cache if present.
   *   <li>When {@code canWriteDatastore} is {@code true}, normal promotion to the main cache and/or
   *       datastore is permitted. Implementations may mark entries as "old" when this flag is
   *       {@code false} to avoid proactive advertising.
   *   <li>When {@code writeLocalToDatastore} is {@code true}, an implementation may allow writing
   *       to the datastore even if {@code canWriteDatastore} is {@code false} (for example, for
   *       locally originated items).
   * </ul>
   *
   * @param hash hash of the public key being stored.
   * @param key key material to store.
   * @param deep whether to write to the persistent datastore ({@code true}) or only to the main
   *     cache ({@code false}).
   * @param canWriteClientCache whether the per-client cache may be written (typically for local
   *     requests when enabled by configuration).
   * @param canWriteDatastore whether promotion to the main cache/datastore is permitted.
   * @param forULPR hint allowing writes to a specialized "slashdot" cache when promotion is
   *     disallowed.
   * @param writeLocalToDatastore override permitting datastore writes even when {@code
   *     canWriteDatastore} is {@code false}.
   */
  void cacheKey(
      byte[] hash,
      DSAPublicKey key,
      boolean deep,
      boolean canWriteClientCache,
      boolean canWriteDatastore,
      boolean forULPR,
      boolean writeLocalToDatastore);
}
