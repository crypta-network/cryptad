/** Public key lookups with an in‑memory LRU cache. */
package network.crypta.node;

import java.io.IOException;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.store.BlockMetadata;
import network.crypta.store.GetPubkey;
import network.crypta.store.PubkeyStore;
import network.crypta.support.ByteArrayWrapper;
import network.crypta.support.HexUtil;
import network.crypta.support.LRUMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resolves and caches DSA public keys for content blocks.
 *
 * <p>This class consults multiple sources in a defined order and maintains a small in-memory LRU
 * cache to avoid repeated datastore or disk lookups. All accesses to the in-memory cache are
 * synchronized because the underlying {@link LRUMap} is not thread-safe.
 *
 * <p>Lookup order (when applicable): memory cache → client caches (including legacy) → main
 * datastore (including legacy) → datacache (including legacy) → slashdot cache (when requested).
 */
public class NodeGetPubkey implements GetPubkey {
  private static final Logger LOG = LoggerFactory.getLogger(NodeGetPubkey.class);

  // Enable the small RAM-backed pubkey cache for hot entries.
  private static final boolean USE_RAM_PUBKEYS_CACHE = true;
  // Upper bound for entries kept in the in-memory LRU cache.
  private static final int MAX_MEMORY_CACHED_PUBKEYS = 1000;

  private final LRUMap<ByteArrayWrapper, DSAPublicKey> cachedPubKeys;

  private PubkeyStore pubKeyDatastore;
  private PubkeyStore pubKeyDatacache;
  private PubkeyStore pubKeyClientcache;
  private PubkeyStore pubKeySlashdotcache;

  private final Node node;

  /**
   * Creates a pubkey resolver bound to the provided node.
   *
   * @param node owning node for datastore and cache access
   */
  public NodeGetPubkey(Node node) {
    cachedPubKeys = LRUMap.createSafeMap(ByteArrayWrapper.FAST_COMPARATOR);
    this.node = node;
  }

  /**
   * Updates the primary datastore and datacache used for public key lookups.
   *
   * @param pubKeyDatastore the main pubkey datastore
   * @param pubKeyDatacache the main pubkey datacache
   */
  public void setDataStore(PubkeyStore pubKeyDatastore, PubkeyStore pubKeyDatacache) {
    this.pubKeyDatastore = pubKeyDatastore;
    this.pubKeyDatacache = pubKeyDatacache;
  }

  /**
   * Returns the {@link DSAPublicKey} identified by {@code hash}.
   *
   * <p>The method consults sources in priority order and may populate the in-memory cache on a hit.
   * When {@code canReadClientCache} is {@code true}, legacy client caches are also consulted. When
   * {@code forULPR} is {@code true}, the slashdot cache is consulted as the last step.
   *
   * <p>Lookup order: memory cache → client caches (when allowed) → datastore (and legacy) →
   * datacache (and legacy) → slashdot cache (when {@code forULPR}).
   *
   * @param hash 32-byte key hash; method treats it as non-null and does not copy the array.
   * @param canReadClientCache whether client caches may be used for reading.
   * @param forULPR whether the request targets ULPR paths and may consult the slashdot cache.
   * @param meta optional metadata sink; implementations append read information when non-null.
   * @return the resolved public key, or {@code null} when not found.
   */
  @Override
  public DSAPublicKey getKey(
      byte[] hash, boolean canReadClientCache, boolean forULPR, BlockMetadata meta) {
    boolean ignoreOldBlocks = shouldIgnoreOldBlocks(canReadClientCache);
    if (LOG.isDebugEnabled()) LOG.debug("Get pubkey for hash={}", HexUtil.bytesToHex(hash));

    DSAPublicKey fromRam = getFromRamCache(hash);
    if (fromRam != null) return fromRam;
    try {
      DSAPublicKey key =
          orElse(
              tryClientCaches(hash, canReadClientCache, meta),
              () ->
                  orElse(
                      tryStores(hash, ignoreOldBlocks, meta),
                      () ->
                          orElse(
                              tryDataCaches(hash, ignoreOldBlocks, meta),
                              () -> trySlashdot(hash, forULPR, ignoreOldBlocks, meta))));
      if (key != null) {
        // Populate the in-memory cache for subsequent lookups.
        cacheKey(hash, key, false, false, false, false, false);
      }
      return key;
    } catch (IOException e) {
      // Surface the I/O error; stack trace is attached via the throwable parameter.
      LOG.error("Pubkey store access error (cause={})", e, e);
      return null;
    }
  }

  /**
   * Caches a key in memory and, when permitted, writes it to backing stores.
   *
   * <p>This method updates the RAM LRU cache unconditionally. Depending on the flags, it may also
   * write to the client cache, slashdot cache, datacache, and optionally the main datastore.
   *
   * @param hash 32-byte key hash; method treats it as non-null and does not copy the array.
   * @param key non-null public key to cache.
   * @param deep when {@code true}, writes to the main datastore in addition to the datacache.
   * @param canWriteClientCache whether the client cache may be updated.
   * @param canWriteDatastore whether writing to the main datastore is allowed.
   * @param forULPR whether the slashdot cache may also be updated.
   * @param writeLocalToDatastore when {@code true}, treat writes as local-to-datastore operations.
   */
  @Override
  public void cacheKey(
      byte[] hash,
      DSAPublicKey key,
      boolean deep,
      boolean canWriteClientCache,
      boolean canWriteDatastore,
      boolean forULPR,
      boolean writeLocalToDatastore) {
    if (LOG.isDebugEnabled())
      LOG.debug("Cache pubkey hash={} key={}", HexUtil.bytesToHex(hash), key);
    ByteArrayWrapper w = new ByteArrayWrapper(hash);
    synchronized (cachedPubKeys) {
      DSAPublicKey key2 = cachedPubKeys.get(w);
      if ((key2 != null) && !key2.equals(key))
        throw new IllegalArgumentException(
            "Wrong hash?? Already have different key with same hash!");
      // Touch/insert to keep LRU order fresh.
      cachedPubKeys.push(w, key);
      while (cachedPubKeys.size() > MAX_MEMORY_CACHED_PUBKEYS) cachedPubKeys.popKey();
    }
    try {
      if (canWriteClientCache
          && !(canWriteDatastore || writeLocalToDatastore)
          && pubKeyClientcache != null) {
        pubKeyClientcache.put(key, false);
      }
      if (forULPR && !(canWriteDatastore || writeLocalToDatastore) && pubKeySlashdotcache != null) {
        pubKeySlashdotcache.put(key, false);
      }
      // If the request originated nearby, avoid persisting to stores or caches.
      if (!(canWriteDatastore || writeLocalToDatastore)) return;
      if (deep) {
        pubKeyDatastore.put(key, !canWriteDatastore);
      }
      pubKeyDatacache.put(key, !canWriteDatastore);
    } catch (IOException e) {
      // Surface the I/O error; stack trace is attached via the throwable parameter.
      LOG.error("Pubkey store access error (cause={})", e, e);
    }
  }

  /** Sets the client-local pubkey store used for reads/writes when permitted. */
  public void setLocalDataStore(PubkeyStore pubKeyClientcache) {
    this.pubKeyClientcache = pubKeyClientcache;
  }

  /** Sets the slashdot cache used for ULPR-related reads/writes when permitted. */
  public void setLocalSlashdotcache(PubkeyStore pubKeySlashdotcache) {
    this.pubKeySlashdotcache = pubKeySlashdotcache;
  }

  private boolean shouldIgnoreOldBlocks(boolean canReadClientCache) {
    boolean ignoreOldBlocks = !node.getWriteLocalToDatastore();
    if (canReadClientCache) ignoreOldBlocks = false;
    return ignoreOldBlocks;
  }

  private DSAPublicKey getFromRamCache(byte[] hash) {
    if (!USE_RAM_PUBKEYS_CACHE) return null;
    ByteArrayWrapper w = new ByteArrayWrapper(hash);
    synchronized (cachedPubKeys) {
      DSAPublicKey key = cachedPubKeys.get(w);
      if (key != null) {
        cachedPubKeys.push(w, key);
        if (LOG.isDebugEnabled())
          LOG.debug("Memory cache hit for hash={}", HexUtil.bytesToHex(hash));
        return key;
      }
    }
    return null;
  }

  private DSAPublicKey tryClientCaches(byte[] hash, boolean canReadClientCache, BlockMetadata meta)
      throws IOException {
    if (pubKeyClientcache != null && canReadClientCache) {
      DSAPublicKey key = pubKeyClientcache.fetch(hash, false, false, meta);
      if (key != null) return key;
    }
    if (node.storage().getOldPKClientCache() != null && canReadClientCache) {
      PubkeyStore pks = node.storage().getOldPKClientCache();
      DSAPublicKey key = (pks != null) ? pks.fetch(hash, false, false, meta) : null;
      if (key != null) {
        if (LOG.isDebugEnabled())
          LOG.debug("Client cache (legacy) hit for hash={}", HexUtil.bytesToHex(hash));
        return key;
      }
    }
    return null;
  }

  private DSAPublicKey tryStores(byte[] hash, boolean ignoreOldBlocks, BlockMetadata meta)
      throws IOException {
    DSAPublicKey key = pubKeyDatastore.fetch(hash, false, ignoreOldBlocks, meta);
    if (key != null) {
      if (LOG.isDebugEnabled()) LOG.debug("Datastore hit for hash={}", HexUtil.bytesToHex(hash));
      return key;
    }
    PubkeyStore pks = node.storage().getOldPK();
    if (pks != null) key = pks.fetch(hash, false, ignoreOldBlocks, meta);
    if (key != null) {
      if (LOG.isDebugEnabled())
        LOG.debug("Datastore (legacy) hit for hash={}", HexUtil.bytesToHex(hash));
      return key;
    }
    return null;
  }

  private DSAPublicKey tryDataCaches(byte[] hash, boolean ignoreOldBlocks, BlockMetadata meta)
      throws IOException {
    DSAPublicKey key = pubKeyDatacache.fetch(hash, false, ignoreOldBlocks, meta);
    if (key != null) {
      if (LOG.isDebugEnabled()) LOG.debug("Datacache hit for hash={}", HexUtil.bytesToHex(hash));
      return key;
    }
    PubkeyStore pks = node.storage().getOldPKCache();
    if (pks != null) key = pks.fetch(hash, false, ignoreOldBlocks, meta);
    if (key != null) {
      if (LOG.isDebugEnabled())
        LOG.debug("Datacache (legacy) hit for hash={}", HexUtil.bytesToHex(hash));
      return key;
    }
    return null;
  }

  private DSAPublicKey trySlashdot(
      byte[] hash, boolean forULPR, boolean ignoreOldBlocks, BlockMetadata meta)
      throws IOException {
    if (pubKeySlashdotcache != null && forULPR) {
      DSAPublicKey key = pubKeySlashdotcache.fetch(hash, false, ignoreOldBlocks, meta);
      if (LOG.isDebugEnabled())
        LOG.debug("Slashdot cache hit for hash={}", HexUtil.bytesToHex(hash));
      return key;
    }
    return null;
  }

  @FunctionalInterface
  private interface DSAPubkeySupplier {
    DSAPublicKey get() throws IOException;
  }

  private static DSAPublicKey orElse(DSAPublicKey first, DSAPubkeySupplier fallback)
      throws IOException {
    return (first != null) ? first : fallback.get();
  }
}
