package network.crypta.store;

import java.io.IOException;

import network.crypta.crypt.DSAPublicKey;
import network.crypta.support.HexUtil;
import network.crypta.support.Logger;

public class SimpleGetPubkey implements GetPubkey {
	
	final PubkeyStore store;
	
	public SimpleGetPubkey(PubkeyStore store) {
		this.store = store;
	}

	@Override
	public DSAPublicKey getKey(byte[] hash, boolean canReadClientCache,
			boolean forULPR, BlockMetadata meta) {
		try {
			return store.fetch(hash, false, false, meta);
		} catch (IOException e) {
			Logger.error(this, "Caught " + e + " fetching pubkey for " + HexUtil.bytesToHex(hash));
			return null;
		}
	}

	@Override
	public void cacheKey(byte[] hash, DSAPublicKey key, boolean deep,
			boolean canWriteClientCache, boolean canWriteDatastore,
			boolean forULPR, boolean writeLocalToDatastore) {
		try {
			store.put(hash, key, false);
		} catch (IOException e) {
			Logger.error(this, "Caught " + e + " storing pubkey for " + HexUtil.bytesToHex(hash));
		}
	}

}
