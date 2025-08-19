package network.crypta.store;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import network.crypta.crypt.DSAGroup;
import network.crypta.crypt.DSAPrivateKey;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.Global;
import network.crypta.support.ByteArrayWrapper;
import network.crypta.support.math.MersenneTwister;
import org.junit.Test;

public class PubkeyStoreTest {

  @Test
  public void testSimple() throws IOException {
    final int keys = 10;
    PubkeyStore pk = new PubkeyStore();
    new RAMFreenetStore<>(pk, keys);
    DSAGroup group = Global.DSAgroupBigA;
    Random random = new MersenneTwister(1010101);
    HashMap<ByteArrayWrapper, DSAPublicKey> map = new HashMap<>();
    for (int i = 0; i < keys; i++) {
      DSAPrivateKey privKey = new DSAPrivateKey(group, random);
      DSAPublicKey key = new DSAPublicKey(group, privKey);
      byte[] hash = key.asBytesHash();
      ByteArrayWrapper w = new ByteArrayWrapper(hash);
      map.put(w, key.cloneKey());
      pk.put(hash, key, false);
      assertTrue(pk.fetch(hash, false, false, null).equals(key));
    }
    int x = 0;
    for (Map.Entry<ByteArrayWrapper, DSAPublicKey> entry : map.entrySet()) {
      x++;
      assertTrue(pk.fetch(entry.getKey().get(), false, false, null).equals(entry.getValue()));
    }
    assert (x == keys);
  }
}
