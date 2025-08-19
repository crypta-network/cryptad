package network.crypta.store.saltedhash;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import network.crypta.crypt.DSAGroup;
import network.crypta.crypt.DSAPrivateKey;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.Global;
import network.crypta.crypt.RandomSource;
import network.crypta.crypt.SHA256;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.CHKDecodeException;
import network.crypta.keys.CHKEncodeException;
import network.crypta.keys.CHKVerifyException;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.ClientSSKBlock;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.keys.Key;
import network.crypta.keys.KeyDecodeException;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.SSKBlock;
import network.crypta.keys.SSKEncodeException;
import network.crypta.keys.SSKVerifyException;
import network.crypta.node.SemiOrderedShutdownHook;
import network.crypta.store.CHKStore;
import network.crypta.store.GetPubkey;
import network.crypta.store.KeyCollisionException;
import network.crypta.store.PubkeyStore;
import network.crypta.store.RAMFreenetStore;
import network.crypta.store.SSKStore;
import network.crypta.store.SimpleGetPubkey;
import network.crypta.support.PooledExecutor;
import network.crypta.support.SimpleReadOnlyArrayBucket;
import network.crypta.support.Ticker;
import network.crypta.support.TrivialTicker;
import network.crypta.support.api.Bucket;
import network.crypta.support.compress.Compressor;
import network.crypta.support.compress.InvalidCompressionCodecException;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FileUtil;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * SaltedHashFreenetStoreTest Test for SaltedHashFreenetStore
 *
 * @author Simon Vocella <voxsim@gmail.com>
 */
public class SaltedHashFreenetStoreTest {

  private final Random weakPRNG = new Random(12340);
  private final PooledExecutor exec = new PooledExecutor();
  private final Ticker ticker = new TrivialTicker(exec);
  private File tempDir;

  @Before
  public void setUp() throws java.lang.Exception {
    tempDir = new File("tmp-saltedHashfreenetstoretest");
    tempDir.mkdir();
    exec.start();
    ResizablePersistentIntBuffer.setPersistenceTime(-1);
  }

  @After
  public void tearDown() {
    FileUtil.removeAll(tempDir);
  }

  /* Simple test with CHK for SaltedHashFreenetStore without slotFilter */
  @Test
  public void testSimpleCHK()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    File f = new File(tempDir, "saltstore");
    FileUtil.removeAll(f);

    CHKStore store = new CHKStore();
    SaltedHashFreenetStore<CHKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            f,
            "testSaltedHashFreenetStoreCHK",
            store,
            weakPRNG,
            10,
            false,
            SemiOrderedShutdownHook.get(),
            true,
            true,
            ticker,
            null);
    saltStore.start(null, true);

    for (int i = 0; i < 5; i++) {
      String test = "test" + i;
      ClientCHKBlock block = encodeBlockCHK(test);
      store.put(block.getBlock(), false);
      ClientCHK key = block.getClientKey();
      CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
      String data = decodeBlockCHK(verify, key);
      assertEquals(test, data);
    }

    saltStore.close();
  }

  /* Simple test with SSK for SaltedHashFreenetStore without slotFilter */
  @Test
  public void testSimpleSSK()
      throws IOException,
          KeyCollisionException,
          SSKVerifyException,
          KeyDecodeException,
          SSKEncodeException,
          InvalidCompressionCodecException {
    File f = new File(tempDir, "saltstore");
    FileUtil.removeAll(f);

    final int keys = 5;
    PubkeyStore pk = new PubkeyStore();
    new RAMFreenetStore<>(pk, keys);
    GetPubkey pubkeyCache = new SimpleGetPubkey(pk);
    SSKStore store = new SSKStore(pubkeyCache);
    SaltedHashFreenetStore<SSKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            f,
            "testSaltedHashFreenetStoreSSK",
            store,
            weakPRNG,
            20,
            false,
            SemiOrderedShutdownHook.get(),
            true,
            true,
            ticker,
            null);
    saltStore.start(null, true);
    RandomSource random = new DummyRandomSource(12345);

    for (int i = 0; i < 5; i++) {
      String test = "test" + i;
      ClientSSKBlock block = encodeBlockSSK(test, random);
      SSKBlock sskBlock = (SSKBlock) block.getBlock();
      store.put(sskBlock, false, false);
      ClientSSK key = block.getClientKey();
      NodeSSK ssk = (NodeSSK) key.getNodeKey();
      pubkeyCache.cacheKey(ssk.getPubKeyHash(), ssk.getPubKey(), false, false, false, false, false);
      SSKBlock verify = store.fetch(ssk, false, false, false, false, null);
      String data = decodeBlockSSK(verify, key);
      assertEquals(test, data);
    }

    saltStore.close();
  }

  private String decodeBlockCHK(CHKBlock verify, ClientCHK key)
      throws CHKVerifyException, CHKDecodeException, IOException {
    ClientCHKBlock cb = new ClientCHKBlock(verify, key);
    Bucket output = cb.decode(new ArrayBucketFactory(), 32768, false);
    byte[] buf = BucketTools.toByteArray(output);
    return new String(buf, StandardCharsets.UTF_8);
  }

  private ClientCHKBlock encodeBlockCHK(String test) throws CHKEncodeException, IOException {
    byte[] data = test.getBytes(StandardCharsets.UTF_8);
    SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(data);
    return ClientCHKBlock.encode(
        bucket,
        false,
        false,
        (short) -1,
        bucket.size(),
        Compressor.DEFAULT_COMPRESSORDESCRIPTOR,
        null,
        (byte) 0);
  }

  @Test
  public void testOnCollisionsSSK()
      throws IOException,
          SSKEncodeException,
          InvalidCompressionCodecException,
          SSKVerifyException,
          KeyDecodeException,
          KeyCollisionException {
    // With slot filters turned off, it goes straight to disk, because probablyInStore() always
    // returns true.
    checkOnCollisionsSSK(false);
    // With slot filters turned on, it should be cached, it should compare it, and still not throw
    // if it's the same block.
    checkOnCollisionsSSK(true);
  }

  /* Test collisions on SSK */
  private void checkOnCollisionsSSK(boolean useSlotFilter)
      throws IOException,
          SSKEncodeException,
          InvalidCompressionCodecException,
          SSKVerifyException,
          KeyDecodeException,
          KeyCollisionException {
    File f = new File(tempDir, "saltstore");
    FileUtil.removeAll(f);

    final int keys = 5;
    PubkeyStore pk = new PubkeyStore();
    new RAMFreenetStore<>(pk, keys);
    GetPubkey pubkeyCache = new SimpleGetPubkey(pk);
    SSKStore store = new SSKStore(pubkeyCache);
    SaltedHashFreenetStore<SSKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            f,
            "testSaltedHashFreenetStoreOnCloseSSK",
            store,
            weakPRNG,
            10,
            true,
            SemiOrderedShutdownHook.get(),
            true,
            true,
            ticker,
            null);
    saltStore.start(null, true);
    RandomSource random = new DummyRandomSource(12345);

    final int CRYPTO_KEY_LENGTH = 32;
    byte[] ckey = new byte[CRYPTO_KEY_LENGTH];
    random.nextBytes(ckey);
    DSAGroup g = Global.DSAgroupBigA;
    DSAPrivateKey privKey = new DSAPrivateKey(g, random);
    DSAPublicKey pubKey = new DSAPublicKey(g, privKey);
    byte[] pkHash = SHA256.digest(pubKey.asBytes());
    String docName = "myDOC";
    InsertableClientSSK ik =
        new InsertableClientSSK(
            docName, pkHash, pubKey, privKey, ckey, Key.ALGO_AES_PCFB_256_SHA256);

    String test = "test";
    SimpleReadOnlyArrayBucket bucket =
        new SimpleReadOnlyArrayBucket(test.getBytes(StandardCharsets.UTF_8));
    ClientSSKBlock block =
        ik.encode(
            bucket,
            false,
            false,
            (short) -1,
            bucket.size(),
            random,
            Compressor.DEFAULT_COMPRESSORDESCRIPTOR);
    SSKBlock sskBlock = (SSKBlock) block.getBlock();
    store.put(sskBlock, false, false);

    // If the block is the same then there should not be a collision
    try {
      store.put(sskBlock, false, false);
      assertTrue(true);
    } catch (KeyCollisionException e) {
      fail();
    }

    String test1 = "test1";
    SimpleReadOnlyArrayBucket bucket1 =
        new SimpleReadOnlyArrayBucket(test1.getBytes(StandardCharsets.UTF_8));
    ClientSSKBlock block1 =
        ik.encode(
            bucket1,
            false,
            false,
            (short) -1,
            bucket1.size(),
            random,
            Compressor.DEFAULT_COMPRESSORDESCRIPTOR);
    SSKBlock sskBlock1 = (SSKBlock) block1.getBlock();

    // if it's different (e.g. different content, same key), there should be a KCE thrown
    try {
      store.put(sskBlock1, false, false);
      fail();
    } catch (KeyCollisionException e) {
      assertTrue(true);
    }

    // if overwrite is set, then no collision should be thrown
    try {
      store.put(sskBlock1, true, false);
      assertTrue(true);
    } catch (KeyCollisionException e) {
      fail();
    }

    ClientSSK key = block1.getClientKey();
    pubkeyCache.cacheKey(
        sskBlock.getKey().getPubKeyHash(),
        sskBlock.getKey().getPubKey(),
        false,
        false,
        false,
        false,
        false);
    // Check that it's in the cache, *not* the underlying store.
    NodeSSK ssk = (NodeSSK) key.getNodeKey();
    SSKBlock verify = store.fetch(ssk, false, false, false, false, null);
    String data = decodeBlockSSK(verify, key);
    assertEquals(test1, data);

    saltStore.close();
  }

  private String decodeBlockSSK(SSKBlock verify, ClientSSK key)
      throws SSKVerifyException, KeyDecodeException, IOException {
    ClientSSKBlock cb = ClientSSKBlock.construct(verify, key);
    Bucket output = cb.decode(new ArrayBucketFactory(), 32768, false);
    byte[] buf = BucketTools.toByteArray(output);
    return new String(buf, StandardCharsets.UTF_8);
  }

  private ClientSSKBlock encodeBlockSSK(String test, RandomSource random)
      throws IOException, SSKEncodeException, InvalidCompressionCodecException {
    byte[] data = test.getBytes(StandardCharsets.UTF_8);
    SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(data);
    InsertableClientSSK ik = InsertableClientSSK.createRandom(random, test);
    return ik.encode(
        bucket,
        false,
        false,
        (short) -1,
        bucket.size(),
        random,
        Compressor.DEFAULT_COMPRESSORDESCRIPTOR);
  }
}
