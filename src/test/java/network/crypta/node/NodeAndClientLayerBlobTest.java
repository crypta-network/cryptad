package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.FetchWaiter;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.InsertBlock;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertException;
import network.crypta.client.async.BinaryBlob;
import network.crypta.client.async.BinaryBlobFormatException;
import network.crypta.client.async.BinaryBlobWriter;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.ClientGetterOptions;
import network.crypta.client.async.ClientGetterRequest;
import network.crypta.client.async.SimpleBlockSet;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeStarter.TestNodeParameters;
import network.crypta.support.PooledExecutor;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.TestProperty;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FileUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.event.Level;

class NodeAndClientLayerBlobTest extends NodeAndClientLayerTestBase {

  @Test
  void testFetchPullBlobSingleNode()
      throws NodeInitException,
          InsertException,
          FetchException,
          IOException,
          BinaryBlobFormatException {
    if (!TestProperty.EXTENSIVE) {
      return;
    }
    DummyRandomSource random = new DummyRandomSource(25312);
    final PriorityAwareExecutor executor = new PooledExecutor();
    FileUtil.removeAll(dir);
    assertTrue(dir.mkdirs() || dir.isDirectory());
    NodeStarter.globalTestInit(dir, false, Level.ERROR, "", true, random);
    TestNodeParameters params = new TestNodeParameters();
    params.setRandom(new DummyRandomSource(253121));
    params.setRamStore(true);
    params.setStoreSize(FILE_SIZE * 3);
    params.setBaseDirectory(dir);
    params.setExecutor(executor);
    Node node = NodeStarter.createTestNode(params);
    node.start(false);
    HighLevelSimpleClient client = node.services().clientCore().makeClient((short) 0, false, false);
    // First do an ordinary insert.
    InsertContext ictx = client.getInsertContext(true);
    ictx.setLocalRequestOnly(true);
    InsertBlock block = generateBlock(random, false);
    FreenetURI uri = client.insert(block, "", (short) 0, ictx);
    assertEquals("SSK", uri.getKeyType());
    FetchContext ctx = client.getFetchContext(FILE_SIZE * 2);
    ctx.setLocalRequestOnly(true);
    FetchWaiter fw = new FetchWaiter(rc);
    client.fetch(uri, FILE_SIZE * 2, fw, ctx, (short) 0);
    FetchResult result = fw.waitForCompletion();
    assertTrue(BucketTools.equalBuckets(result.asBucket(), block.getData()));
    // Now fetch the blob...
    fw = new FetchWaiter(rc);
    Bucket blobBucket =
        node.services().clientCore().getTempBucketFactory().makeBucket(FILE_SIZE * 3);
    BinaryBlobWriter bbw = new BinaryBlobWriter(blobBucket);
    ClientGetter getter =
        new ClientGetter(
            new ClientGetterRequest(fw, uri, ctx, (short) 0),
            ClientGetterOptions.withBinaryBlobWriter(null, bbw));
    getter.start(node.services().clientCore().getClientContext());
    fw.waitForCompletion();
    assertTrue(blobBucket.size() > 0);
    // Now bootstrap a second node, and fetch using the blob on that node.
    params = new TestNodeParameters();
    params.setRandom(new DummyRandomSource(253121));
    params.setRamStore(true);
    params.setStoreSize(FILE_SIZE * 3);
    params.setBaseDirectory(new File(dir, "fetchNode"));
    File fetchNodeDir = params.getBaseDirectory();
    assertTrue(fetchNodeDir.mkdirs() || fetchNodeDir.isDirectory());
    params.setExecutor(executor);
    Node node2 = NodeStarter.createTestNode(params);
    node2.start(false);
    HighLevelSimpleClient client2 =
        node.services().clientCore().makeClient((short) 0, false, false);
    FetchContext ctx2 = client.getFetchContext(FILE_SIZE * 2);
    SimpleBlockSet blocks = new SimpleBlockSet();
    DataInputStream dis = new DataInputStream(blobBucket.getInputStream());
    BinaryBlob.readBinaryBlob(dis, blocks, true);
    ctx2 = new FetchContext(ctx2, FetchContext.IDENTICAL_MASK, true, blocks);
    fw = new FetchWaiter(rc);
    client2.fetch(uri, FILE_SIZE * 2, fw, ctx2, (short) 0);
    result = fw.waitForCompletion();
    assertTrue(BucketTools.equalBuckets(result.asBucket(), block.getData()));
  }

  @AfterEach
  void cleanUp() {
    FileUtil.removeAll(dir);
  }

  private static final File dir = new File("test-fetch-pull-blob-single-node");
}
