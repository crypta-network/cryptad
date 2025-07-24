package network.crypta.node;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;

import org.junit.After;
import org.junit.Test;

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
import network.crypta.client.async.SimpleBlockSet;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeStarter.TestNodeParameters;
import network.crypta.support.Executor;
import network.crypta.support.Logger;
import network.crypta.support.LoggerHook.InvalidThresholdException;
import network.crypta.support.PooledExecutor;
import network.crypta.support.TestProperty;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FileUtil;

public class NodeAndClientLayerBlobTest extends NodeAndClientLayerTestBase {

    @Test
    public void testFetchPullBlobSingleNode()
        throws InvalidThresholdException, NodeInitException, InsertException, FetchException,
               IOException, BinaryBlobFormatException {
        if (!TestProperty.EXTENSIVE) {
            return;
        }
        DummyRandomSource random = new DummyRandomSource(25312);
        final Executor executor = new PooledExecutor();
        FileUtil.removeAll(dir);
        dir.mkdir();
        NodeStarter.globalTestInit(dir, false, Logger.LogLevel.ERROR, "", true, random);
        TestNodeParameters params = new TestNodeParameters();
        params.random = new DummyRandomSource(253121);
        params.ramStore = true;
        params.storeSize = FILE_SIZE * 3;
        params.baseDirectory = dir;
        params.executor = executor;
        Node node = NodeStarter.createTestNode(params);
        node.start(false);
        HighLevelSimpleClient client = node.getClientCore().makeClient((short) 0, false, false);
        // First do an ordinary insert.
        InsertContext ictx = client.getInsertContext(true);
        ictx.localRequestOnly = true;
        InsertBlock block = generateBlock(random, false);
        FreenetURI uri = client.insert(block, "", (short) 0, ictx);
        assertEquals(uri.getKeyType(), "SSK");
        FetchContext ctx = client.getFetchContext(FILE_SIZE * 2);
        ctx.localRequestOnly = true;
        FetchWaiter fw = new FetchWaiter(rc);
        client.fetch(uri, FILE_SIZE * 2, fw, ctx, (short) 0);
        FetchResult result = fw.waitForCompletion();
        assertTrue(BucketTools.equalBuckets(result.asBucket(), block.getData()));
        // Now fetch the blob...
        fw = new FetchWaiter(rc);
        Bucket blobBucket = node.getClientCore().getTempBucketFactory().makeBucket(FILE_SIZE * 3);
        BinaryBlobWriter bbw = new BinaryBlobWriter(blobBucket);
        ClientGetter getter = new ClientGetter(fw, uri, ctx, (short) 0, null, bbw, false, null, null);
        getter.start(node.getClientCore().getClientContext());
        fw.waitForCompletion();
        assertTrue(blobBucket.size() > 0);
        // Now bootstrap a second node, and fetch using the blob on that node.
        params = new TestNodeParameters();
        params.random = new DummyRandomSource(253121);
        params.ramStore = true;
        params.storeSize = FILE_SIZE * 3;
        params.baseDirectory = new File(dir, "fetchNode");
        params.baseDirectory.mkdir();
        params.executor = executor;
        Node node2 = NodeStarter.createTestNode(params);
        node2.start(false);
        HighLevelSimpleClient client2 = node.getClientCore().makeClient((short) 0, false, false);
        FetchContext ctx2 = client.getFetchContext(FILE_SIZE * 2);
        SimpleBlockSet blocks = new SimpleBlockSet();
        DataInputStream dis = new DataInputStream(blobBucket.getInputStream());
        BinaryBlob.readBinaryBlob(dis, blocks, true);
        ctx2 = new FetchContext(ctx2, FetchContext.IDENTICAL_MASK, true, blocks);
        fw = new FetchWaiter(rc);
        getter = client2.fetch(uri, FILE_SIZE * 2, fw, ctx2, (short) 0);
        result = fw.waitForCompletion();
        assertTrue(BucketTools.equalBuckets(result.asBucket(), block.getData()));
    }

    @After
    public void cleanUp() {
        FileUtil.removeAll(dir);
    }
    private static final File dir = new File("test-fetch-pull-blob-single-node");

}
