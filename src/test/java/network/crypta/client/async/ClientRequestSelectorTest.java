package network.crypta.client.async;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Random;

import org.junit.Test;

import network.crypta.client.ClientMetadata;
import network.crypta.client.HighLevelSimpleClientImpl;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertException;
import network.crypta.client.Metadata;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.async.SplitFileInserterSegmentStorage.BlockInsert;
import network.crypta.client.async.SplitFileInserterStorage.Status;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.crypt.CRCChecksumChecker;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.HashResult;
import network.crypta.crypt.HashType;
import network.crypta.crypt.MultiHashInputStream;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.Key;
import network.crypta.support.CheatingTicker;
import network.crypta.support.DummyJobRunner;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PooledExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.WaitableExecutor;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.ByteArrayRandomAccessBufferFactory;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.NativeThread;
import network.crypta.support.io.NullOutputStream;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.PooledFileRandomAccessBufferFactory;
import network.crypta.support.io.RAFInputStream;
import network.crypta.support.io.ReadOnlyRandomAccessBuffer;
import network.crypta.support.io.TempBucketFactory;
import network.crypta.support.io.TrivialPersistentFileTracker;

public class ClientRequestSelectorTest {

    public ClientRequestSelectorTest() throws IOException {
        dir = new File("split-file-inserter-storage-test");
        dir.mkdir();
        executor = new WaitableExecutor(new PooledExecutor());
        ticker = new CheatingTicker(executor);
        RandomSource r = new DummyRandomSource(12345);
        fg = new FilenameGenerator(r, true, dir, "freenet-test");
        persistentFileTracker = new TrivialPersistentFileTracker(dir, fg);
        bigRAFFactory = new PooledFileRandomAccessBufferFactory(fg, r);
        smallBucketFactory = new ArrayBucketFactory();
        bigBucketFactory = new TempBucketFactory(executor, fg, 0, 0, r, false, 0, null);
        baseContext = HighLevelSimpleClientImpl.makeDefaultInsertContext(bigBucketFactory,
                                                                         new SimpleEventProducer());
        cryptoKey = new byte[32];
        r.nextBytes(cryptoKey);
        checker = new CRCChecksumChecker();
        memoryLimitedJobRunner =
            new MemoryLimitedJobRunner(9 * 1024 * 1024L, 20, executor, NativeThread.JAVA_PRIORITY_RANGE);
        jobRunner = new DummyJobRunner(executor, null);
    }

    @Test
    public void testSmallSplitfileChooseCompletion() throws IOException, InsertException {
        Random r = new Random(12121);
        long size = 65536; // Exact multiple, so no last block
        LockableRandomAccessBuffer data = generateData(r, size, smallRAFFactory);
        HashResult[] hashes = getHashes(data);
        MyCallback cb = new MyCallback();
        InsertContext context = baseContext.clone();
        context.maxInsertRetries = 2;
        ClientRequestSelector keys = new ClientRequestSelector(true, false, false, null);
        SplitFileInserterStorage storage =
            new SplitFileInserterStorage(data, size, cb, null, new ClientMetadata(), false, null,
                                         smallRAFFactory, false, context, cryptoAlgorithm, cryptoKey,
                                         null, hashes, smallBucketFactory, checker, r,
                                         memoryLimitedJobRunner, jobRunner, ticker, keys, false, 0, 0, 0,
                                         0);
        storage.start();
        cb.waitForFinishedEncode();
        assertEquals(storage.segments.length, 1);
        SplitFileInserterSegmentStorage segment = storage.segments[0];
        assertEquals(segment.dataBlockCount, 2);
        assertEquals(segment.checkBlockCount, 3);
        assertEquals(segment.crossCheckBlockCount, 0);
        assertEquals(storage.getStatus(), Status.ENCODED);
        boolean[] chosenBlocks = new boolean[segment.totalBlockCount];
        // Choose and fail all blocks.
        for (int i = 0; i < segment.totalBlockCount; i++) {
            BlockInsert chosen = segment.chooseBlock();
            assertNotNull(chosen);
            keys.addRunningInsert(chosen);
            assertFalse(chosenBlocks[chosen.blockNumber]);
            chosenBlocks[chosen.blockNumber] = true;
            segment.onFailure(chosen.blockNumber,
                              new InsertException(InsertExceptionMode.ROUTE_NOT_FOUND));
        }
        BlockInsert chosen = segment.chooseBlock();
        assertNull(chosen);
        for (int i = 0; i < segment.totalBlockCount; i++) {
            keys.removeRunningInsert(new BlockInsert(segment, i));
        }
        // Choose and succeed all blocks.
        chosenBlocks = new boolean[segment.totalBlockCount];
        for (int i = 0; i < segment.totalBlockCount; i++) {
            chosen = segment.chooseBlock();
            keys.addRunningInsert(chosen);
            assertNotNull(chosen);
            assertFalse(chosenBlocks[chosen.blockNumber]);
            chosenBlocks[chosen.blockNumber] = true;
            segment.onInsertedBlock(chosen.blockNumber,
                                    segment.encodeBlock(chosen.blockNumber).getClientKey());
        }
        cb.waitForSucceededInsert();
        assertEquals(storage.getStatus(), Status.SUCCEEDED);
    }

    private HashResult[] getHashes(LockableRandomAccessBuffer data) throws IOException {
        InputStream is = new RAFInputStream(data, 0, data.size());
        MultiHashInputStream hashStream = new MultiHashInputStream(is, HashType.SHA256.bitmask);
        FileUtil.copy(is, new NullOutputStream(), data.size());
        is.close();
        return hashStream.getResults();
    }

    private LockableRandomAccessBuffer generateData(
        Random random, long size,
        LockableRandomAccessBufferFactory smallRAFFactory)
        throws IOException {
        LockableRandomAccessBuffer thing = smallRAFFactory.makeRAF(size);
        BucketTools.fill(thing, random, 0, size);
        return new ReadOnlyRandomAccessBuffer(thing);
    }

    private static class MyCallback implements SplitFileInserterStorageCallback {

        @Override
        public synchronized void onFinishedEncode() {
            finishedEncode = true;
            notifyAll();
        }

        @Override
        public synchronized void onHasKeys() {
            notifyAll();
        }

        @Override
        public void encodingProgress() {
            // Ignore.
        }

        public synchronized void waitForFinishedEncode() throws InsertException {
            while (!finishedEncode) {
                checkFailed();
                try {
                    wait();
                } catch (InterruptedException e) {
                    // Ignore.
                }
            }
        }

        @Override
        public synchronized void onSucceeded(Metadata metadata) {
            succeededInsert = true;
            notifyAll();
        }

        public synchronized void waitForSucceededInsert() throws InsertException {
            while (!succeededInsert) {
                checkFailed();
                try {
                    wait();
                } catch (InterruptedException e) {
                    // Ignore.
                }
            }
        }

        @Override
        public synchronized void onFailed(InsertException e) {
            failed = e;
            notifyAll();
        }

        @Override
        public void onInsertedBlock() {
            // Ignore.
        }

        @Override
        public void clearCooldown() {
            // Ignore.
        }

        @Override
        public short getPriorityClass() {
            return 0;
        }

        private void checkFailed() throws InsertException {
            if (failed != null) {
                throw failed;
            }
        }
        private boolean finishedEncode;
        private boolean succeededInsert;
        private InsertException failed;

    }
    final LockableRandomAccessBufferFactory smallRAFFactory = new ByteArrayRandomAccessBufferFactory();
    final FilenameGenerator fg;
    final PersistentFileTracker persistentFileTracker;
    final LockableRandomAccessBufferFactory bigRAFFactory;
    final BucketFactory smallBucketFactory;
    final BucketFactory bigBucketFactory;
    final File dir;
    final InsertContext baseContext;
    final WaitableExecutor executor;
    final Ticker ticker;
    final byte cryptoAlgorithm = Key.ALGO_AES_CTR_256_SHA256;
    final byte[] cryptoKey;
    final ChecksumChecker checker;
    final MemoryLimitedJobRunner memoryLimitedJobRunner;
    final PersistentJobRunner jobRunner;
}
