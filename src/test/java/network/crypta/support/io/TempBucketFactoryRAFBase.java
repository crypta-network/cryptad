package network.crypta.support.io;

import static org.junit.Assert.*;

import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import network.crypta.crypt.EncryptedRandomAccessBucket;
import network.crypta.crypt.MasterSecret;
import network.crypta.support.Executor;
import network.crypta.support.SerialExecutor;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.api.RandomAccessBuffer;
import network.crypta.support.io.TempBucketFactory.TempBucket;
import network.crypta.support.io.TempBucketFactory.TempRandomAccessBuffer;

public abstract class TempBucketFactoryRAFBase extends RandomAccessBufferTestBase {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public TempBucketFactoryRAFBase() {
        super(TEST_LIST);
    }

    public abstract boolean enableCrypto();

    @Before
    public void setUp() throws IOException {
        fg = new FilenameGenerator(weakPRNG, true, f, "temp-raf-test-");
        factory = new TempBucketFactory(exec, fg, 4096, 65536, weakPRNG, false, 1024 * 1024 * 2, secret);
        factory.setEncryption(enableCrypto());
        assertEquals(factory.getRamUsed(), 0);
        FileUtil.removeAll(f);
        f.mkdir();
        assertTrue(f.exists() && f.isDirectory());
    }

    @After
    public void tearDown() {
        assertEquals(factory.getRamUsed(), 0);
        // Everything should have been free()'ed.
        assertEquals(f.listFiles().length, 0);
        FileUtil.removeAll(f);
    }

    @Test
    public void testArrayMigration() throws IOException {
        Random r = new Random(21162506);
        for (int size : TEST_LIST_NOT_MIGRATED) {
            innerTestArrayMigration(size, r);
        }
    }

    @Test
    public void testBucketToRAFWhileArray() throws IOException {
        int len = 4095;
        Random r = new Random(21162101);
        TempBucket bucket = (TempBucket) factory.makeBucket(1024);
        byte[] buf = new byte[len];
        r.nextBytes(buf);
        OutputStream os = bucket.getOutputStream();
        os.write(buf.clone());
        os.close();
        assertTrue(bucket.isRAMBucket());
        assertEquals(len, bucket.size());
        TempRandomAccessBuffer raf = (TempRandomAccessBuffer) bucket.toRandomAccessBuffer();
        bucket.getInputStream().close(); // Can read.
        try {
            bucket.getOutputStream(); // Cannot write.
            fail();
        } catch (IOException e) {
            // Ok.
        }
        assertEquals(len, raf.size());
        assertFalse(raf.hasMigrated());
        checkArrayInner(buf, raf, len, r);
        // Now migrate to disk.
        raf.migrateToDisk();
        File f = ((PooledFileRandomAccessBuffer) raf.getUnderlying()).file;
        assertTrue(f.exists());
        assertEquals(len, f.length());
        assertTrue(raf.hasMigrated());
        assertEquals(factory.getRamUsed(), 0);
        checkArrayInner(buf, raf, len, r);
        checkBucket(bucket, buf);
        raf.close();
        raf.free();
        assertFalse(f.exists());
    }

    @Test
    public void testBucketToRAFCallTwiceArray() throws IOException {
        int len = 4095;
        Random r = new Random(21162101);
        TempBucket bucket = (TempBucket) factory.makeBucket(1024);
        byte[] buf = new byte[len];
        r.nextBytes(buf);
        OutputStream os = bucket.getOutputStream();
        os.write(buf.clone());
        os.close();
        assertTrue(bucket.isRAMBucket());
        assertEquals(len, bucket.size());
        TempRandomAccessBuffer raf = (TempRandomAccessBuffer) bucket.toRandomAccessBuffer();
        assertNotNull(raf);
        raf = (TempRandomAccessBuffer) bucket.toRandomAccessBuffer();
        assertNotNull(raf);
        raf.close();
        raf.free();
    }

    @Test
    public void testBucketToRAFCallTwiceFile() throws IOException {
        int len = 4095;
        Random r = new Random(21162101);
        TempBucket bucket = (TempBucket) factory.makeBucket(1024);
        byte[] buf = new byte[len];
        r.nextBytes(buf);
        OutputStream os = bucket.getOutputStream();
        os.write(buf.clone());
        os.close();
        assertTrue(bucket.isRAMBucket());
        assertEquals(len, bucket.size());
        assertTrue(bucket.migrateToDisk());
        TempRandomAccessBuffer raf = (TempRandomAccessBuffer) bucket.toRandomAccessBuffer();
        assertNotNull(raf);
        raf = (TempRandomAccessBuffer) bucket.toRandomAccessBuffer();
        assertNotNull(raf);
        raf.close();
        raf.free();
    }

    @Test
    public void testBucketToRAFFreeBucketWhileArray() throws IOException {
        int len = 4095;
        Random r = new Random(21162101);
        TempBucket bucket = (TempBucket) factory.makeBucket(1024);
        byte[] buf = new byte[len];
        r.nextBytes(buf);
        OutputStream os = bucket.getOutputStream();
        os.write(buf.clone());
        os.close();
        assertTrue(bucket.isRAMBucket());
        assertEquals(len, bucket.size());
        bucket.getInputStream().close();
        bucket.free();
        try {
            TempRandomAccessBuffer raf = (TempRandomAccessBuffer) bucket.toRandomAccessBuffer();
            fail();
        } catch (IOException e) {
            // Ok.
        }
    }

    @Test
    public void testBucketToRAFFreeWhileArray() throws IOException {
        int len = 4095;
        Random r = new Random(21162101);
        TempBucket bucket = (TempBucket) factory.makeBucket(1024);
        byte[] buf = new byte[len];
        r.nextBytes(buf);
        OutputStream os = bucket.getOutputStream();
        os.write(buf.clone());
        os.close();
        assertTrue(bucket.isRAMBucket());
        assertEquals(len, bucket.size());
        bucket.getInputStream().close();
        TempRandomAccessBuffer raf = (TempRandomAccessBuffer) bucket.toRandomAccessBuffer();
        bucket.free();
        try {
            raf.pread(0, new byte[len], 0, buf.length);
            fail();
        } catch (IOException e) {
            // Ok.
        }
        try {
            bucket.getInputStream();
            fail();
        } catch (IOException e) {
            // Ok.
        }
    }

    @Test
    public void testBucketToRAFFreeWhileFile() throws IOException {
        int len = 4095;
        Random r = new Random(21162101);
        TempBucket bucket = (TempBucket) factory.makeBucket(1024);
        byte[] buf = new byte[len];
        r.nextBytes(buf);
        OutputStream os = bucket.getOutputStream();
        os.write(buf.clone());
        os.close();
        assertTrue(bucket.isRAMBucket());
        assertEquals(len, bucket.size());
        bucket.getInputStream().close();
        TempRandomAccessBuffer raf = (TempRandomAccessBuffer) bucket.toRandomAccessBuffer();
        assertTrue(raf.migrateToDisk());
        assertFalse(raf.migrateToDisk());
        assertFalse(bucket.migrateToDisk());
        assertTrue(raf.hasMigrated());
        File f = ((PooledFileRandomAccessBuffer) raf.getUnderlying()).file;
        assertTrue(f.exists());
        bucket.free();
        assertFalse(f.exists());
        try {
            raf.pread(0, new byte[len], 0, buf.length);
            fail();
        } catch (IOException e) {
            // Ok.
        }
        try {
            bucket.getInputStream();
            fail();
        } catch (IOException e) {
            // Ok.
        }
    }

    @Test
    public void testBucketToRAFFreeWhileFileFreeRAF() throws IOException {
        int len = 4095;
        Random r = new Random(21162101);
        TempBucket bucket = (TempBucket) factory.makeBucket(1024);
        byte[] buf = new byte[len];
        r.nextBytes(buf);
        OutputStream os = bucket.getOutputStream();
        os.write(buf.clone());
        os.close();
        assertTrue(bucket.isRAMBucket());
        assertEquals(len, bucket.size());
        bucket.getInputStream().close();
        TempRandomAccessBuffer raf = (TempRandomAccessBuffer) bucket.toRandomAccessBuffer();
        raf.migrateToDisk();
        assertTrue(raf.hasMigrated());
        File f = ((PooledFileRandomAccessBuffer) raf.getUnderlying()).file;
        assertTrue(f.exists());
        raf.free();
        assertFalse(f.exists());
        try {
            raf.pread(0, new byte[len], 0, buf.length);
            fail();
        } catch (IOException e) {
            // Ok.
        }
        try {
            InputStream is = bucket.getInputStream();
            is.read(); // Tricky to make it fail on getInputStream(). FIXME.
            fail();
        } catch (IOException e) {
            // Ok.
        }
    }

    @Test
    public void testBucketToRAFFreeWhileFileMigrateFirst() throws IOException {
        int len = 4095;
        Random r = new Random(21162101);
        TempBucket bucket = (TempBucket) factory.makeBucket(1024);
        byte[] buf = new byte[len];
        r.nextBytes(buf);
        OutputStream os = bucket.getOutputStream();
        os.write(buf.clone());
        os.close();
        assertTrue(bucket.isRAMBucket());
        assertEquals(len, bucket.size());
        bucket.getInputStream().close();
        bucket.migrateToDisk();
        File f = getFile(bucket);
        assertTrue(f.exists());
        TempRandomAccessBuffer raf = (TempRandomAccessBuffer) bucket.toRandomAccessBuffer();
        assertTrue(raf.hasMigrated());
        bucket.free();
        assertFalse(f.exists());
        try {
            raf.pread(0, new byte[len], 0, buf.length);
            fail();
        } catch (IOException e) {
            // Ok.
        }
        try {
            bucket.getInputStream();
            fail();
        } catch (IOException e) {
            // Ok.
        }
    }

    @Test
    public void testBucketToRAFWhileFile() throws IOException {
        int len = 4095;
        Random r = new Random(21162101);
        TempBucket bucket = (TempBucket) factory.makeBucket(1024);
        byte[] buf = new byte[len];
        r.nextBytes(buf);
        OutputStream os = bucket.getOutputStream();
        os.write(buf.clone());
        os.close();
        assertTrue(bucket.isRAMBucket());
        assertEquals(len, bucket.size());
        // Migrate to disk
        bucket.migrateToDisk();
        assertFalse(bucket.isRAMBucket());
        File f = getFile(bucket);
        assertTrue(f.exists());
        if (enableCrypto()) {
            assertEquals(f.length(), 8192);
        } else {
            assertEquals(f.length(), 4095);
        }
        TempRandomAccessBuffer raf = (TempRandomAccessBuffer) bucket.toRandomAccessBuffer();
        assertTrue(f.exists());
        if (enableCrypto()) {
            assertEquals(f.length(), 8192);
        } else {
            assertEquals(f.length(), 4095);
        }
        assertEquals(len, raf.size());
        checkArrayInner(buf, raf, len, r);
        assertEquals(factory.getRamUsed(), 0);
        checkArrayInner(buf, raf, len, r);
        raf.close();
        raf.free();
        assertFalse(f.exists());
    }

    @Test
    public void testBucketToRAFFailure() throws IOException {
        int len = 4095;
        Random r = new Random(21162101);
        TempBucket bucket = (TempBucket) factory.makeBucket(1024);
        byte[] buf = new byte[len];
        r.nextBytes(buf);
        OutputStream os = bucket.getOutputStream();
        os.write(buf.clone());
        assertTrue(bucket.isRAMBucket());
        try {
            bucket.toRandomAccessBuffer();
            fail();
        } catch (IOException e) {
            // Ok.
        }
        os.close();
        InputStream is = bucket.getInputStream();
        try {
            bucket.toRandomAccessBuffer();
            fail();
        } catch (IOException e) {
            // Ok.
        }
        is.close();
        TempRandomAccessBuffer raf = (TempRandomAccessBuffer) bucket.toRandomAccessBuffer();
        try {
            bucket.getOutputStream(); // Cannot write.
            fail();
        } catch (IOException e) {
            // Ok.
        }
        checkBucket(bucket, buf);
        raf.free();
    }

    @Override
    protected RandomAccessBuffer construct(long size) throws IOException {
        return factory.makeRAF(size);
    }

    /**
     * Create an array, fill it with random numbers, write it sequentially to the RandomAccessBuffer,
     * then read randomly and compare.
     */
    protected void innerTestArrayMigration(int len, Random r) throws IOException {
        if (len == 0) {
            return;
        }
        byte[] buf = new byte[len];
        r.nextBytes(buf);
        RandomAccessBuffer raf = construct(len);
        TempRandomAccessBuffer t = (TempRandomAccessBuffer) raf;
        assertFalse(t.hasMigrated());
        assertEquals(factory.getRamUsed(), len);
        t.migrateToDisk();
        assertTrue(t.hasMigrated());
        assertEquals(factory.getRamUsed(), 0);
        raf.pwrite(0L, buf, 0, buf.length);
        checkArrayInner(buf, raf, len, r);
        raf.close();
        raf.free();
    }

    private File getFile(TempBucket bucket) {
        if (!this.enableCrypto()) {
            return ((TempFileBucket) (bucket.getUnderlying())).getFile();
        } else {
            EncryptedRandomAccessBucket erab = (EncryptedRandomAccessBucket) bucket.getUnderlying();
            RandomAccessBucket b = erab.getUnderlying();
            if (b instanceof PaddedRandomAccessBucket) {
                b = ((PaddedRandomAccessBucket) b).getUnderlying();
            }
            return ((TempFileBucket) b).getFile();
        }
    }

    private void checkBucket(TempBucket bucket, byte[] buf) throws IOException {
        DataInputStream dis = new DataInputStream(bucket.getInputStream());
        byte[] cbuf = new byte[buf.length];
        dis.readFully(cbuf);
        assertArrayEquals(buf, cbuf);
    }

    private void checkArrayInner(byte[] buf, RandomAccessBuffer raf, int len, Random r)
        throws IOException {
        for (int i = 0; i < 100; i++) {
            int end = len == 1 ? 1 : r.nextInt(len) + 1;
            int start = r.nextInt(end);
            checkArraySectionEqualsReadData(buf, raf, start, end, true);
        }
        checkArraySectionEqualsReadData(buf, raf, 0, len, true);
        if (len > 1) {
            checkArraySectionEqualsReadData(buf, raf, 1, len - 1, true);
        }
    }
    static final MasterSecret secret = new MasterSecret();
    private static final int[] TEST_LIST = new int[]{0, 1, 32, 64, 32768, 1024 * 1024, 1024 * 1024 + 1};
    private static final int[] TEST_LIST_NOT_MIGRATED = new int[]{1, 32, 64, 1024, 2048, 4095};
    private final Random weakPRNG = new Random(12340);
    private final Executor exec = new SerialExecutor(NativeThread.PriorityLevel.NORM_PRIORITY.value);
    private final File f = new File("temp-bucket-raf-test");
    private FilenameGenerator fg;
    private TempBucketFactory factory;

}
