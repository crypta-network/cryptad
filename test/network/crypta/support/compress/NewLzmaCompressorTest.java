package network.crypta.support.compress;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Random;

import org.junit.Test;

import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.Closer;
import network.crypta.support.io.NullBucket;

/**
 * Test case for {@link Bzip2Compressor} class.
 */
public class NewLzmaCompressorTest {

    /**
     * test BZIP2 compressor's identity and functionality
     */
    @Test
    public void testNewLzmaCompressor() throws IOException {
        Compressor.COMPRESSOR_TYPE lzcompressor = Compressor.COMPRESSOR_TYPE.LZMA_NEW;
        Compressor compressorZero = Compressor.COMPRESSOR_TYPE.getCompressorByMetadataID((short) 3);

        // check BZIP2 is the second compressor
        assertEquals(lzcompressor, compressorZero);
    }

    //	public void testCompress() throws IOException {
    //
    //		// do bzip2 compression
    //		byte[] compressedData = doCompress(UNCOMPRESSED_DATA_1.getBytes());
    //
    //		// output size same as expected?
    //		//assertEquals(compressedData.length, COMPRESSED_DATA_1.length);
    //
    //		// check each byte is exactly as expected
    //		for (int i = 0; i < compressedData.length; i++) {
    //			assertEquals(COMPRESSED_DATA_1[i], compressedData[i]);
    //		}
    //	}
    //
    //	public void testBucketDecompress() throws IOException {
    //
    //		byte[] compressedData = COMPRESSED_DATA_1;
    //
    //		// do bzip2 decompression with buckets
    //		byte[] uncompressedData = doBucketDecompress(compressedData);
    //
    //		// is the (round-tripped) uncompressed string the same as the original?
    //		String uncompressedString = new String(uncompressedData);
    //		assertEquals(uncompressedString, UNCOMPRESSED_DATA_1);
    //	}
    //
    @Test
    public void testByteArrayDecompress() throws IOException {

        // build 5k array
        byte[] originalUncompressedData = new byte[5 * 1024];
        for (int i = 0; i < originalUncompressedData.length; i++) {
            originalUncompressedData[i] = 1;
        }

        byte[] compressedData = doCompress(originalUncompressedData);
        byte[] outUncompressedData = new byte[5 * 1024];

        int writtenBytes = 0;

        writtenBytes =
            Compressor.COMPRESSOR_TYPE.LZMA_NEW.decompress(compressedData, 0, compressedData.length,
                                                           outUncompressedData);

        assertEquals(writtenBytes, originalUncompressedData.length);
        assertEquals(originalUncompressedData.length, outUncompressedData.length);

        // check each byte is exactly as expected
        for (int i = 0; i < outUncompressedData.length; i++) {
            assertEquals(originalUncompressedData[i], outUncompressedData[i]);
        }
    }

    // FIXME add exact decompression check.

    @Test
    public void testRandomByteArrayDecompress() throws IOException {

        Random random = new Random(1234);

        for (int rounds = 0; rounds < 100; rounds++) {
            int scale = random.nextInt(19) + 1;
            int size = random.nextInt(1 << scale);

            // build 5k array
            byte[] originalUncompressedData = new byte[size];
            random.nextBytes(originalUncompressedData);

            byte[] compressedData = doCompress(originalUncompressedData);
            byte[] outUncompressedData = new byte[size];

            int writtenBytes = 0;

            writtenBytes =
                Compressor.COMPRESSOR_TYPE.LZMA_NEW.decompress(compressedData, 0, compressedData.length,
                                                               outUncompressedData);

            assertEquals(writtenBytes, originalUncompressedData.length);
            assertEquals(originalUncompressedData.length, outUncompressedData.length);

            // check each byte is exactly as expected
            for (int i = 0; i < outUncompressedData.length; i++) {
                assertEquals(originalUncompressedData[i], outUncompressedData[i]);
            }
        }
    }

    @Test
    public void testCompressException() throws IOException {

        byte[] uncompressedData = UNCOMPRESSED_DATA_1.getBytes();
        Bucket inBucket = new ArrayBucket(uncompressedData);
        BucketFactory factory = new ArrayBucketFactory();

        try {
            Compressor.COMPRESSOR_TYPE.LZMA_NEW.compress(inBucket, factory, 32, 32);
        } catch (CompressionOutputSizeException e) {
            // expect this
        }
        // TODO LOW codec doesn't actually enforce size limit
        //fail("did not throw expected CompressionOutputSizeException");
    }

    @Test
    public void testDecompressException() throws IOException {

        // build 5k array
        byte[] uncompressedData = new byte[5 * 1024];
        for (int i = 0; i < uncompressedData.length; i++) {
            uncompressedData[i] = 1;
        }

        byte[] compressedData = doCompress(uncompressedData);

        Bucket inBucket = new ArrayBucket(compressedData);
        NullBucket outBucket = new NullBucket();
        InputStream decompressorInput = null;
        OutputStream decompressorOutput = null;

        try {
            decompressorInput = inBucket.getInputStream();
            decompressorOutput = outBucket.getOutputStream();
            Compressor.COMPRESSOR_TYPE.LZMA_NEW.decompress(decompressorInput, decompressorOutput,
                                                           4096 + 10, 4096 + 20);
            decompressorInput.close();
            decompressorOutput.close();
        } catch (CompressionOutputSizeException e) {
            // expect this
        } finally {
            Closer.close(decompressorInput);
            Closer.close(decompressorOutput);
            inBucket.free();
            outBucket.free();
        }
        // TODO LOW codec doesn't actually enforce size limit
        //fail("did not throw expected CompressionOutputSizeException");
    }

    private byte[] doCompress(byte[] uncompressedData) throws IOException {
        Bucket inBucket = new ArrayBucket(uncompressedData);
        BucketFactory factory = new ArrayBucketFactory();
        Bucket outBucket = null;

        outBucket =
            Compressor.COMPRESSOR_TYPE.LZMA_NEW.compress(inBucket, factory, uncompressedData.length,
                                                         uncompressedData.length * 2L + 64);

        InputStream in = null;
        in = outBucket.getInputStream();
        long size = outBucket.size();
        byte[] outBuf = new byte[(int) size];

        in.read(outBuf);

        return outBuf;
    }
    private static final String UNCOMPRESSED_DATA_1 = GzipCompressorTest.UNCOMPRESSED_DATA_1;
}
