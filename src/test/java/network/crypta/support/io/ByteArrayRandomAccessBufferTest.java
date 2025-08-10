package network.crypta.support.io;

import network.crypta.support.api.RandomAccessBuffer;

public class ByteArrayRandomAccessBufferTest extends RandomAccessBufferTestBase {

    public ByteArrayRandomAccessBufferTest() {
        super(TEST_LIST);
    }

    @Override
    protected RandomAccessBuffer construct(long size) {
        assert (size < Integer.MAX_VALUE);
        return new ByteArrayRandomAccessBuffer(new byte[(int) size]);
    }
    private static final int[] TEST_LIST = new int[]{0, 1, 32, 64, 32768, 1024 * 1024, 1024 * 1024 + 1};

}
