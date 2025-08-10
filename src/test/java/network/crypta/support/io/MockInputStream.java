package network.crypta.support.io;

import java.io.InputStream;

public class MockInputStream extends InputStream {

    public MockInputStream() {
    }

    @Override
    public int read() {
        return -1;
    }

    @Override
    public int read(byte[] data, int offset, int len) {
        return len;
    }
}