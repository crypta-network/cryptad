package network.crypta.support.io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * A wrapper that overwrites {@link #skip} and delegates to {@link #read} instead.
 *
 * <p>Some implementations of {@link InputStream} implement {@link
 * InputStream#skip} in a way that throws an expecption if the stream
 * is not seekable - {@link System#in System.in} is known to behave
 * that way. For such a stream it is impossible to invoke skip at all
 * and you have to read from the stream (and discard the data read)
 * instead. Skipping is potentially much faster than reading so we do
 * want to invoke {@code skip} when possible. We provide this class so
 * you can wrap your own {@link InputStream} in it if you encounter
 * problems with {@code skip} throwing an excpetion.</p>
 *
 * @since 1.17
 */
public class SkipShieldingInputStream extends FilterInputStream {
    private static final int SKIP_BUFFER_SIZE = 8192;
    // we can use a shared buffer as the content is discarded anyway
    private static final byte[] SKIP_BUFFER = new byte[SKIP_BUFFER_SIZE];
    public SkipShieldingInputStream(InputStream in) {
        super(in);
    }

    @Override
    public long skip(long n) throws IOException {
        int retval;
        if (n < 0) {
            retval = 0;
        }
        else {
            retval = read(SKIP_BUFFER, 0, (int) Math.min(n, SKIP_BUFFER_SIZE));
            if (retval < 0) {
                retval = 0;
            }
        }
        return retval;
    }
}
