package network.crypta.support.io;
import java.io.*;

import network.crypta.client.async.ClientContext;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.RandomAccessBucket;

public class NullBucket implements Bucket, Serializable, RandomAccessBucket {

	@Serial private static final long serialVersionUID = 1L;
    public static final OutputStream nullOut = new NullOutputStream();
    public static final InputStream  nullIn  = new NullInputStream();

    public final long length;
    
    public NullBucket() {
        this(0);
    }

    public NullBucket(long length) {
        this.length = length;
    }
    
    /**
     * Returns an OutputStream that is used to put data in this Bucket.
     **/
    @Override
    public OutputStream getOutputStream() { return nullOut; }

    @Override
    public OutputStream getOutputStreamUnbuffered() { return nullOut; }

    /**
     * Returns an InputStream that reads data from this Bucket. If there is
     * no data in this bucket, null is returned.
     **/
    @Override
    public InputStream getInputStream() { return nullIn; }

    @Override
    public InputStream getInputStreamUnbuffered() { return nullIn; }

    /**
     * Returns the amount of data currently in this bucket.
     **/
    @Override
    public long size() {
        return length;
    }

    /** Returns the name of this NullBucket. */
    @Override
    public String getName() {
    	return "President George W. NullBucket";
    }

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public void setReadOnly() {
		// Do nothing
	}

	@Override
	public void free() {
		// Do nothing
	}

	@Override
	public RandomAccessBucket createShadow() {
		return new NullBucket();
	}

    @Override
    public void onResume(ClientContext context) {
        // Do nothing.
    }

    @Override
    public void storeTo(DataOutputStream dos) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public LockableRandomAccessBuffer toRandomAccessBuffer() throws IOException {
        return new NullRandomAccessBuffer(length);
    }
}

