package network.crypta.support.io;

import java.io.*;

import network.crypta.client.async.ClientContext;
import network.crypta.crypt.MasterSecret;
import network.crypta.support.LogThresholdCallback;
import network.crypta.support.Logger;
import network.crypta.support.Logger.LogLevel;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.RandomAccessBucket;

public class DelayedFreeBucket implements Bucket, Serializable, DelayedFree {

	@Serial private static final long serialVersionUID = 1L;
    // Only set on construction and on onResume() on startup. So shouldn't need locking.
	private transient PersistentFileTracker factory;
	private final Bucket bucket;
	private boolean freed;
	/** Has the bucket been migrated to a RandomAccessBucket? If so it should not be accessed 
	 * again, and in particular it should not be freed, since the new DelayedFreeRandomAccessBucket
	 * will share share the underlying RandomAccessBucket. */
	private boolean migrated;
	private transient long createdCommitID;

        private static volatile boolean logMINOR;
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}
	
	@Override
	public synchronized boolean toFree() {
		return freed;
	}
	
	public DelayedFreeBucket(PersistentFileTracker factory, Bucket bucket) {
		this.factory = factory;
		this.bucket = bucket;
		this.createdCommitID = factory.commitID();
		if(bucket == null) throw new NullPointerException();
	}

    @Override
	public OutputStream getOutputStream() throws IOException {
        synchronized(this) {
            if(migrated) throw new IOException("Already migrated to a RandomAccessBucket");
            if(freed) throw new IOException("Already freed");
        }
		return bucket.getOutputStream();
	}

    @Override
    public OutputStream getOutputStreamUnbuffered() throws IOException {
        synchronized(this) {
            if(migrated) throw new IOException("Already migrated to a RandomAccessBucket");
            if(freed) throw new IOException("Already freed");
        }
        return bucket.getOutputStreamUnbuffered();
    }

	@Override
	public InputStream getInputStream() throws IOException {
	    synchronized(this) {
	        if(migrated) throw new IOException("Already migrated to a RandomAccessBucket");
	        if(freed) throw new IOException("Already freed");
	    }
		return bucket.getInputStream();
	}

    @Override
    public InputStream getInputStreamUnbuffered() throws IOException {
        synchronized(this) {
            if(migrated) throw new IOException("Already migrated to a RandomAccessBucket");
            if(freed) throw new IOException("Already freed");
        }
        return bucket.getInputStreamUnbuffered();
    }

	@Override
	public String getName() {
		return bucket.getName();
	}

	@Override
	public long size() {
		return bucket.size();
	}

	@Override
	public boolean isReadOnly() {
		return bucket.isReadOnly();
	}

	@Override
	public void setReadOnly() {
		bucket.setReadOnly();
	}

    public synchronized Bucket getUnderlying() {
		if(freed) return null;
		if(migrated) return null;
		return bucket;
	}
	
	@Override
	public void free() {
	    synchronized(this) {
	        if(freed) return;
	        if(migrated) return;
	        freed = true;
	    }
	    if(logMINOR)
	        Logger.minor(this, "Freeing "+this+" underlying="+bucket, new Exception("debug"));
	    this.factory.delayedFree(this, createdCommitID);
	}

	@Override
	public String toString() {
		return super.toString()+":"+bucket;
	}
	
	@Override
	public Bucket createShadow() {
		return bucket.createShadow();
	}

	@Override
    public void realFree() {
		bucket.free();
	}

    @Override
    public void onResume(ClientContext context) throws ResumeFailedException {
        this.factory = context.persistentBucketFactory;
        bucket.onResume(context);
    }
    
    static final int MAGIC = 0x4e9c9a03;
    static final int VERSION = 1;

    @Override
    public void storeTo(DataOutputStream dos) throws IOException {
        dos.writeInt(MAGIC);
        dos.writeInt(VERSION);
        bucket.storeTo(dos);
    }

    protected DelayedFreeBucket(DataInputStream dis, FilenameGenerator fg, 
            PersistentFileTracker persistentFileTracker, MasterSecret masterKey) 
    throws StorageFormatException, IOException, ResumeFailedException {
        int version = dis.readInt();
        if(version != VERSION) throw new StorageFormatException("Bad version");
        bucket = BucketTools.restoreFrom(dis, fg, persistentFileTracker, masterKey);
    }
    
    /** Convert to a RandomAccessBucket if it can be done quickly. Otherwise return null. 
     * @throws IOException If the bucket has already been freed. */
    public synchronized RandomAccessBucket toRandomAccessBucket() throws IOException {
        if(freed) throw new IOException("Already freed");
        if(bucket instanceof RandomAccessBucket accessBucket) {
            migrated = true;
            return new DelayedFreeRandomAccessBucket(factory, accessBucket);
            // Underlying file is already registered.
        }
        return null;
    }

}