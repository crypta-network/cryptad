package network.crypta.client.async;

import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;

import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchResult;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.KeyDecodeException;
import network.crypta.keys.TooBigException;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.SendableRequestItem;
import network.crypta.support.LogThresholdCallback;
import network.crypta.support.Logger;
import network.crypta.support.Logger.LogLevel;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.InsufficientDiskSpaceException;

/** 
 * Fetch a single block file. Used directly for very simple fetches, but also base class for 
 * SingleFileFetcher.
 * 
 * WARNING: Changing non-transient members on classes that are Serializable can result in 
 * restarting downloads or losing uploads.
 */
public class SimpleSingleFileFetcher extends BaseSingleFileFetcher implements ClientGetState, Serializable {

	@Serial private static final long serialVersionUID = 1L;

    SimpleSingleFileFetcher(ClientKey key, int maxRetries, FetchContext ctx, ClientRequester parent, 
			GetCompletionCallback rcb, boolean isEssential, boolean dontAdd, long l, ClientContext context, boolean deleteFetchContext, boolean realTimeFlag) {
		super(key, maxRetries, ctx, parent, deleteFetchContext, realTimeFlag);
		this.rcb = rcb;
		this.token = l;
		if(!dontAdd) {
			if(isEssential)
				parent.addMustSucceedBlocks(1);
			else
				parent.addBlock();
			parent.notifyClients(context);
		}
	}
    
	final GetCompletionCallback rcb;
	final long token;

        private static volatile boolean logMINOR;
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}
	
	// Translate it, then call the real onFailure
	@Override
	public void onFailure(LowLevelGetException e, SendableRequestItem reqTokenIgnored, ClientContext context) {
	    onFailure(translateException(e), false, context);
	}

	// Real onFailure
	protected void onFailure(FetchException e, boolean forceFatal, ClientContext context) {
		if(logMINOR) Logger.minor(this, "onFailure( "+e+" , "+forceFatal+")", e);
		if(parent.isCancelled() || cancelled) {
			if(logMINOR) Logger.minor(this, "Failing: cancelled");
			e = new FetchException(FetchExceptionMode.CANCELLED);
			forceFatal = true;
		}
		if(!(e.isFatal() || forceFatal) ) {
			if(retry(context)) {
				if(logMINOR) Logger.minor(this, "Retrying");
				return;
			}
		}
		// :(
		unregisterAll(context);
		synchronized(this) {
			finished = true;
		}
		if(e.isFatal() || forceFatal)
			parent.fatallyFailedBlock(context);
		else
			parent.failedBlock(context);
		rcb.onFailure(e, this, context);
	}

	/** Will be overridden by SingleFileFetcher */
	protected void onSuccess(FetchResult data, ClientContext context) {
		if(parent.isCancelled()) {
			data.asBucket().free();
			onFailure(new FetchException(FetchExceptionMode.CANCELLED), false, context);
			return;
		}
		rcb.onSuccess(new SingleFileStreamGenerator(data.asBucket(), persistent), data.getMetadata(), null, this, context);
	}

	@Override
	public void onSuccess(ClientKeyBlock block, boolean fromStore, Object reqTokenIgnored, ClientContext context) {
		if(parent instanceof ClientGetter getter)
			getter.addKeyToBinaryBlob(block, context);
		Bucket data = extract(block, context);
		if(data == null) return; // failed
		context.uskManager.checkUSK(key.getURI(), fromStore, block.isMetadata());
		if(!block.isMetadata()) {
			onSuccess(new FetchResult(new ClientMetadata(null), data), context);
		} else {
			onFailure(new FetchException(FetchExceptionMode.INVALID_METADATA, "Metadata where expected data"), false, context);
		}
	}

	/** Convert a ClientKeyBlock to a Bucket. If an error occurs, report it via onFailure
	 * and return null.
	 */
	protected Bucket extract(ClientKeyBlock block, ClientContext context) {
		Bucket data;
		try {
			data = block.decode(context.getBucketFactory(parent.persistent()), (int)(Math.min(ctx.maxOutputLength, Integer.MAX_VALUE)), false);
		} catch (KeyDecodeException e1) {
			if(logMINOR)
				Logger.minor(this, "Decode failure: "+e1, e1);
			onFailure(new FetchException(FetchExceptionMode.BLOCK_DECODE_ERROR, e1.getMessage()), false, context);
			return null;
		} catch (TooBigException e) {
			onFailure(new FetchException(FetchExceptionMode.TOO_BIG, e), false, context);
			return null;
		} catch (InsufficientDiskSpaceException e) {
		    onFailure(new FetchException(FetchExceptionMode.NOT_ENOUGH_DISK_SPACE), false, context);
		    return null;
		} catch (IOException e) {
			Logger.error(this, "Could not capture data - disk full?: "+e, e);
			onFailure(new FetchException(FetchExceptionMode.BUCKET_ERROR, e), false, context);
			return null;
		}
		return data;
	}

	/** getToken() is not supported */
	@Override
	public long getToken() {
		return token;
	}

	@Override
	public void cancel(ClientContext context) {
		super.cancel(context);
		rcb.onFailure(new FetchException(FetchExceptionMode.CANCELLED), this, context);
	}

	@Override
	protected void notFoundInStore(ClientContext context) {
		this.onFailure(new FetchException(FetchExceptionMode.DATA_NOT_FOUND), true, context);
	}

	@Override
	protected void onBlockDecodeError(SendableRequestItem token, ClientContext context) {
		onFailure(new FetchException(FetchExceptionMode.BLOCK_DECODE_ERROR, "Could not decode block with the URI given, probably invalid as inserted, possible the URI is wrong"), true, context);
	}

    @Override
    public void onShutdown(ClientContext context) {
        // Do nothing.
    }

    @Override
    protected ClientGetState getClientGetState() {
        return this;
    }
    
}
