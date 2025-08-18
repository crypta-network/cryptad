package network.crypta.client.async;

import java.io.Serial;
import java.util.List;

import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchException;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.crypt.HashResult;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.node.RequestClient;
import network.crypta.support.compress.Compressor;
import network.crypta.support.io.ResumeFailedException;

/**
 * Wrapper for a backgrounded USKFetcher.
 */
public class USKFetcherWrapper extends BaseClientGetter {
	@Serial private static final long serialVersionUID = -6416069493740293035L;

	final USK usk;
	
	public USKFetcherWrapper(USK usk, short prio, final RequestClient client) {
		super(prio, client);
		this.usk = usk;
	}

	@Override
	public FreenetURI getURI() {
		return usk.getURI();
	}

	@Override
	public boolean isFinished() {
		return false;
	}

	@Override
	protected void innerNotifyClients(ClientContext context) {
		// Do nothing
	}

	@Override
	public void onSuccess(StreamGenerator streamGenerator, ClientMetadata clientMetadata, List<? extends Compressor> decompressors, ClientGetState state, ClientContext context) {
		// Ignore; we don't do anything with it because we are running in the background.
	}

	@Override
	public void onFailure(FetchException e, ClientGetState state, ClientContext context) {
		// Ignore
	}

	@Override
	public void onBlockSetFinished(ClientGetState state, ClientContext context) {
		// Ignore
	}

	@Override
	public void onTransition(ClientGetState oldState, ClientGetState newState, ClientContext context) {
		// Ignore
	}

	@Override
	public String toString() {
		return super.toString()+ ':' +usk;
	}

	@Override
	public void onExpectedMIME(ClientMetadata meta, ClientContext context) {
		// Ignore
	}

	@Override
	public void onExpectedSize(long size, ClientContext context) {
		// Ignore
	}

	@Override
	public void onFinalizedMetadata() {
		// Ignore
	}

	@Override
	public void cancel(ClientContext context) {
		super.cancel();
	}

	@Override
	protected void innerToNetwork(ClientContext context) {
		// Ignore
	}

	@Override
	public void onExpectedTopSize(long size, long compressed, int blocksReq, int blocksTotal, ClientContext context) {
		// Ignore
	}

	@Override
	public void onSplitfileCompatibilityMode(CompatibilityMode min, CompatibilityMode max, byte[] splitfileKey, boolean compressed, boolean bottomLayer, boolean definitiveAnyway, ClientContext context) {
		// Ignore
	}

	@Override
	public void onHashes(HashResult[] hashes, ClientContext context) {
		// Ignore
	}

    @Override
    public void innerOnResume(ClientContext context) throws ResumeFailedException {
        super.innerOnResume(context);
    }

    @Override
    protected ClientBaseCallback getCallback() {
        return null;
    }
}
