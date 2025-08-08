/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package network.crypta.pluginmanager;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;

import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchResult;
import network.crypta.client.FetchWaiter;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.events.ClientEvent;
import network.crypta.client.events.ClientEventListener;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.pluginmanager.PluginManager.PluginProgress;
import network.crypta.support.Logger;

public class PluginDownLoaderFreenet extends PluginDownLoader<FreenetURI> {
	final HighLevelSimpleClient hlsc;
	final boolean desperate;
	final Node node;
	private boolean fatalFailure;
	private ClientGetter get;

	PluginDownLoaderFreenet(HighLevelSimpleClient hlsc, Node node, boolean desperate) {
		this.hlsc = hlsc.clone();
		this.node = node;
		this.desperate = desperate;
	}

	@Override
	public FreenetURI checkSource(String source) throws PluginNotFoundException {
		try {
			return new FreenetURI(source);
		} catch (MalformedURLException e) {
			Logger.error(this, "not a valid freenet key: " + source, e);
			throw new PluginNotFoundException("not a valid freenet key: " + source, e);
		}
	}

	@Override
	InputStream getInputStream(final PluginProgress progress) throws IOException, PluginNotFoundException {
		FreenetURI uri = getSource();
		System.out.println("Downloading plugin from Crypta: "+uri);
		while (true) {
			try {
				progress.setDownloading();
				hlsc.addEventHook(new ClientEventListener() {

					@Override
					public void receive(ClientEvent ce, ClientContext context) {
						if(ce instanceof SplitfileProgressEvent split) {
                            if(split.finalizedTotal) {
								progress.setDownloadProgress(split.minSuccessfulBlocks, split.succeedBlocks, split.totalBlocks, split.failedBlocks, split.fatallyFailedBlocks, split.finalizedTotal);
							}
						}
					}
					
				});
				FetchContext context = hlsc.getFetchContext();
				if(desperate) {
					context.maxNonSplitfileRetries = -1;
					context.maxSplitfileBlockRetries = -1;
				}
				FetchWaiter fw = new FetchWaiter(node.getNonPersistentClientBulk());

				get = new ClientGetter(fw, uri, context, PluginManager.PRIO, null, null, null);
				try {
					node.getClientCore().getClientContext().start(get);
				} catch (PersistenceDisabledException e) {
					// Impossible
				}
				FetchResult res = fw.waitForCompletion();
				return res.asBucket().getInputStream();
			} catch (FetchException e) {
				if ((e.getMode() == FetchExceptionMode.PERMANENT_REDIRECT) || (e.getMode() == FetchExceptionMode.TOO_MANY_PATH_COMPONENTS)) {
					uri = e.newURI;
					continue;
				}
				if(e.isFatal())
					fatalFailure = true;
				Logger.error(this, "error while fetching plugin: " + getSource(), e);
				throw new PluginNotFoundException("error while fetching plugin: " + e.getMessage() + " for key "  + getSource(), e);
			}
		}
	}

	@Override
	String getPluginName(String source) throws PluginNotFoundException {
		return source.substring(source.lastIndexOf('/') + 1);
	}

	@Override
	String getSHA1sum() throws PluginNotFoundException {
		return null;
	}

	public boolean fatalFailure() {
		return fatalFailure;
	}

	@Override
	void tryCancel() {
		if(get != null)
			get.cancel(node.getClientCore().getClientContext());
	}

	@Override
	public boolean isLoadingFromFreenet() {
		return true;
	}

	public PluginDownLoader<FreenetURI> getRetryDownloader() {
		return new PluginDownLoaderFreenet(hlsc, node, true);
	}

}
