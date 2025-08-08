package network.crypta.clients.fcp;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.USKCallback;
import network.crypta.client.async.USKProgressCallback;
import network.crypta.keys.USK;
import network.crypta.node.NodeClientCore;

public class SubscribeUSK implements USKProgressCallback {

	// FIXME allow client to specify priorities
	final FCPConnectionHandler handler;
	final String identifier;
	final NodeClientCore core;
	final boolean dontPoll;
	final short prio;
	final short prioProgress;
	final USK usk;
	final USKCallback toUnsub;
	
	public SubscribeUSK(SubscribeUSKMessage message, NodeClientCore core, FCPConnectionHandler handler) throws IdentifierCollisionException {
		this.handler = handler;
		this.dontPoll = message.dontPoll;
		this.identifier = message.identifier;
		this.core = core;
		this.usk = message.key;
		prio = message.prio;
		prioProgress = message.prioProgress;
		handler.addUSKSubscription(identifier, this);
		if((!message.dontPoll) && message.sparsePoll)
			toUnsub = core.getUskManager().subscribeSparse(message.key, this, message.ignoreUSKDatehints,
					handler.getRebootClient().lowLevelClient(message.realTimeFlag));
		else {
			core.getUskManager().subscribe(message.key, this, !message.dontPoll, message.ignoreUSKDatehints,
					handler.getRebootClient().lowLevelClient(message.realTimeFlag));
			toUnsub = this;
		}
	}

	@Override
	public void onFoundEdition(long l, USK key, ClientContext context, boolean wasMetadata, short codec, byte[] data, boolean newKnownGood, boolean newSlotToo) {
		if(handler.isClosed()) {
			core.getUskManager().unsubscribe(key, toUnsub);
			return;
		}
		//if(newKnownGood && !newSlotToo) return;
		FCPMessage msg = new SubscribedUSKUpdate(identifier, l, key, newKnownGood, newSlotToo);
		handler.send(msg);
	}

	@Override
	public short getPollingPriorityNormal() {
		return prio;
	}

	@Override
	public short getPollingPriorityProgress() {
		return prioProgress;
	}

	public void unsubscribe() {
		core.getUskManager().unsubscribe(usk, toUnsub);
	}

	@Override
	public void onSendingToNetwork(ClientContext context) {
		handler.send(new SubscribedUSKSendingToNetworkMessage(identifier));
	}

	@Override
	public void onRoundFinished(ClientContext context) {
		handler.send(new SubscribedUSKRoundFinishedMessage(identifier));
	}

}
