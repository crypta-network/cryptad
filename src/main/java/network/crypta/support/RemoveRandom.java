package network.crypta.support;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.RequestSelectionTreeNode;

public interface RemoveRandom extends RequestSelectionTreeNode {

	// OPTIMISE: Would a stack-trace-less exception be faster?
	/** Either a RandomGrabArrayItem or the time at which we should try again. */
	final class RemoveRandomReturn {
		public final RandomGrabArrayItem item;
		public final long wakeupTime;
		RemoveRandomReturn(RandomGrabArrayItem item) {
			this.item = item;
			this.wakeupTime = -1;
		}
		RemoveRandomReturn(long wakeupTime) {
			this.item = null;
			this.wakeupTime = wakeupTime;
		}
	}
	
	/** Return a random RandomGrabArrayItem, or a time at which there will be one, or null
	 * if the RGA is empty and should be removed by the parent. */
    RemoveRandomReturn removeRandom(RandomGrabArrayItemExclusionList excluding, ClientContext context, long now);

	void setParent(RemoveRandomParent newTopLevel);

}
