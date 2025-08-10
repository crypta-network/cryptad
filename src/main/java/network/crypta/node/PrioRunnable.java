package network.crypta.node;

/**
 * A Runnable which specifies a priority.
 * @author toad
 */
public interface PrioRunnable extends Runnable {

	int getPriority();
	
}
