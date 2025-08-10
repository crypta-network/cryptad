package network.crypta.node;

import network.crypta.support.SimpleFieldSet;

/**
 * Something that can be persisted to disk in the form of a SimpleFieldSet.
 */
public interface Persistable {

	SimpleFieldSet persistThrottlesToFieldSet();

}
