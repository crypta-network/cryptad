package network.crypta.store;

import network.crypta.support.LightweightException;
import network.crypta.support.Logger;

public class KeyCollisionException extends LightweightException {
	private static final long serialVersionUID = -1;
    private static volatile boolean logDEBUG;
    
    static { Logger.registerClass(KeyCollisionException.class); }
    
    @Override
    protected boolean shouldFillInStackTrace() {
        return logDEBUG;
    }
}
