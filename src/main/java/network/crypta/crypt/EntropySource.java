package network.crypta.crypt;

/**
 * A token used as an argument to a RandomSource's acceptTimerEntropy.
 * One such token must exist for each timed source.
 **/
public class EntropySource {
    public long lastVal;
    public int lastDelta, lastDelta2;
}
	
