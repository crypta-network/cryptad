package network.crypta.node;

public class MasterKeysFileSizeException extends Exception {

	final private static long serialVersionUID = -2753942792186990130L;

	final public boolean tooBig;

	public MasterKeysFileSizeException(boolean tooBig) {
		this.tooBig = tooBig;
	}

	public boolean isTooBig() {
		return tooBig;
	}

	public String sizeToString() {
		return tooBig? "big" : "small";
	}

}
