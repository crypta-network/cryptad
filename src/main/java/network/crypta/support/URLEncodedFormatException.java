package network.crypta.support;

/**
 * Thrown when trying to decode a string which is not in 
 * "<code>x-www-form-urlencoded</code>" format.
 **/
public class URLEncodedFormatException extends Exception {
	private static final long serialVersionUID = -1;
	
    URLEncodedFormatException () {}
    URLEncodedFormatException (String s) { super(s); }
}
