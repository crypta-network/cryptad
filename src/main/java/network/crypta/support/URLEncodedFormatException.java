package network.crypta.support;

import java.io.Serial;

/**
 * Thrown when trying to decode a string which is not in 
 * "<code>x-www-form-urlencoded</code>" format.
 **/
public class URLEncodedFormatException extends Exception {
	@Serial private static final long serialVersionUID = -1;
	
    URLEncodedFormatException () {}
    URLEncodedFormatException (String s) { super(s); }
}
