package network.crypta.support.io;

import java.io.IOException;
import java.io.Serial;

/** Thrown when the file being loaded appears not to be a stored splitfile or other request. */
public class StorageFormatException extends Exception {
	@Serial private static final long serialVersionUID = 6953756148374736258L;

    public StorageFormatException(String message) {
        super(message);
    }

    public StorageFormatException(String message, IOException e) {
        super(message, e);
    }
    
}
