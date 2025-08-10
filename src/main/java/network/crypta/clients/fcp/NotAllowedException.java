package network.crypta.clients.fcp;

/** Thrown when a client tries to upload a file it's not allowed to upload (or otherwise read it), or 
 * download to a file which it's not allowed to download to (or otherwise write to). */
public class NotAllowedException extends Exception {
	private static final long serialVersionUID = 1L;
}
