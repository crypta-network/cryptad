package network.crypta.crypt;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;

import network.crypta.support.io.Closer;

/**
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public class SHA256 {

	/**
	 * It won't reset the Message Digest for you!
	 * @param InputStream
	 * @param MessageDigest
	 * @return
	 * @throws IOException
	 */
	public static void hash(InputStream is, MessageDigest md) throws IOException {
		try {
			byte[] buf = new byte[4096];
			int readBytes = is.read(buf);
			while(readBytes > -1) {
				md.update(buf, 0, readBytes);
				readBytes = is.read(buf);
			}
			is.close();
		} finally {
			Closer.close(is);
		}
	}

	/**
	 * Create a new SHA-256 MessageDigest
	 */
	public static MessageDigest getMessageDigest() {
		return HashType.SHA256.get();
	}

	/**
	 * No-op function retained for backwards compatibility.
	 *
	 * @deprecated message digests are no longer pooled, there is no need to return them
	 */
	@Deprecated
	public static void returnMessageDigest(MessageDigest md256) {
	}

	public static byte[] digest(byte[] data) {
		return getMessageDigest().digest(data);
	}

	public static int getDigestLength() {
		return HashType.SHA256.hashLength;
	}
}
