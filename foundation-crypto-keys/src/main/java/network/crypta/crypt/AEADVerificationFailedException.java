package network.crypta.crypt;

import java.io.IOException;
import java.io.Serial;

/**
 * Signals that authentication tag verification fails while reading AEAD‑protected data.
 *
 * <p>This exception is thrown by {@link AEADInputStream} when the underlying AEAD cipher reports an
 * authentication failure during finalization (e.g., incorrect key/nonce, corrupted or truncated
 * ciphertext). Catch this type to distinguish verification failures from other I/O errors.
 *
 * @see AEADInputStream
 * @see IOException
 */
public class AEADVerificationFailedException extends IOException {
  /** Stable serial form for this {@link IOException} subclass. */
  @Serial private static final long serialVersionUID = 4850585521631586023L;
}
