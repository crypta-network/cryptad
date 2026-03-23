package network.crypta.crypt;

import network.crypta.support.api.ResumeContext;
import network.crypta.support.io.ResumeFailedException;

/**
 * Internal helpers for resolving crypto-specific resume state.
 *
 * <p>This utility keeps the cast from {@link ResumeContext} to {@link CryptoResumeContext} in one
 * package-local place so encrypted resume callers can fail consistently when they are invoked with
 * a generic support-layer context. That keeps the public resume signatures unchanged while making
 * the crypto dependency explicit at the point where encrypted state is actually reconstructed.
 *
 * <p>The helper is intentionally small. It does not add fallback behavior or alternate secret
 * lookup rules; it only validates that the caller supplied the crypto-aware resume contract needed
 * by encrypted persistent storage.
 */
final class CryptoResumeContexts {

  /** Prevents instantiation of this utility holder. */
  private CryptoResumeContexts() {}

  /**
   * Returns the crypto-aware resume context required by encrypted persistent storage.
   *
   * <p>Encrypted buckets and buffers call this during resume when they need access to the
   * persistent master secret. If the supplied context only implements the generic support-layer
   * contract, resume cannot safely rebuild the encrypted state, so this method fails with a
   * deterministic {@link ResumeFailedException}.
   *
   * @param context generic resume context supplied to an encrypted {@code onResume(...)} path
   * @return the same context, narrowed to {@link CryptoResumeContext} for crypto-specific access
   * @throws ResumeFailedException when the supplied context does not expose crypto resume services
   */
  static CryptoResumeContext require(ResumeContext context) throws ResumeFailedException {
    if (context instanceof CryptoResumeContext cryptoContext) {
      return cryptoContext;
    }
    throw new ResumeFailedException("Encrypted persistent state requires a CryptoResumeContext");
  }
}
