package network.crypta.platform.appdist;

import java.io.Serial;
import java.security.PublicKey;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class PublicKeyFingerprintTest {
  private static final String EXPECTED_FINGERPRINT =
      "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81";

  @Test
  void sha256_whenKeyHasCanonicalEncoding_expectLowercaseFingerprint() {
    PublicKey publicKey = new EncodedPublicKey(new byte[] {1, 2, 3});

    String fingerprint = PublicKeyFingerprint.sha256(publicKey);

    assertEquals(EXPECTED_FINGERPRINT, fingerprint);
  }

  @Test
  void sha256_whenKeyIsNull_expectNullPointerException() {
    assertThrows(NullPointerException.class, () -> PublicKeyFingerprint.sha256(null));
  }

  @Test
  void sha256_whenCanonicalEncodingIsMissing_expectIllegalArgumentException() {
    PublicKey missingEncoding = new EncodedPublicKey(null);
    PublicKey emptyEncoding = new EncodedPublicKey(new byte[0]);

    assertThrows(
        IllegalArgumentException.class, () -> PublicKeyFingerprint.sha256(missingEncoding));
    assertThrows(IllegalArgumentException.class, () -> PublicKeyFingerprint.sha256(emptyEncoding));
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class EncodedPublicKey implements PublicKey {
    @Serial private static final long serialVersionUID = 1L;

    private final byte[] encoded;

    private EncodedPublicKey(byte[] encoded) {
      this.encoded = encoded;
    }

    @Override
    public String getAlgorithm() {
      return "test";
    }

    @Override
    public String getFormat() {
      return "test";
    }

    @Override
    public byte[] getEncoded() {
      return encoded;
    }
  }
}
