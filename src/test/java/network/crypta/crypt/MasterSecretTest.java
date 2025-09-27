package network.crypta.crypt;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

public class MasterSecretTest {
  private static final KeyType[] types = KeyType.values();

  @Test
  public void testDeriveKey() {
    MasterSecret secret = new MasterSecret();
    for (KeyType type : types) {
      assertNotNull(secret.deriveKey(type));
    }
  }

  @Test
  public void testDeriveKeyLength() {
    MasterSecret secret = new MasterSecret();
    for (KeyType type : types) {
      assertEquals(secret.deriveKey(type).getEncoded().length, type.keySize >> 3);
    }
  }

  @Test
  public void testDeriveKeyNullInput() {
    MasterSecret secret = new MasterSecret();
    assertThrows(NullPointerException.class, () -> secret.deriveKey(null));
  }

  @Test
  public void testDeriveIv() {
    MasterSecret secret = new MasterSecret();
    for (KeyType type : types) {
      assertNotNull(secret.deriveIv(type));
    }
  }

  @Test
  public void testDeriveIvLength() {
    MasterSecret secret = new MasterSecret();
    for (KeyType type : types) {
      assertEquals(secret.deriveIv(type).getIV().length, type.ivSize >> 3);
    }
  }

  @Test
  public void testDeriveIvNullInput() {
    MasterSecret secret = new MasterSecret();
    assertThrows(NullPointerException.class, () -> secret.deriveIv(null));
  }
}
