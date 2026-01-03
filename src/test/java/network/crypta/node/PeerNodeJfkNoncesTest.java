package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import network.crypta.crypt.SHA256;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PeerNodeJfkNoncesTest {

  @Test
  void rememberNonce_whenMaxNoncesZero_expectEvictsImmediately() {
    // Arrange
    PeerNodeJfkNonces nonces = new PeerNodeJfkNonces();
    byte[] nonce = new byte[] {1, 2, 3};
    byte[] nonceHash = SHA256.digest(nonce);

    // Act
    nonces.rememberNonce(nonce, 0);
    byte[] found = nonces.findOriginalNonceByHash(nonceHash);

    // Assert
    assertArrayEquals(new byte[0], found);
  }

  @Test
  void findOriginalNonceByHash_whenPresent_expectSameReference() {
    // Arrange
    PeerNodeJfkNonces nonces = new PeerNodeJfkNonces();
    byte[] nonce = new byte[] {9, 8, 7, 6};
    byte[] nonceHash = SHA256.digest(nonce);
    nonces.rememberNonce(nonce, 10);

    // Act
    byte[] found = nonces.findOriginalNonceByHash(nonceHash);

    // Assert
    assertSame(nonce, found);
    assertArrayEquals(nonce, found);
  }

  @Test
  void findOriginalNonceByHash_whenEvicted_expectNull() {
    // Arrange
    PeerNodeJfkNonces nonces = new PeerNodeJfkNonces();
    byte[] first = new byte[] {1, 1, 1};
    byte[] second = new byte[] {2, 2, 2};
    byte[] firstHash = SHA256.digest(first);
    byte[] secondHash = SHA256.digest(second);

    // Act
    nonces.rememberNonce(first, 1);
    nonces.rememberNonce(second, 1);
    byte[] foundFirst = nonces.findOriginalNonceByHash(firstHash);
    byte[] foundSecond = nonces.findOriginalNonceByHash(secondHash);

    // Assert
    assertArrayEquals(new byte[0], foundFirst);
    assertSame(second, foundSecond);
  }

  @Test
  void findOriginalNonceByHash_whenMissing_expectNull() {
    // Arrange
    PeerNodeJfkNonces nonces = new PeerNodeJfkNonces();
    byte[] nonce = new byte[] {3, 4, 5};
    byte[] nonceHash = SHA256.digest(nonce);

    // Act
    byte[] found = nonces.findOriginalNonceByHash(nonceHash);

    // Assert
    assertArrayEquals(new byte[0], found);
  }

  @Test
  void clear_whenNoncesPresent_expectEmptyLookup() {
    // Arrange
    PeerNodeJfkNonces nonces = new PeerNodeJfkNonces();
    byte[] nonce = new byte[] {7, 7, 7, 7};
    byte[] nonceHash = SHA256.digest(nonce);
    nonces.rememberNonce(nonce, 10);

    // Act
    nonces.clear();
    byte[] found = nonces.findOriginalNonceByHash(nonceHash);

    // Assert
    assertArrayEquals(new byte[0], found);
  }
}
