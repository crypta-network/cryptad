package network.crypta.crypt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.SecureRandom;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class BlockCiphersTest {
  private final BlockCipher selected = BlockCiphers.aes();

  @BeforeEach
  public void skipIfJceNotSupported() {
    Assumptions.assumeTrue(selected instanceof BlockCiphers.JceEcbBlockCipher);
  }

  @Test
  public void isCompatibleWithBouncyCastle() {
    BlockCipher bouncyCastle = AESEngine.newInstance();

    SecureRandom random = new SecureRandom();
    assertEquals(bouncyCastle.getBlockSize(), selected.getBlockSize());
    assertEquals(bouncyCastle.getAlgorithmName(), selected.getAlgorithmName());

    KeyParameter key = new KeyParameter(random.generateSeed(16));
    bouncyCastle.init(true, key);
    selected.init(true, key);

    byte[] block = random.generateSeed(24);
    byte[] expectedOut = new byte[block.length];
    byte[] actualOut = new byte[block.length];
    assertEquals(
        bouncyCastle.processBlock(block, 0, expectedOut, 0),
        selected.processBlock(block, 0, actualOut, 0));
    assertArrayEquals(expectedOut, actualOut);
  }
}
