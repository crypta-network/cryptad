package network.crypta.crypt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Security;
import javax.crypto.spec.IvParameterSpec;
import network.crypta.support.Fields;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

public class MessageAuthCodeTest {
  private static final MACType[] types = MACType.values();
  private static final byte[][] keys = {
    Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
    Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
    Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
    Hex.decode("e285000e6080a701a410040f4814470b568d149b821f99d41319e6410094a760")
  };
  private static final byte[] hmacMessage = "Hi There".getBytes(StandardCharsets.UTF_8);
  private static final byte[][] messages = {
    hmacMessage, hmacMessage, hmacMessage, Hex.decode("66f75c0e0c7a406586")
  };
  private static final IvParameterSpec[] IVs = {
    null, null, null, new IvParameterSpec(Hex.decode("166450152e2394835606a9d1dd2cdc8b"))
  };
  private static final byte[][] trueMacs = {
    Hex.decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
    Hex.decode(
        "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7"
            + "f4af152e8b2fa9cb6"),
    Hex.decode(
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a70"
            + "2038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"),
    Hex.decode("1644272eee3b30b7f82568425e817756")
  };
  private static final byte[][] falseMacs = {
    Hex.decode("4bb5e21dd13001ed5faccfcfdaf8a854881dc200c9833da726e9376c2e32cff7"),
    Hex.decode(
        "4bb5e21dd13001ed5faccfcfdaf8a854881dc200c9833da726e9376c2e32cff7faea9ea9076ede7"
            + "f4af152e8b2fa9cb6"),
    Hex.decode(
        "4bb5e21dd13001ed5faccfcfdaf8a854881dc200c9833da726e9376c2e32cff7faea9ea9076ede7"
            + "2038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"),
    Hex.decode("881dc200c9833da726e9376c2e32cff7")
  };

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  public void testAddByte() throws InvalidKeyException, InvalidAlgorithmParameterException {
    for (int i = 0; i < types.length; i++) {
      MessageAuthCode mac;
      if (types[i].ivlen != -1) {
        mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
      } else {
        mac = new MessageAuthCode(types[i], keys[i]);
      }

      for (int j = 0; j < messages[i].length; j++) {
        mac.addByte(messages[i][j]);
      }
      assertArrayEquals(
          Fields.copyToArray(mac.genMac()), trueMacs[i], "MACType: " + types[i].name());
    }
  }

  @Test
  @SuppressWarnings("null")
  public void testAddByteNullInput()
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    for (int i = 0; i < types.length; i++) {
      MessageAuthCode mac;
      if (types[i].ivlen != -1) {
        mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
      } else {
        mac = new MessageAuthCode(types[i], keys[i]);
      }

      boolean throwNull = false;
      Byte nullByte = null;
      try {
        mac.addByte(nullByte);
      } catch (NullPointerException e) {
        throwNull = true;
      }

      assertTrue(throwNull, "MACType: " + types[i].name());
    }
  }

  @Test
  public void testAddBytesByteBuffer()
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    for (int i = 0; i < types.length; i++) {
      MessageAuthCode mac;
      if (types[i].ivlen != -1) {
        mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
      } else {
        mac = new MessageAuthCode(types[i], keys[i]);
      }
      ByteBuffer byteBuffer = ByteBuffer.wrap(messages[i]);

      mac.addBytes(byteBuffer);
      assertArrayEquals(mac.genMac().array(), trueMacs[i], "MACType: " + types[i].name());
    }
  }

  @Test
  public void testAddBytesByteBufferNullInput() throws InvalidKeyException {
    int i = 0;
    MessageAuthCode mac;
    mac = new MessageAuthCode(types[i], keys[i]);

    ByteBuffer byteBuffer = null;
    assertThrows(IllegalArgumentException.class, () -> mac.addBytes(byteBuffer));
  }

  @Test
  public void testAddBytesByteArrayIntInt()
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    for (int i = 0; i < types.length; i++) {
      MessageAuthCode mac;
      if (types[i].ivlen != -1) {
        mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
      } else {
        mac = new MessageAuthCode(types[i], keys[i]);
      }
      mac.addBytes(messages[i], 0, messages[i].length / 2);
      mac.addBytes(
          messages[i], messages[i].length / 2, messages[i].length - messages[i].length / 2);

      assertArrayEquals(mac.genMac().array(), trueMacs[i], "MACType: " + types[i].name());
    }
  }

  @Test
  public void testAddBytesByteArrayIntIntNullInput()
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    for (int i = 0; i < types.length; i++) {
      MessageAuthCode mac;
      if (types[i].ivlen != -1) {
        mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
      } else {
        mac = new MessageAuthCode(types[i], keys[i]);
      }

      boolean throwNull = false;
      byte[] nullArray = null;
      try {
        mac.addBytes(nullArray, 0, messages[i].length);
      } catch (NullPointerException e) {
        throwNull = true;
      }

      assertTrue(throwNull, "MACType: " + types[i].name());
    }
  }

  @Test
  public void testAddBytesByteArrayIntIntOffsetOutOfBounds()
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    for (int i = 0; i < types.length; i++) {
      MessageAuthCode mac;
      if (types[i].ivlen != -1) {
        mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
      } else {
        mac = new MessageAuthCode(types[i], keys[i]);
      }

      boolean throwNull = false;
      try {
        mac.addBytes(messages[i], -3, messages[i].length - 3);
      } catch (IllegalArgumentException e) {
        throwNull = true;
      }

      assertTrue(throwNull, "MACType: " + types[i].name());
    }
  }

  @Test
  public void testAddBytesByteArrayIntIntLengthOutOfBounds()
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    for (int i = 0; i < types.length; i++) {
      MessageAuthCode mac;
      if (types[i].ivlen != -1) {
        mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
      } else {
        mac = new MessageAuthCode(types[i], keys[i]);
      }

      boolean throwNull = false;
      try {
        mac.addBytes(messages[i], 0, messages[i].length + 3);
      } catch (IllegalArgumentException e) {
        throwNull = true;
      }

      assertTrue(throwNull, "MACType: " + types[i].name());
    }
  }

  @Test
  // tests .genMac() and .addBytes(byte[]...] as well
  public void testGetMacByteArrayArray()
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    for (int i = 0; i < types.length; i++) {
      MessageAuthCode mac;
      if (types[i].ivlen != -1) {
        mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
      } else {
        mac = new MessageAuthCode(types[i], keys[i]);
      }
      byte[] result = mac.genMac(messages[i]).array();
      assertTrue(MessageAuthCode.verify(result, trueMacs[i]), "MACType: " + types[i].name());
    }
  }

  @Test
  public void testGetMacByteArrayArrayReset()
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    for (int i = 0; i < types.length; i++) {
      MessageAuthCode mac;
      if (types[i].ivlen != -1) {
        mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
      } else {
        mac = new MessageAuthCode(types[i], keys[i]);
      }
      mac.addBytes(messages[i]);
      byte[] result = mac.genMac(messages[i]).array();
      assertArrayEquals(result, trueMacs[i], "MACType: " + types[i].name());
    }
  }

  @Test
  public void testGetMacByteArrayArrayNullInput()
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    for (int i = 0; i < types.length; i++) {
      MessageAuthCode mac;
      if (types[i].ivlen != -1) {
        mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
      } else {
        mac = new MessageAuthCode(types[i], keys[i]);
      }

      boolean throwNull = false;
      byte[] nullArray = null;
      try {
        mac.genMac(nullArray);
      } catch (NullPointerException e) {
        throwNull = true;
      }

      assertTrue(throwNull, "MACType: " + types[i].name());
    }
  }

  @Test
  public void testGetMacByteArrayArrayNullMatrixElementInput()
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    MessageAuthCode mac = new MessageAuthCode(types[3], keys[3], IVs[3]);
    byte[][] nullMatrix = {messages[3], null};
    assertThrows(NullPointerException.class, () -> mac.genMac(nullMatrix));
  }

  @Test
  public void testVerify() {
    assertTrue(MessageAuthCode.verify(trueMacs[3], trueMacs[3]));
  }

  @Test
  public void testVerifyFalse() {
    assertFalse(MessageAuthCode.verify(trueMacs[3], falseMacs[3]));
  }

  @Test
  public void testVerifyNullInput1() {
    byte[] nullArray = null;
    assertFalse(MessageAuthCode.verify(nullArray, trueMacs[3]));
  }

  @Test
  public void testVerifyNullInput2() {
    byte[] nullArray = null;
    assertFalse(MessageAuthCode.verify(trueMacs[1], nullArray));
  }

  @Test
  public void testVerifyData() throws InvalidKeyException, InvalidAlgorithmParameterException {
    for (int i = 0; i < types.length; i++) {
      System.out.println(types[i].name());
      MessageAuthCode mac;
      if (types[i].ivlen != -1) {
        mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
      } else {
        mac = new MessageAuthCode(types[i], keys[i]);
      }
      assertTrue(mac.verifyData(trueMacs[i], messages[i]), "MACType: " + types[i].name());
    }
  }

  @Test
  public void testVerifyDataFalse() throws InvalidKeyException, InvalidAlgorithmParameterException {
    for (int i = 0; i < types.length; i++) {
      MessageAuthCode mac;
      if (types[i].ivlen != -1) {
        mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
      } else {
        mac = new MessageAuthCode(types[i], keys[i]);
      }
      assertFalse(mac.verifyData(falseMacs[i], messages[i]), "MACType: " + types[i].name());
    }
  }

  @Test
  public void testVerifyDataNullInput1()
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    for (int i = 0; i < types.length; i++) {
      MessageAuthCode mac;
      if (types[i].ivlen != -1) {
        mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
      } else {
        mac = new MessageAuthCode(types[i], keys[i]);
      }
      byte[] nullArray = null;
      assertFalse(mac.verifyData(nullArray, messages[i]), "MACType: " + types[i].name());
    }
  }

  @Test
  public void testVerifyDataNullInput2()
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    for (int i = 0; i < types.length; i++) {
      MessageAuthCode mac;
      if (types[i].ivlen != -1) {
        mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
      } else {
        mac = new MessageAuthCode(types[i], keys[i]);
      }
      boolean throwNull = false;
      byte[] nullArray = null;
      try {
        mac.verifyData(trueMacs[i], nullArray);
      } catch (NullPointerException e) {
        throwNull = true;
      }
      assertTrue(throwNull, "MACType: " + types[i].name());
    }
  }

  @Test
  public void testGetKey() throws InvalidKeyException, InvalidAlgorithmParameterException {
    for (int i = 0; i < types.length; i++) {
      MessageAuthCode mac;
      if (types[i].ivlen != -1) {
        mac = new MessageAuthCode(types[i], keys[i], IVs[i]);
      } else {
        mac = new MessageAuthCode(types[i], keys[i]);
      }
      assertArrayEquals(mac.getKey().getEncoded(), keys[i], "MACType: " + types[i].name());
    }
  }

  @Test
  public void testGetIV() throws InvalidKeyException, InvalidAlgorithmParameterException {
    MessageAuthCode mac = new MessageAuthCode(types[3], keys[3], IVs[3]);
    assertArrayEquals(mac.getIv().getIV(), IVs[3].getIV());
  }

  @Test
  public void testGetIVUnsupportedTypeException() throws InvalidKeyException {
    MessageAuthCode mac = new MessageAuthCode(types[0], keys[0]);
    assertThrows(UnsupportedTypeException.class, mac::getIv);
  }

  @Test
  public void testSetIVIvParameterSpec()
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    MessageAuthCode mac = new MessageAuthCode(types[3], keys[3], IVs[3]);
    mac.genIV();
    mac.setIV(IVs[3]);
    assertArrayEquals(IVs[3].getIV(), mac.getIv().getIV());
  }

  @Test
  public void testSetIVIvParameterSpecNullInput()
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    IvParameterSpec nullInput = null;
    MessageAuthCode mac = new MessageAuthCode(types[3], keys[3], IVs[3]);
    assertThrows(InvalidAlgorithmParameterException.class, () -> mac.setIV(nullInput));
  }

  @Test
  public void testSetIVIvParameterSpecUnsupportedTypeException()
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    MessageAuthCode mac = new MessageAuthCode(types[0], keys[0]);
    assertThrows(UnsupportedTypeException.class, () -> mac.setIV(IVs[1]));
  }

  @Test
  public void testGenIV() throws InvalidKeyException, InvalidAlgorithmParameterException {
    MessageAuthCode mac = new MessageAuthCode(types[3], keys[3], IVs[3]);
    assertNotNull(mac.genIV());
  }

  @Test
  public void testGenIVLength() throws InvalidKeyException, InvalidAlgorithmParameterException {
    MessageAuthCode mac = new MessageAuthCode(types[3], keys[3], IVs[3]);
    assertEquals(mac.genIV().getIV().length, types[3].ivlen);
  }

  @Test
  public void testGenIVUnsupportedTypeException() throws InvalidKeyException {
    MessageAuthCode mac = new MessageAuthCode(types[0], keys[0]);
    assertThrows(UnsupportedTypeException.class, mac::genIV);
  }
}
