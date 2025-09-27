package network.crypta.crypt;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

public class HashTest {
  private static final byte[] helloWorld = "hello world".getBytes(StandardCharsets.UTF_8);
  private static final byte[] nullArray = null;
  private static final HashType[] types = {
    HashType.MD5,
    HashType.ED2K,
    HashType.SHA1,
    HashType.TTH,
    HashType.SHA256,
    HashType.SHA384,
    HashType.SHA512
  };
  private static final String[] trueHashes = {
    "5eb63bbbe01eeed093cb22bb8f5acdc3",
    "aa010fbc1d14c795d86ef98c95479d17",
    "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
    "ca1158e471d147bb714a6b1b8a537ff756f7abe1b63dc11d",
    "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
    "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3"
        + "e417cb71ce646efd0819dd8c088de1bd",
    "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f"
        + "989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"
  };
  private static final String[] falseHashes = {
    "aa010fbc1d14c795d86ef98c95479d17",
    "5eb63bbbe01eeed093cb22bb8f5acdc3",
    "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee",
    "2aae6c35c94fcfb415dbe95f408b9ce91ee846edb63dc11d",
    "ca1158e471d147bb714a6b1b8a537ff756f7abe1b63dc11d9088f7ace2efcde9",
    "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9e417cb71ce646efd0819dd8c08"
        + "8de1bd",
    "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c08"
        + "8de1bdd830e81f605dcf7dc5542e93ae9cd76f"
  };

  @Test
  // This also tests addBytes(byte[]...) and getHash()
  public void testGetHashByteArrayArray() {
    for (int i = 0; i < types.length; i++) {
      Hash hash = new Hash(types[i]);
      byte[] abcResult = hash.genHash(helloWorld);
      byte[] expectedABCResult = Hex.decode(trueHashes[i]);
      assertArrayEquals(abcResult, expectedABCResult, "HashType: " + types[i].name());
    }
  }

  @Test
  // This also tests addBytes(byte[]...) and getHash()
  public void testGetHashByteArrayArrayReset() {
    for (int i = 0; i < types.length; i++) {
      Hash hash = new Hash(types[i]);
      byte[] abcResult = hash.genHash(helloWorld);
      byte[] abcResult2 = hash.genHash(helloWorld);
      assertArrayEquals(abcResult, abcResult2, "HashType: " + types[i].name());
    }
  }

  @Test
  // This also tests addBytes(byte[]...) and getHash()
  public void testGetHashByteArrayArraySameAsMessageDigest() {
    for (int i = 0; i < types.length; i++) {
      Hash hash = new Hash(types[i]);
      MessageDigest md = types[i].get();
      byte[] mdResult = md.digest(helloWorld);
      byte[] hashResult = hash.genHash(helloWorld);
      assertArrayEquals(mdResult, hashResult, "HashType: " + types[i].name());
    }
  }

  @Test
  // This also tests addBytes(byte[]...) and getHash()
  public void testGetHashByteArrayArrayNullInput() {
    for (int i = 0; i < types.length; i++) {
      Hash hash = new Hash(types[i]);

      boolean throwNull = false;
      try {
        hash.genHash(nullArray);
      } catch (NullPointerException e) {
        throwNull = true;
      }
      assertTrue(throwNull, "HashType: " + types[i].name());
    }
  }

  @Test
  // This also tests addBytes(byte[]...)
  public void testGetHashByteArrayArrayNullMatrixElementInput() {
    for (int i = 0; i < types.length; i++) {
      Hash hash = new Hash(types[i]);
      boolean throwNulls = false;
      byte[][] nullMatrix = {helloWorld, null};
      try {
        hash.genHash(nullMatrix);
      } catch (NullPointerException e) {
        throwNulls = true;
      }
      assertTrue(throwNulls, "HashType: " + types[i].name());
    }
  }

  @Test
  // tests getHashResult() as well
  public void testGetHashResultHashResultByteArray() {
    for (int i = 0; i < types.length; i++) {
      HashResult hash2 = new HashResult(types[i], Hex.decode(trueHashes[i]));
      Hash hash = new Hash(types[i]);
      HashResult hash1 = hash.genHashResult(helloWorld);
      assertTrue(Hash.verify(hash1, hash2), "HashType: " + types[i].name());
    }
  }

  @Test
  public void testGetHashHex() {
    for (int i = 0; i < types.length; i++) {
      Hash hash = new Hash(types[i]);
      hash.addBytes(helloWorld);
      String hexHash = hash.genHexHash();
      assertEquals(trueHashes[i], hexHash, "HashType: " + types[i].name());
    }
  }

  @Test
  public void testAddByteByte() {
    for (int i = 0; i < types.length; i++) {
      Hash hash = new Hash(types[i]);

      for (int j = 0; j < helloWorld.length; j++) {
        hash.addByte(helloWorld[j]);
      }
      assertArrayEquals(Hex.decode(trueHashes[i]), hash.genHash(), "HashType: " + types[i].name());
    }
  }

  @Test
  @SuppressWarnings("null")
  public void testAddByteByteNullInput() {
    for (int i = 0; i < types.length; i++) {
      Hash hash = new Hash(types[i]);
      boolean throwNull = false;
      Byte nullByte = null;
      try {
        hash.addByte(nullByte);
      } catch (NullPointerException e) {
        throwNull = true;
      }
      assertTrue(throwNull, "HashType: " + types[i].name());
    }
  }

  @Test
  public void testAddBytesByteBuffer() {
    for (int i = 0; i < types.length; i++) {
      ByteBuffer byteBuffer = ByteBuffer.wrap(helloWorld);
      Hash hash = new Hash(types[i]);
      hash.addBytes(byteBuffer);
      assertArrayEquals(Hex.decode(trueHashes[i]), hash.genHash(), "HashType: " + types[i].name());
    }
  }

  @Test
  public void testAddBytesByteBufferNullInput() {
    for (int i = 0; i < types.length; i++) {
      Hash hash = new Hash(types[i]);
      boolean throwNull = false;
      ByteBuffer nullBuffer = null;
      try {
        hash.addBytes(nullBuffer);
      } catch (NullPointerException e) {
        throwNull = true;
      }
      assertTrue(throwNull, "HashType: " + types[i].name());
    }
  }

  @Test
  public void testAddByteByteArrayIntInt() {
    for (int i = 0; i < types.length; i++) {
      Hash hash = new Hash(types[i]);
      hash.addBytes(helloWorld, 0, helloWorld.length / 2);
      hash.addBytes(helloWorld, helloWorld.length / 2, helloWorld.length - helloWorld.length / 2);
      assertArrayEquals(Hex.decode(trueHashes[i]), hash.genHash(), "HashType: " + types[i].name());
    }
  }

  @Test
  public void testAddByteByteArrayIntIntNullInput() {
    for (int i = 0; i < types.length; i++) {
      Hash hash = new Hash(types[i]);
      boolean throwNull = false;
      byte[] nullArray = null;
      try {
        hash.addBytes(nullArray, 0, helloWorld.length);
      } catch (IllegalArgumentException e) {
        throwNull = true;
      }
      assertTrue(throwNull, "HashType: " + types[i].name());
    }
  }

  @Test
  public void testAddByteByteArrayIntIntOffsetOutOfBounds() {
    for (int i = 0; i < types.length; i++) {
      Hash hash = new Hash(types[i]);
      boolean throwOutOfBounds = false;
      try {
        hash.addBytes(helloWorld, -3, helloWorld.length - 3);
      } catch (ArrayIndexOutOfBoundsException e) {
        throwOutOfBounds = true;
      }
      assertTrue(throwOutOfBounds, "HashType: " + types[i].name());
    }
  }

  @Test
  public void testAddByteByteArrayIntIntLengthOutOfBounds() {
    for (int i = 0; i < types.length; i++) {
      Hash hash = new Hash(types[i]);
      boolean throwOutOfBounds = false;
      try {
        hash.addBytes(helloWorld, 0, helloWorld.length + 3);
      } catch (IllegalArgumentException e) {
        throwOutOfBounds = true;
      }
      assertTrue(throwOutOfBounds, "HashType: " + types[i].name());
    }
  }

  @Test
  public void testVerifyByteArrayByteArray() {
    for (int i = 0; i < types.length; i++) {
      Hash hash = new Hash(types[i]);
      assertTrue(
          hash.verify(Hex.decode(trueHashes[i]), helloWorld), "HashType: " + types[i].name());
    }
  }

  @Test
  public void testVerifyByteArrayByteArrayFalse() {
    for (int i = 0; i < types.length; i++) {
      Hash hash = new Hash(types[i]);
      assertFalse(
          hash.verify(Hex.decode(falseHashes[i]), helloWorld), "HashType: " + types[i].name());
    }
  }

  @Test
  public void testVerifyByteArrayByteArrayWrongSizeMac() {
    for (int i = 0; i < types.length; i++) {
      Hash hash = new Hash(types[i]);

      assertFalse(hash.verify(helloWorld, helloWorld), "HashType: " + types[i].name());
    }
  }

  @Test
  public void testVerifyByteArrayByteArrayNullInputPos1() {
    for (int i = 0; i < types.length; i++) {
      Hash hash = new Hash(types[i]);
      boolean throwResult = false;
      boolean valid = true;
      try {
        valid = hash.verify(nullArray, helloWorld);
      } catch (NullPointerException e) {
        throwResult = true;
      }
      assertTrue(throwResult || !valid, "HashType: " + types[i].name());
    }
  }

  @Test
  public void testVerifyByteArrayByteArrayNullInputPos2() {
    for (int i = 0; i < types.length; i++) {
      Hash hash = new Hash(types[i]);
      boolean throwResult = false;
      try {
        hash.verify(helloWorld, nullArray);
      } catch (NullPointerException e) {
        throwResult = true;
      }
      assertTrue(throwResult, "HashType: " + types[i].name());
    }
  }

  @Test
  public void testVerifyHashResultByteArray() {
    for (int i = 0; i < types.length; i++) {
      HashResult hashResult = new HashResult(types[i], Hex.decode(trueHashes[i]));

      assertTrue(Hash.verify(hashResult, helloWorld), "HashType: " + types[i].name());
    }
  }

  @Test
  public void testVerifyHashResultByteArrayFalse() {
    for (int i = 0; i < types.length; i++) {
      HashResult hashResult = new HashResult(types[i], Hex.decode(falseHashes[i]));

      assertFalse(Hash.verify(hashResult, helloWorld), "HashType: " + types[i].name());
    }
  }

  @Test
  public void testVerifyHashResultByteArrayWrongSizeMac() {
    for (int i = 0; i < types.length; i++) {
      byte[] hash1 = helloWorld;
      HashResult hashResult = new HashResult(types[i], hash1, true);

      assertFalse(Hash.verify(hashResult, hash1), "HashType: " + types[i].name());
    }
  }

  @Test
  public void testVerifyHashResultByteArrayNullInputPos1() {
    for (int i = 0; i < types.length; i++) {
      byte[] hashResult = Hex.decode(trueHashes[i]);
      boolean throwResult = false;
      HashResult nullResult = null;
      try {
        Hash.verify(nullResult, hashResult);
      } catch (NullPointerException e) {
        throwResult = true;
      }
      assertTrue(throwResult, "HashType: " + types[i].name());
    }
  }

  @Test
  public void testVerifyHashResultByteArrayNullInputPos2() {
    for (int i = 0; i < types.length; i++) {
      HashResult hash1 = new HashResult(types[i], Hex.decode(trueHashes[i]));
      boolean throwResult = false;
      try {
        Hash.verify(hash1, nullArray);
      } catch (NullPointerException e) {
        throwResult = true;
      }
      assertTrue(throwResult, "HashType: " + types[i].name());
    }
  }

  @Test
  public void testVerifyHashResultHashResult() {
    for (int i = 0; i < types.length; i++) {
      HashResult hash = new HashResult(types[i], Hex.decode(trueHashes[i]));

      assertTrue(Hash.verify(hash, hash), "HashType: " + types[i].name());
    }
  }

  @Test
  public void testVerifyHashResultHashResultFalse() {
    for (int i = 0; i < types.length; i++) {
      HashResult hash1 = new HashResult(types[i], Hex.decode(trueHashes[i]));
      HashResult hash2 = new HashResult(types[i], Hex.decode(falseHashes[i]));

      assertFalse(Hash.verify(hash1, hash2), "HashType: " + types[i].name());
    }
  }

  @Test
  public void testVerifyHashResultHashResultNullInputPos1() {
    for (int i = 0; i < types.length; i++) {
      HashResult hash = new HashResult(types[i], Hex.decode(trueHashes[i]));
      boolean throwResult = false;
      HashResult nullResult = null;
      try {
        Hash.verify(nullResult, hash);
      } catch (NullPointerException e) {
        throwResult = true;
      }
      assertTrue(throwResult, "HashType: " + types[i].name());
    }
  }

  @Test
  public void testVerifyHashResultHashResultNullInputPos2() {
    for (int i = 0; i < types.length; i++) {
      HashResult hash = new HashResult(types[i], Hex.decode(trueHashes[i]));
      HashResult nullResult = null;

      assertFalse(Hash.verify(hash, nullResult), "HashType: " + types[i].name());
    }
  }
}
