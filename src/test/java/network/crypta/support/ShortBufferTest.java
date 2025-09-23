package network.crypta.support;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

/**
 * Test case for {@link ShortBuffer} class.
 *
 * @author stuart martin &lt;wavey@freenetproject.org&gt;
 * @author Daniel Cheng &lt;sdiz@freenetproject.org&gt;
 */
public class ShortBufferTest {

  private static final String DATA_STRING_1 =
      "asldkjaskjdsakdhasdhaskjdhaskjhbkasbhdjkasbduiwbxgdoudgboewuydxbybuewyxbuewyuwe"
          + "dasdkljasndijwnodhnqweoidhnaouidhbnwoduihwnxodiuhnwuioxdhnwqiouhnxwqoiushdnxwqoiudhxnwqoiudhxni";

  @Test
  public void testByteArrayShortBuffer() {

    byte[] data = DATA_STRING_1.getBytes();

    ShortBuffer buffer = new ShortBuffer(data);

    assertEquals(data, buffer.getData());

    doTestShortBuffer(data, buffer);
  }

  @Test
  public void testByteArrayIndexShortBuffer() {

    // get content
    byte[] data = DATA_STRING_1.getBytes();

    byte[] dataSub = new byte[5];

    // prepare 'substring'
    System.arraycopy(data, 4, dataSub, 0, 5);

    ShortBuffer buffer = new ShortBuffer(data, 4, 5);

    assertNotEquals(dataSub, buffer.getData());

    doTestShortBuffer(dataSub, buffer);
  }

  @Test
  public void testBadLength() {
    try {
      new ShortBuffer(new byte[0], 0, -1);
      fail();
    } catch (IllegalArgumentException e) {
      // expect this
    }
    try {
      new ShortBuffer(new byte[0], 0, 1);
      fail();
    } catch (IllegalArgumentException e) {
      // expect this
    }
    try {
      new ShortBuffer(new byte[0], 1, 0);
      fail();
    } catch (IllegalArgumentException e) {
      // expect this
    }
    try {
      new ShortBuffer(new byte[32768], 0, 32768);
      fail();
    } catch (IllegalArgumentException e) {
      // expect this
    }
    new Buffer(new byte[1], 1, 0);
    new Buffer(new byte[1], 0, 1);
  }

  @Test
  public void testDataInputStreamShortBuffer() {

    byte[] data = DATA_STRING_1.getBytes(); // get some content

    byte[] data2 = new byte[data.length + 2]; // make room for 4 byte length indicator

    int length = DATA_STRING_1.getBytes().length;

    // populate length as first 4 bytes
    data2[0] = (byte) ((length & 0xff00) >> 8);
    data2[1] = (byte) ((length & 0xff));

    System.arraycopy(data, 0, data2, 2, data.length); // populate rest of content

    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data2));
    ShortBuffer buffer = null;

    try {
      buffer = new ShortBuffer(dis);
    } catch (IOException e) {
      fail("unexpected exception: " + e.getMessage());
    }
    // perform rest of test with the *original* array because ShortBuffer(DataInputStream) chomps
    // first 4 bytes
    doTestShortBuffer(data, buffer);
  }

  private void doTestShortBuffer(byte[] data, ShortBuffer buffer) {
    assertEquals(data.length, buffer.getLength());

    for (int i = 0; i < buffer.getLength(); i++) {
      assertEquals(data[i], buffer.byteAt(i));
    }

    try {
      buffer.byteAt(data.length + 1); // expect exception
      fail();
    } catch (ArrayIndexOutOfBoundsException e) {
      // expect this
    }
  }

  @Test
  public void testShortBufferToString() {
    String shortString = "feep";
    ShortBuffer shortShortBuffer = new ShortBuffer(shortString.getBytes());

    String outString = shortShortBuffer.toString();
    assertEquals(outString, "{4:102 101 101 112 "); // FIXME: final brace?
  }

  @Test
  public void testEquals() {
    ShortBuffer b1 = new ShortBuffer("ShortBuffer1".getBytes());
    ShortBuffer b2 = new ShortBuffer("ShortBuffer2".getBytes());
    ShortBuffer b3 = new ShortBuffer("ShortBuffer1".getBytes());

    assertNotEquals(b1, b2);
    assertEquals(b1, b3);
    assertNotEquals(b2, b3);
    assertEquals(b1, b1);
    assertEquals(b2, b2);
    assertEquals(b3, b1);
  }

  @Test
  public void testHashcode() {

    ShortBuffer b1 = new ShortBuffer("ShortBuffer1".getBytes());
    ShortBuffer b2 = new ShortBuffer("ShortBuffer2".getBytes());
    ShortBuffer b3 = new ShortBuffer("ShortBuffer1".getBytes());

    Map<ShortBuffer, ShortBuffer> hashMap = new HashMap<>();

    hashMap.put(b1, b1);
    hashMap.put(b2, b2);
    hashMap.put(b3, b3); // should clobber b1 due to content

    // see if b3 survived
    Object o = hashMap.get(b3);
    assertNotSame(o, b1);
    assertSame(o, b3);

    // see if b1 survived
    o = hashMap.get(b1);
    assertNotSame(o, b1);
    assertSame(o, b3);
  }

  @Test
  public void testCopy() {
    byte[] oldBuf = DATA_STRING_1.getBytes();
    ShortBuffer b = new ShortBuffer(oldBuf);

    byte[] newBuf = new byte[b.getLength()];
    b.copyTo(newBuf, 0);

    for (int i = 0; i < oldBuf.length; i++) {
      assertEquals(newBuf[i], oldBuf[i]);
    }
  }
}
