package network.crypta.client.filter;

import static network.crypta.client.filter.ResourceFileUtil.resourceToBucket;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.BucketTools;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@SuppressWarnings("java:S100") // descriptive test method names
class BMPFilterTest {
  /**
   * Invalid BMP inputs that must be rejected by the filter.
   *
   * <p>Files include: small, one, two, three, four, five, six, seven, eight, nine, ten
   */
  @ParameterizedTest
  @ValueSource(
      strings = {
        "./bmp/small.bmp",
        "./bmp/one.bmp",
        "./bmp/two.bmp",
        "./bmp/three.bmp",
        "./bmp/four.bmp",
        "./bmp/five.bmp",
        "./bmp/six.bmp",
        "./bmp/seven.bmp",
        "./bmp/eight.bmp",
        "./bmp/nine.bmp",
        "./bmp/ten.bmp"
      })
  void readFilter_whenVariousInvalidHeaders_expectDataFilterException(String resource)
      throws IOException {
    // Arrange
    Bucket input = resourceToBucket(resource);

    // Act + Assert
    filterImage(input, DataFilterException.class);
  }

  /** Valid BMP inputs that should pass through unchanged (including padding cases). */
  @ParameterizedTest
  @ValueSource(
      strings = {
        "./bmp/ok.bmp",
        "./bmp/sizeCalculationWithPadding.bmp",
        "./bmp/sizeCalculationWithoutPadding.bmp"
      })
  void readFilter_whenValidImages_expectPassThrough(String resource) throws IOException {
    // Arrange
    Bucket input = resourceToBucket(resource);

    // Act
    Bucket output = filterImage(input, null);

    // Assert
    assertEquals(input.size(), output.size(), "Input and output should be the same length");
    assertArrayEquals(
        BucketTools.toByteArray(input),
        BucketTools.toByteArray(output),
        "Input and output are not identical");
  }

  private Bucket filterImage(Bucket input, Class<? extends Exception> expected) throws IOException {
    BMPFilter objBMPFilter = new BMPFilter();
    Bucket output = new ArrayBucket();
    try (InputStream inStream = input.getInputStream();
        OutputStream outStream = output.getOutputStream()) {
      if (expected != null) {
        assertThrows(expected, () -> readFilter(objBMPFilter, inStream, outStream));
      } else {
        readFilter(objBMPFilter, inStream, outStream);
      }
    }
    return output;
  }

  private static void readFilter(
      BMPFilter objBMPFilter, InputStream inStream, OutputStream outStream) throws IOException {
    objBMPFilter.readFilter(inStream, outStream, "", null, null, null);
  }

  @Test
  void readInt_whenLittleEndian_expectCorrectValue() throws IOException {
    // Arrange
    BMPFilter filter = new BMPFilter();
    byte[] bytes = new byte[] {0x01, 0x02, 0x03, 0x04}; // little-endian => 0x04030201
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bytes))) {
      // Act
      int value = filter.readInt(dis);

      // Assert
      assertEquals(0x04030201, value);
    }
  }

  @Test
  void readInt_whenEOF_expectEOFException() {
    // Arrange
    BMPFilter filter = new BMPFilter();
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(new byte[0]))) {
      // Act + Assert
      assertThrows(EOFException.class, () -> filter.readInt(dis));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  void readShort_whenLittleEndian_expectCorrectValue() throws IOException {
    // Arrange
    BMPFilter filter = new BMPFilter();
    byte[] bytes = new byte[] {0x34, 0x12}; // little-endian => 0x1234
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bytes))) {
      // Act
      int value = filter.readShort(dis);

      // Assert
      assertEquals(0x1234, value);
    }
  }

  @Test
  void readShort_whenEOFOnFirstOrSecondByte_expectEOFException() {
    // Arrange
    BMPFilter filter = new BMPFilter();

    // First byte missing
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(new byte[0]))) {
      assertThrows(EOFException.class, () -> filter.readShort(dis));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }

    // Second byte missing
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(new byte[] {0x01}))) {
      assertThrows(EOFException.class, () -> filter.readShort(dis));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
}
