package network.crypta.client.filter;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

@SuppressWarnings("java:S100")
class JPEGFilterTest {

  private static final byte[] SOI = {(byte) 0xFF, (byte) 0xD8};
  private static final byte[] EOI = {(byte) 0xFF, (byte) 0xD9};

  @ParameterizedTest
  @ValueSource(bytes = {0x10, 0x11, 0x13})
  void readFilter_whenJfxxThumbnailExtensionAllowed_preservesSegment(byte extensionCode)
      throws IOException {
    JPEGFilter filter = new JPEGFilter(true, true);
    byte[] jpegWithThumbnail = buildJpeg(jfifSegment(), jfxxSegment(extensionCode));

    byte[] filtered = runFilter(filter, jpegWithThumbnail);

    assertArrayEquals(jpegWithThumbnail, filtered);
  }

  @ParameterizedTest
  @CsvSource({"true, first note", "false, second note"})
  void readFilter_whenDeleteCommentsFlagSet_controlsCommentPresence(
      boolean deleteComments, String commentText) throws IOException {
    JPEGFilter filter = new JPEGFilter(deleteComments, true);
    byte[] commentFrame = commentSegment(commentText);
    byte[] input = buildJpeg(jfifSegment(), commentFrame);
    byte[] expected = deleteComments ? buildJpeg(jfifSegment()) : input;

    byte[] filtered = runFilter(filter, input);

    assertArrayEquals(expected, filtered);
  }

  @Test
  void readFilter_whenDeleteExifEnabled_dropsExifFrame() throws IOException {
    JPEGFilter filter = new JPEGFilter(false, true);
    byte[] exifFrame = exifSegment();
    byte[] input = buildJpeg(jfifSegment(), exifFrame);
    byte[] expected = buildJpeg(jfifSegment());

    byte[] filtered = runFilter(filter, input);

    assertArrayEquals(expected, filtered);
  }

  @Test
  void readFilter_whenDeleteExifDisabled_preservesExifFrame() throws IOException {
    JPEGFilter filter = new JPEGFilter(false, false);
    byte[] exifFrame = exifSegment();
    byte[] input = buildJpeg(jfifSegment(), exifFrame);

    byte[] filtered = runFilter(filter, input);

    assertArrayEquals(input, filtered);
  }

  @Test
  void readFilter_whenSoiHeaderMissing_throwsDataFilterException() {
    JPEGFilter filter = new JPEGFilter(true, true);
    byte[] invalid = new byte[] {0x00, 0x01, 0x02};

    assertThrows(
        DataFilterException.class,
        () ->
            filter.readFilter(
                new ByteArrayInputStream(invalid),
                new ByteArrayOutputStream(),
                StandardCharsets.UTF_8.name(),
                Map.of(),
                null,
                null));
  }

  @Test
  void readFilter_whenMarkerStartNot0xff_throwsDataFilterException() {
    JPEGFilter filter = new JPEGFilter(true, true);
    byte[] invalid = new byte[] {(byte) 0xFF, (byte) 0xD8, 0x00, (byte) 0xFF, (byte) 0xD9};

    assertThrows(
        DataFilterException.class,
        () ->
            filter.readFilter(
                new ByteArrayInputStream(invalid),
                new ByteArrayOutputStream(),
                StandardCharsets.UTF_8.name(),
                Map.of(),
                null,
                null));
  }

  @Test
  void readFilter_whenScanTerminates_emitsMarkerOnce() throws IOException {
    JPEGFilter filter = new JPEGFilter(true, true);
    byte[] scanHeader = new byte[] {0x01, 0x01, 0x00, 0x00, 0x3F, 0x00};
    byte[] scanData = new byte[] {0x11, 0x22, (byte) 0xFF, 0x00, 0x33};
    byte[] input = buildJpeg(jfifSegment(), scanSegment(scanHeader, scanData));

    byte[] filtered = runFilter(filter, input);

    assertArrayEquals(input, filtered);
  }

  private static byte[] runFilter(JPEGFilter filter, byte[] input) throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    filter.readFilter(
        new ByteArrayInputStream(input),
        output,
        StandardCharsets.UTF_8.name(),
        Map.of(),
        null,
        null);
    return output.toByteArray();
  }

  private static byte[] buildJpeg(byte[]... segments) {
    ByteArrayOutputStream image = new ByteArrayOutputStream();
    image.writeBytes(SOI);
    for (byte[] segment : segments) {
      image.writeBytes(segment);
    }
    image.writeBytes(EOI);
    return image.toByteArray();
  }

  private static byte[] jfifSegment() {
    byte[] payload =
        new byte[] {
          0x4A,
          0x46,
          0x49,
          0x46,
          0x00, // "JFIF\0"
          0x01, // major version
          0x01, // minor version
          0x00, // units
          0x00,
          0x48, // X density 72
          0x00,
          0x48, // Y density 72
          0x00, // thumbnail width
          0x00 // thumbnail height
        };
    return markerWithPayload(0xE0, payload);
  }

  private static byte[] jfxxSegment(byte extensionCode) {
    byte[] payload =
        new byte[] {
          0x4A,
          0x46,
          0x58,
          0x58,
          0x00, // "JFXX\0"
          extensionCode,
          0x01,
          0x01,
          0x00,
          0x7F,
          0x00
        };
    return markerWithPayload(0xE0, payload);
  }

  private static byte[] exifSegment() {
    byte[] payload = new byte[] {0x45, 0x78, 0x69, 0x66, 0x00, 0x00, 0x01, 0x02};
    return markerWithPayload(0xE1, payload);
  }

  private static byte[] commentSegment(String text) {
    return markerWithPayload(0xFE, text.getBytes(StandardCharsets.ISO_8859_1));
  }

  private static byte[] scanSegment(byte[] scanHeader, byte[] scanData) {
    ByteArrayOutputStream segment = new ByteArrayOutputStream();
    segment.write((byte) 0xFF);
    segment.write((byte) 0xDA);
    int blockLength = scanHeader.length + 2;
    segment.write((blockLength >> 8) & 0xFF);
    segment.write(blockLength & 0xFF);
    segment.writeBytes(scanHeader);
    segment.writeBytes(scanData);
    return segment.toByteArray();
  }

  private static byte[] markerWithPayload(int markerType, byte[] payload) {
    ByteArrayOutputStream segment = new ByteArrayOutputStream();
    segment.write((byte) 0xFF);
    segment.write((byte) markerType);
    int blockLength = payload.length + 2;
    segment.write((blockLength >> 8) & 0xFF);
    segment.write(blockLength & 0xFF);
    segment.writeBytes(payload);
    return segment.toByteArray();
  }
}
