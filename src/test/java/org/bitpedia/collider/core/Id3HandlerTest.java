package org.bitpedia.collider.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings("java:S100")
class Id3HandlerTest {

  @TempDir Path tempDir;

  @Test
  void readId3Tags_whenFileHasV23Frames_populatesAllKnownFields() throws IOException {
    Path file = createV23File(tempDir);

    Id3Handler.Id3Info info = Id3Handler.readId3Tags(file.toString());

    assertEquals("Title V23", info.title);
    assertEquals("Album V23", info.album);
    assertEquals("Artist V23", info.artist);
    assertEquals("2024", info.year);
    assertEquals("8", info.genre); // Jazz is index 8 in the static genre list
    assertEquals("7", info.trackNumber);
    assertEquals("JUnit Encoder", info.encoder);
  }

  @Test
  void readId3Tags_whenFileHasV22Frames_populatesFieldsFromV22() throws IOException {
    Path file = createV22File(tempDir);

    Id3Handler.Id3Info info = Id3Handler.readId3Tags(file.toString());

    assertEquals("Title V22", info.title);
    assertEquals("Album V22", info.album);
    assertEquals("Artist V22", info.artist);
    assertEquals("1999", info.year);
    assertEquals("CustomGenre", info.genre);
    assertEquals("12", info.trackNumber);
    assertEquals("EncoderV22", info.encoder);
  }

  @Test
  void readId3Tags_whenV2Unsupported_usesId3v1Fallback() throws IOException {
    Path file = createUnsupportedV2WithV1Tag(tempDir);

    Id3Handler.Id3Info info = Id3Handler.readId3Tags(file.toString());

    assertEquals("V1 Title", info.title);
    assertEquals("V1 Artist", info.artist);
    assertEquals("V1 Album", info.album);
    assertEquals("2010", info.year);
    assertEquals("5", info.trackNumber);
    assertEquals("13", info.genre);
  }

  @Test
  void readId3Tags_whenNoTagsPresent_returnsNull() throws IOException {
    Path file = Files.write(tempDir.resolve("plain.bin"), new byte[] {0x01, 0x02, 0x03});

    Id3Handler.Id3Info info = Id3Handler.readId3Tags(file.toString());

    assertNull(info);
  }

  private static Path createV23File(Path dir) throws IOException {
    ByteArrayOutputStream frames = new ByteArrayOutputStream();
    writeV23Frame(frames, "TIT2", "Title V23");
    writeV23Frame(frames, "TALB", "Album V23");
    writeV23Frame(frames, "TPE1", "Artist V23");
    writeV23Frame(frames, "TYER", "2024");
    writeV23Frame(frames, "TCON", "Jazz");
    writeV23Frame(frames, "TRCK", "7");
    writeV23Frame(frames, "TSSE", "JUnit Encoder");

    int tagBodySize = frames.size(); // includes frame headers and bodies

    ByteArrayOutputStream file = new ByteArrayOutputStream();
    DataOutputStream header = new DataOutputStream(file);
    header.write("ID3".getBytes(StandardCharsets.ISO_8859_1));
    header.writeByte(3); // version major
    header.writeByte(0); // version revision
    header.writeByte(0); // flags
    header.write(toSynchsafe(tagBodySize));
    file.write(frames.toByteArray());

    Path path = dir.resolve("id3v23.mp3");
    Files.write(path, file.toByteArray());
    return path;
  }

  private static Path createV22File(Path dir) throws IOException {
    ByteArrayOutputStream frames = new ByteArrayOutputStream();
    writeV22Frame(frames, "TT2", "Title V22");
    writeV22Frame(frames, "TAL", "Album V22");
    writeV22Frame(frames, "TP1", "Artist V22");
    writeV22Frame(frames, "TYE", "1999");
    writeV22Frame(frames, "TSI", "CustomGenre");
    writeV22Frame(frames, "TRK", "12");
    writeV22Frame(frames, "TSS", "EncoderV22");

    int tagBodySize = frames.size();

    ByteArrayOutputStream file = new ByteArrayOutputStream();
    DataOutputStream header = new DataOutputStream(file);
    header.write("ID3".getBytes(StandardCharsets.ISO_8859_1));
    header.writeByte(2); // version major
    header.writeByte(0); // version revision
    header.writeByte(0); // flags
    header.write(toSynchsafe(tagBodySize));
    file.write(frames.toByteArray());

    Path path = dir.resolve("id3v22.mp3");
    Files.write(path, file.toByteArray());
    return path;
  }

  private static Path createUnsupportedV2WithV1Tag(Path dir) throws IOException {
    ByteArrayOutputStream file = new ByteArrayOutputStream();
    DataOutputStream header = new DataOutputStream(file);
    header.write("ID3".getBytes(StandardCharsets.ISO_8859_1));
    header.writeByte(4); // unsupported version major
    header.writeByte(0);
    header.writeByte(0);
    header.write(new byte[] {0, 0, 0, 0}); // zero size

    file.write(createId3v1Tag());

    Path path = dir.resolve("id3v1.mp3");
    Files.write(path, file.toByteArray());
    return path;
  }

  private static void writeV23Frame(ByteArrayOutputStream frames, String tag, String value)
      throws IOException {
    byte[] valueBytes = value.getBytes(StandardCharsets.ISO_8859_1);
    byte[] frameData = new byte[valueBytes.length + 1]; // first byte = text encoding
    System.arraycopy(valueBytes, 0, frameData, 1, valueBytes.length);

    DataOutputStream out = new DataOutputStream(frames);
    out.write(tag.getBytes(StandardCharsets.ISO_8859_1));
    out.writeInt(frameData.length);
    out.writeShort(0); // flags
    out.write(frameData);
  }

  private static void writeV22Frame(ByteArrayOutputStream frames, String tag, String value)
      throws IOException {
    byte[] valueBytes = value.getBytes(StandardCharsets.ISO_8859_1);
    byte[] frameData = new byte[valueBytes.length + 1];
    System.arraycopy(valueBytes, 0, frameData, 1, valueBytes.length);

    frames.write(tag.getBytes(StandardCharsets.ISO_8859_1));
    int len = frameData.length;
    frames.write(new byte[] {(byte) ((len >> 16) & 0xFF), (byte) ((len >> 8) & 0xFF), (byte) len});
    frames.write(frameData);
  }

  private static byte[] toSynchsafe(int size) {
    return new byte[] {
      (byte) ((size >> 21) & 0x7F),
      (byte) ((size >> 14) & 0x7F),
      (byte) ((size >> 7) & 0x7F),
      (byte) (size & 0x7F)
    };
  }

  private static byte[] createId3v1Tag() {
    String title = "V1 Title";
    String artist = "V1 Artist";
    String album = "V1 Album";
    String year = "2010";
    int track = 5;
    int genre = 13;
    byte[] buf = new byte[128];
    fillField(buf, 0, 3, "TAG");
    fillField(buf, 3, 30, title);
    fillField(buf, 33, 30, artist);
    fillField(buf, 63, 30, album);
    fillField(buf, 93, 4, year);
    fillField(buf, 97, 28, ""); // comment
    buf[125] = 0; // separator indicating track number present
    buf[126] = (byte) track;
    buf[127] = (byte) genre;
    return buf;
  }

  private static void fillField(byte[] buf, int start, int length, String value) {
    byte[] valueBytes = value.getBytes(StandardCharsets.ISO_8859_1);
    int copyLength = Math.min(valueBytes.length, length);
    System.arraycopy(valueBytes, 0, buf, start, copyLength);
    for (int i = start + copyLength; i < start + length; i++) {
      buf[i] = ' ';
    }
  }
}
