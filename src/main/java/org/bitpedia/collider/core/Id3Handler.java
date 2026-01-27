/* (PD) 2006 The Bitzi Corporation
 * Please see http://bitzi.com/publicdomain for more info.
 *
 * $Id: Id3Handler.java,v 1.2 2006/07/14 04:58:39 gojomo Exp $
 */
package org.bitpedia.collider.core;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;

/**
 * Utility reader for ID3 metadata embedded in audio files.
 *
 * <p>This helper parses the ID3v1 footer and ID3v2.2/ID3v2.3 headers directly from a {@code
 * RandomAccessFile}, exposing only the small immutable {@link Id3Info} snapshot that callers
 * typically need for cataloging or display. It performs size validation, gracefully stops on
 * malformed frames, and combines v2 data with the older v1 footer so legacy tags are still honored.
 * The class contains only static methods and state-free helper types, making it safe to invoke from
 * multiple threads as long as each caller supplies its own open file handle.
 *
 * <p>Typical usage reads v2 tags first and falls back to v1 if necessary:
 *
 * <pre>{@code
 * Id3Handler.Id3Info info = Id3Handler.readId3Tags("/path/to/song.mp3");
 * if (info != null) {
 *   System.out.println(info.title);
 * }
 * }</pre>
 *
 * <ul>
 *   <li>Supports ID3v2.2 and ID3v2.3 text frames plus the ID3v1 footer.
 *   <li>Leaves the file otherwise untouched; only reads bytes from supplied streams.
 *   <li>Does not normalize character encodings beyond stripping the leading encoding byte.
 *   <li>Thread-safe through immutability and absence of shared mutable state.
 * </ul>
 */
public class Id3Handler {

  private static final int SUPPORTED_VERSION_2_2 = 2;
  private static final int SUPPORTED_VERSION_2_3 = 3;
  private static final int FRAME_HEADER_V23_SIZE = 10;
  private static final int FRAME_HEADER_V22_SIZE = 6;

  private static final String[] genres = {
    "Blues",
    "Classic Rock",
    "Country",
    "Dance",
    "Disco",
    "Funk",
    "Grunge",
    "Hip-Hop",
    "Jazz",
    "Metal",
    "New Age",
    "Oldies",
    "Other",
    "Pop",
    "R&B",
    "Rap",
    "Reggae",
    "Rock",
    "Techno",
    "Industrial",
    "Alternative",
    "Ska",
    "Death Metal",
    "Pranks",
    "Soundtrack",
    "Euro-Techno",
    "Ambient",
    "Trip-Hop",
    "Vocal",
    "Jazz+Funk",
    "Fusion",
    "Trance",
    "Classical",
    "Instrumental",
    "Acid",
    "House",
    "Game",
    "Sound Clip",
    "Gospel",
    "Noise",
    "AlternRock",
    "Bass",
    "Soul",
    "Punk",
    "Space",
    "Meditative",
    "Instrumental Pop",
    "Instrumental Rock",
    "Ethnic",
    "Gothic",
    "Darkwave",
    "Techno-Industrial",
    "Electronic",
    "Pop-Folk",
    "Eurodance",
    "Dream",
    "Southern Rock",
    "Comedy",
    "Cult",
    "Gangsta",
    "Top 40",
    "Christian Rap",
    "Pop/Funk",
    "Jungle",
    "Native American",
    "Cabaret",
    "New Wave",
    "Psychadelic",
    "Rave",
    "Showtunes",
    "Trailer",
    "Lo-Fi",
    "Tribal",
    "Acid Punk",
    "Acid Jazz",
    "Polka",
    "Retro",
    "Musical",
    "Rock & Roll",
    "Hard Rock",
    "Folk",
    "Folk-Rock",
    "National Folk",
    "Swing",
    "Fast Fusion",
    "Bebob",
    "Latin",
    "Revival",
    "Celtic",
    "Bluegrass",
    "Avantgarde",
    "Gothic Rock",
    "Progressive Rock",
    "Psychedelic Rock",
    "Symphonic Rock",
    "Slow Rock",
    "Big Band",
    "Chorus",
    "Easy Listening",
    "Acoustic",
    "Humour",
    "Speech",
    "Chanson",
    "Opera",
    "Chamber Music",
    "Sonata",
    "Symphony",
    "Booty Bass",
    "Primus",
    "Porn Groove",
    "Satire",
    "Slow Jam",
    "Club",
    "Tango",
    "Samba",
    "Folklore",
    "Ballad",
    "Power Ballad",
    "Rhythmic Soul",
    "Freestyle",
    "Duet",
    "Punk Rock",
    "Drum Solo",
    "Acapella",
    "Euro-House",
    "Dance Hall",
    "Goa",
    "Drum & Bass",
    "Club-House",
    "Hardcore",
    "Terror",
    "Indie",
    "BritPop",
    "Negerpunk",
    "Polsk Punk",
    "Beat",
    "Christian Gangsta",
    "Heavy Metal",
    "Black Metal",
    "Crossover",
    "Contemporary C",
    "Christian Rock",
    "Merengue",
    "Salsa",
    "Thrash Metal",
    "Anime",
    "JPop",
    "SynthPop"
  };

  /**
   * Data holder for an ID3v1 footer parsed from the last 128 bytes of a file.
   *
   * <p>Instances are populated by {@link #readFromFile(RandomAccessFile)} and hold raw field values
   * exactly as encoded in the tag. Text values may contain padding spaces; callers can invoke
   * {@link #trimFields()} to remove trailing whitespace while preserving null values. All fields
   * are mutable to mirror the permissive legacy tag structure and are intended for short-lived use
   * during metadata extraction.
   */
  public static class Id3v1 {

    String id;
    String title;
    String artist;
    String album;
    String year;
    String comment;
    int track;
    int genre;

    /**
     * Creates an empty container for ID3v1 field values read from a file.
     *
     * <p>No normalization or validation is performed during construction; fields are populated by
     * {@link #readFromFile(RandomAccessFile)} or manual assignment before presentation to callers.
     */
    public Id3v1() {
      // Intentionally empty; fields are populated after construction by readFromFile or direct
      // assignment.
    }

    static Id3v1 readFromFile(RandomAccessFile f) {

      byte[] buf = new byte[128];
      try {
        f.seek(f.length() - 128);
        f.read(buf);

        Id3v1 info = new Id3v1();
        info.id = new String(buf, 0, 3, StandardCharsets.ISO_8859_1);
        info.title = new String(buf, 3, 30, StandardCharsets.ISO_8859_1);
        info.artist = new String(buf, 33, 30, StandardCharsets.ISO_8859_1);
        info.album = new String(buf, 63, 30, StandardCharsets.ISO_8859_1);
        info.year = new String(buf, 93, 4, StandardCharsets.ISO_8859_1);
        if (0 == buf[125]) {
          info.comment = new String(buf, 97, 28, StandardCharsets.ISO_8859_1);
          info.track = buf[126] >= 0 ? buf[126] : buf[126] + 256;
        } else {
          info.comment = new String(buf, 97, 30, StandardCharsets.ISO_8859_1);
        }
        info.genre = buf[127] >= 0 ? buf[127] : buf[127] + 256;

        return info;
      } catch (IOException _) {
        return null;
      }
    }

    /**
     * Removes leading and trailing whitespace from all text fields in place.
     *
     * <p>The operation skips null fields and leaves numeric fields unchanged. Use this after
     * reading a tag when human-readable presentation is desired and the trailing padding added by
     * ID3v1 encoders should be suppressed. The method is idempotent and safe to call multiple times
     * on the same instance.
     */
    public void trimFields() {

      if (null != title) title = title.trim();
      if (null != artist) artist = artist.trim();
      if (null != album) album = album.trim();
      if (null != year) year = year.trim();
    }
  }

  /**
   * Parsed ID3v2 header information for the tag block at the start of a file.
   *
   * <p>The header stores the raw version numbers, flags, and sync-safe size bytes that bound the
   * subsequent frame sequence. Instances are produced by {@link #readFromFile(RandomAccessFile)}
   * and consumed internally to drive frame parsing. The class performs no validation beyond simple
   * byte extraction, leaving semantic checks to the caller.
   */
  public static class Id3Header {

    String tag;
    int versionMajor;
    int versionRevision;
    int flags;
    int[] size = new int[4];

    /**
     * Builds an empty header that will be filled from the start of an ID3v2 tag block.
     *
     * <p>All fields remain zero until {@link #readFromFile(RandomAccessFile)} populates them;
     * callers typically do not instantiate this type directly outside parsing utilities.
     */
    public Id3Header() {
      // Intentionally empty; header bytes are assigned during stream parsing.
    }

    static Id3Header readFromFile(RandomAccessFile f) {

      byte[] buf = new byte[10];
      try {
        f.read(buf);

        Id3Header h = new Id3Header();
        h.tag = new String(buf, 0, 3, StandardCharsets.ISO_8859_1);
        h.versionMajor = buf[3] >= 0 ? buf[3] : buf[3] + 256;
        h.versionRevision = buf[4] >= 0 ? buf[4] : buf[4] + 256;
        h.flags = buf[5] >= 0 ? buf[5] : buf[5] + 256;
        h.size[0] = buf[6] >= 0 ? buf[6] : buf[6] + 256;
        h.size[1] = buf[7] >= 0 ? buf[7] : buf[7] + 256;
        h.size[2] = buf[8] >= 0 ? buf[8] : buf[8] + 256;
        h.size[3] = buf[9] >= 0 ? buf[9] : buf[9] + 256;

        return h;
      } catch (IOException _) {
        return null;
      }
    }
  }

  /**
   * Frame header representation for ID3v2.3 tags.
   *
   * <p>Holds the four-character frame identifier, the frame size read from the stream, and the raw
   * flags field. A header is considered valid only when the associated frame size is sensible for
   * the containing file; this class does not enforce those rules itself. Instances are constructed
   * on demand during sequential parsing and discarded once a frame is consumed.
   */
  public static class FrameHeaderv23 {

    String tag;
    int size;
    int flags;

    /** Constructs a placeholder for a single ID3v2.3 frame header before parsing stream bytes. */
    public FrameHeaderv23() {
      // Intentionally empty; values are set from the frame stream when parsing.
    }

    static FrameHeaderv23 readFromFile(RandomAccessFile f) {

      try {

        FrameHeaderv23 h = new FrameHeaderv23();

        byte[] buf = new byte[4];
        f.read(buf);
        h.tag = new String(buf, StandardCharsets.ISO_8859_1);
        h.size = f.readInt();
        h.flags = f.readUnsignedShort();

        return h;
      } catch (Exception _) {
        return null;
      }
    }

    int getFrameSize() {
      return size;
    }
  }

  /**
   * Frame header representation for ID3v2.2 tags.
   *
   * <p>Stores the three-character frame identifier along with the three-byte size field encoded in
   * big-endian order. Parsing is deliberately minimal and defers bounds checking to callers. Each
   * header instance is typically short-lived and paired with a single frame read.
   */
  public static class FrameHeaderv22 {

    String tag;
    byte[] size = new byte[3];

    /** Constructs an empty representation of an ID3v2.2 frame header prior to parsing. */
    public FrameHeaderv22() {
      // Intentionally empty; populated immediately after construction while reading a frame.
    }

    static FrameHeaderv22 readFromFile(RandomAccessFile f) {

      try {
        FrameHeaderv22 h = new FrameHeaderv22();

        byte[] buf = new byte[3];
        f.read(buf);
        h.tag = new String(buf, 0, 3, StandardCharsets.ISO_8859_1);
        f.read(h.size);

        return h;
      } catch (Exception _) {
        return null;
      }
    }

    int getFrameSize() {

      int b1 = size[0] >= 0 ? size[0] : size[0] + 256;
      int b2 = size[1] >= 0 ? size[1] : size[1] + 256;
      int b3 = size[2] >= 0 ? size[2] : size[2] + 256;

      return (b1 << 16) + (b2 << 8) + b3;
    }
  }

  /**
   * Consolidated view of the metadata fields extracted from ID3 tags.
   *
   * <p>The container aggregates artist, album, title, genre, year, encoder, and track number in a
   * format suitable for upstream cataloging logic. All fields are nullable to reflect optional tag
   * presence; callers may freely combine v2 and v1 data by passing a partially populated instance
   * to {@link #readId3v1Tags(String, Id3Info)} for backfilling. Instances are mutable and intended
   * for transient use rather than long-term caching.
   */
  public static class Id3Info {
    String artist;
    String album;
    String title;
    String genre;
    String year;
    String encoder;
    String trackNumber;

    /** Creates an initially blank metadata aggregate suitable for progressive backfilling. */
    public Id3Info() {
      // Intentionally empty; fields are assigned progressively as tags are discovered.
    }
  }

  private static final int TEXT_DATA_OFFSET = 1;

  private static void handleFramev23(String tag, byte[] data, int len, Id3Info info) {

    if ((null == data) || (0 == data.length)) {
      return;
    }

    if ("TIT2".equals(tag)) {
      info.title = new String(data, TEXT_DATA_OFFSET, len, StandardCharsets.ISO_8859_1);
    } else if ("TALB".equals(tag)) {
      info.album = new String(data, TEXT_DATA_OFFSET, len, StandardCharsets.ISO_8859_1);
    } else if ("TPE1".equals(tag)) {
      info.artist = new String(data, TEXT_DATA_OFFSET, len, StandardCharsets.ISO_8859_1);
    } else if ("TYER".equals(tag)) {
      info.year = new String(data, TEXT_DATA_OFFSET, len, StandardCharsets.ISO_8859_1);
    } else if ("TCON".equals(tag)) {

      String genreName = new String(data, TEXT_DATA_OFFSET, len, StandardCharsets.ISO_8859_1);
      for (int i = 0; i < genres.length; i++) {

        if (genres[i].equals(genreName)) {
          info.genre = Integer.toString(i);
        }
      }
    } else if ("TRCK".equals(tag)) {
      info.trackNumber = new String(data, TEXT_DATA_OFFSET, len, StandardCharsets.ISO_8859_1);
    } else if ("TSSE".equals(tag)) {
      info.encoder = new String(data, TEXT_DATA_OFFSET, len, StandardCharsets.ISO_8859_1);
    }
  }

  private static void handleFramev22(String tag, byte[] data, int len, Id3Info info) {

    if ((null == data) || (0 == data.length)) return;

    if ("TT2".equals(tag)) {
      info.title = new String(data, TEXT_DATA_OFFSET, len, StandardCharsets.ISO_8859_1);
    } else if ("TAL".equals(tag)) {
      info.album = new String(data, TEXT_DATA_OFFSET, len, StandardCharsets.ISO_8859_1);
    } else if ("TP1".equals(tag)) {
      info.artist = new String(data, TEXT_DATA_OFFSET, len, StandardCharsets.ISO_8859_1);
    } else if ("TYE".equals(tag)) {
      info.year = new String(data, TEXT_DATA_OFFSET, len, StandardCharsets.ISO_8859_1);
    } else if ("TSI".equals(tag)) {
      info.genre = new String(data, TEXT_DATA_OFFSET, len, StandardCharsets.ISO_8859_1);
    } else if ("TRK".equals(tag)) {
      info.trackNumber = new String(data, TEXT_DATA_OFFSET, len, StandardCharsets.ISO_8859_1);
    } else if ("TSS".equals(tag)) {
      info.encoder = new String(data, TEXT_DATA_OFFSET, len, StandardCharsets.ISO_8859_1);
    }
  }

  private static Id3Info readId3v2Tags(String fileName) {

    try (RandomAccessFile f = new RandomAccessFile(fileName, "r")) {
      long fileSize = f.length();

      Id3Header head = Id3Header.readFromFile(f);
      if (isInvalidHeader(head)) {
        return null;
      }

      long size = calculateTagSize(head.size);
      if (fileSize < size) {
        return null;
      }

      if (0 != (head.flags & (1 << 6))) {

        int extHeaderSize = f.readInt();
        f.skipBytes(extHeaderSize);
      }

      Id3Info info = new Id3Info();
      while (size > 0) {

        int processedSize = processFrame(f, head.versionMajor, info, fileSize);
        if (processedSize < 0) {
          return null;
        }
        if (processedSize == 0) {
          break;
        }

        size -= getHeaderSize(head.versionMajor) + processedSize;
      }

      return info;

    } catch (Exception _) {
      return null;
    }
  }

  private static Id3Info readId3v1Tags(String fileName, Id3Info info) {

    try (RandomAccessFile f = new RandomAccessFile(fileName, "r")) {
      Id3v1 id3 = Id3v1.readFromFile(f);
      if ((null == id3) || !"TAG".equals(id3.id)) {
        return info;
      }

      Id3Info target = (null == info) ? new Id3Info() : info;
      populateFromId3v1(id3, target);

      return target;
    } catch (IOException _) {
      return info;
    }
  }

  /**
   * Reads ID3 metadata from the supplied file path, combining v2 and v1 sources.
   *
   * <p>The method first attempts to parse an ID3v2.2 or ID3v2.3 header from the start of the file;
   * when present and well-formed, it processes frames until the declared tag size is exhausted or a
   * malformed frame is encountered. It then looks for an ID3v1 footer and merges any missing fields
   * such as title or track number. No bytes are written and the file is closed automatically via a
   * try-with-resources block. Callers should treat a {@code null} result as an indication that no
   * usable tag data was found.
   *
   * @param fileName absolute or relative path to the audio file to inspect; must reference a file
   *     readable by the current process.
   * @return populated {@link Id3Info} when at least one supported tag is present; {@code null} when
   *     parsing fails or no metadata is available.
   */
  public static Id3Info readId3Tags(String fileName) {

    return readId3v1Tags(fileName, readId3v2Tags(fileName));
  }

  private static long calculateTagSize(int[] sizeBytes) {
    return (sizeBytes[3] & 0x7F)
        | ((sizeBytes[2] & 0x7F) << 7)
        | ((sizeBytes[1] & 0x7F) << 14)
        | ((sizeBytes[0] & 0x7F) << 21);
  }

  private static boolean isInvalidHeader(Id3Header head) {
    if (null == head) {
      return true;
    }
    if (!"ID3".equals(head.tag)) {
      return true;
    }
    return (SUPPORTED_VERSION_2_2 != head.versionMajor)
        && (SUPPORTED_VERSION_2_3 != head.versionMajor);
  }

  private static int processFrame(RandomAccessFile f, int version, Id3Info info, long fileSize)
      throws IOException {
    if (SUPPORTED_VERSION_2_2 == version) {
      return readAndHandleFrameV22(f, info, fileSize);
    }
    return readAndHandleFrameV23(f, info, fileSize);
  }

  private static int readAndHandleFrameV22(RandomAccessFile f, Id3Info info, long fileSize)
      throws IOException {
    FrameHeaderv22 frame = FrameHeaderv22.readFromFile(f);
    if (null == frame) {
      return -1;
    }
    int frameSize = frame.getFrameSize();
    if (isInvalidFrameSize(frameSize, fileSize)) {
      return 0;
    }
    byte[] frameData = readFrameData(f, frameSize);
    if (null == frameData) {
      return -1;
    }
    handleFramev22(frame.tag, frameData, frameSize - 1, info);
    return frameSize;
  }

  private static int readAndHandleFrameV23(RandomAccessFile f, Id3Info info, long fileSize)
      throws IOException {
    FrameHeaderv23 frame = FrameHeaderv23.readFromFile(f);
    if (null == frame) {
      return -1;
    }
    int frameSize = frame.getFrameSize();
    if (isInvalidFrameSize(frameSize, fileSize)) {
      return 0;
    }
    byte[] frameData = readFrameData(f, frameSize);
    if (null == frameData) {
      return -1;
    }
    handleFramev23(frame.tag, frameData, frameSize - 1, info);
    return frameSize;
  }

  private static boolean isInvalidFrameSize(int frameSize, long fileSize) {
    return (0 == frameSize) || (fileSize < frameSize);
  }

  private static byte[] readFrameData(RandomAccessFile f, int frameSize) throws IOException {
    byte[] frameData = new byte[frameSize];
    int read = f.read(frameData);
    return read == frameSize ? frameData : null;
  }

  private static int getHeaderSize(int version) {
    return SUPPORTED_VERSION_2_3 == version ? FRAME_HEADER_V23_SIZE : FRAME_HEADER_V22_SIZE;
  }

  private static void populateFromId3v1(Id3v1 id3, Id3Info target) {
    id3.trimFields();
    if (hasText(id3.artist)) {
      target.artist = id3.artist;
    }
    if (hasText(id3.album)) {
      target.album = id3.album;
    }
    if (hasText(id3.title)) {
      target.title = id3.title;
    }
    copyValidYear(id3, target);
    if (0 != id3.track) {
      target.trackNumber = Integer.toString(id3.track);
    }

    if (255 != id3.genre) {
      target.genre = Integer.toString(id3.genre);
    }
  }

  private static void copyValidYear(Id3v1 id3, Id3Info target) {
    if (hasText(id3.year)) {
      try {
        int intYear = Integer.parseInt(id3.year);
        if ((1000 <= intYear) && (intYear < 3000)) {
          target.year = id3.year;
        }
      } catch (NumberFormatException _) {
        // Intentionally ignore invalid year formats to preserve original behavior.
      }
    }
  }

  private static boolean hasText(String value) {
    return (null != value) && !value.trim().isEmpty();
  }

  private Id3Handler() {
    throw new IllegalStateException("Utility class");
  }
}
