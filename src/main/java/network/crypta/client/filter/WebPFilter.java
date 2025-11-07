package network.crypta.client.filter;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import network.crypta.l10n.NodeL10n;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class WebPFilter extends RIFFFilter {
  private static final Logger LOG = LoggerFactory.getLogger(WebPFilter.class);

  @Override
  protected byte[] getChunkMagicNumber() {
    return new byte[] {'W', 'E', 'B', 'P'};
  }

  private static final class WebPFilterContext {
    int VP8XFlags = 0;
    boolean hasVP8X = false;
    boolean hasANIM = false;
    boolean hasANMF = false;
    boolean hasALPH = false;
    boolean hasVP8 = false;
    boolean hasVP8L = false;
    int width = 0;
    int height = 0;
  }

  @Override
  protected Object createContext() {
    return new WebPFilterContext();
  }

  @Override
  protected void readFilterChunk(byte[] id, int size, Object context, ReadFilterContext params)
      throws IOException {
    WebPFilterContext ctx = (WebPFilterContext) context;
    // These constants are derived from mux_type.h in libwebp
    int ANIMATION_FLAG = 0x00000002;
    if (id[0] == 'V' && id[1] == 'P' && id[2] == '8' && id[3] == ' ') {
      if (ctx.hasVP8 || ctx.hasVP8L || ctx.hasANIM) {
        throw new DataFilterException(
            l10n("invalidTitle"), l10n("invalidTitle"), "Unexpected VP8 chunk was encountered");
      }
      ctx.hasVP8 = true;
      filterVP8Block(id, size, params.input, params.output, LOG.isDebugEnabled());
    } else if (id[0] == 'V' && id[1] == 'P' && id[2] == '8' && id[3] == 'L') {
      // VP8 Lossless format:
      // https://chromium.googlesource.com/webm/libwebp/+/refs/tags/v1.4.0/doc/webp-lossless-bitstream-spec.txt
      if (ctx.hasVP8 || ctx.hasVP8L || ctx.hasANIM || ctx.hasALPH) {
        throw new DataFilterException(
            l10n("invalidTitle"), l10n("invalidTitle"), "Unexpected VP8L chunk was encountered");
      }
      // output.write(ID);
      // output.writeInt(((size & 0xff000000) >> 24) | ((size & 0x00ff0000) >> 8) | ((size &
      // 0x0000ff00) << 8) | ((size & 0x000000ff) << 24));
      // CVE-2023-4863 is an exploit for libwebp (before version 1.3.2) implementation of WebP
      // lossless format, and that could be used in animation and alpha channel as well. This is
      // really serious that we must not let Bad Thing happen.
      // TODO: Check for CVE-2023-4863 exploit!
      ctx.hasVP8L = true;
      throw new DataFilterException(
          l10n("losslessUnsupportedTitle"),
          l10n("losslessUnsupportedTitle"),
          l10n("losslessUnsupported"));
    } else if (id[0] == 'A' && id[1] == 'L' && id[2] == 'P' && id[3] == 'H') {
      int ALPHA_FLAG = 0x00000010;
      if (ctx.hasVP8L
          || ctx.hasANIM
          || ctx.hasALPH
          || (!ctx.hasVP8X)
          || ((ctx.VP8XFlags & ALPHA_FLAG) == 0)) {
        // Only applicable to VP8 images. VP8L already has alpha channel, so does not need this.
        throw new DataFilterException(
            l10n("invalidTitle"), l10n("invalidTitle"), "Unexpected ALPH chunk was encountered");
      }
      ctx.hasALPH = true;
      filterALPHBlock(id, size, params.input, params.output, LOG.isDebugEnabled());
    } else if (id[0] == 'A' && id[1] == 'N' && id[2] == 'I' && id[3] == 'M') {
      if ((ctx.VP8XFlags & ANIMATION_FLAG) == 0 || ctx.hasVP8 || ctx.hasVP8L || ctx.hasANIM) {
        throw new DataFilterException(
            l10n("invalidTitle"), l10n("invalidTitle"), "Unexpected ANIM chunk was encountered");
      }
      ctx.hasANIM = true;
      // Global animation parameters
      params.output.write(id);
      writeLittleEndianInt(params.output, size);
      if (size != 6) {
        throw new DataFilterException(
            l10n("invalidTitle"), l10n("invalidTitle"), "ANIM chunk size is too small or too big");
      }
      // Background color and loop count here. Pass through.
      passthroughBytes(params.input, params.output, size);
    } else if (id[0] == 'A' && id[1] == 'N' && id[2] == 'M' && id[3] == 'F') {
      // Animation frame
      if ((ctx.VP8XFlags & ANIMATION_FLAG) == 0 || ctx.hasVP8 || ctx.hasVP8L || !ctx.hasANIM) {
        // Animation frame in static WebP file - Unexpected
        throw new DataFilterException(
            l10n("invalidTitle"), l10n("invalidTitle"), "Unexpected ANMF chunk was encountered");
      }
      if ((size < 16 + 8) || (size % 2 != 0)) {
        // Not enough data for ANMF data and block header for at least one block
        // Or size is odd (can't happen because there are sub-blocks)
        throw new DataFilterException(
            l10n("invalidTitle"),
            l10n("invalidTitle"),
            "ANMF chunk size is invalid (size=" + size + ")");
      }
      ctx.hasANMF = true;
      params.output.write(id);
      writeLittleEndianInt(params.output, size);
      int[] ANMFContent = new int[16]; // Unsigned bytes, can't use Java signed bytes
      for (int i = 0; i < 16; i++) {
        ANMFContent[i] = params.input.readUnsignedByte();
      }
      // Check image sizes
      int frameX, frameY, frameWidth, frameHeight, frameFlags;
      frameX = ANMFContent[0] | (ANMFContent[1] << 8) | (ANMFContent[2] << 16);
      frameY = ANMFContent[3] | (ANMFContent[4] << 8) | (ANMFContent[5] << 16);
      frameWidth = (ANMFContent[6] | (ANMFContent[7] << 8) | (ANMFContent[8] << 16)) + 1;
      frameHeight = (ANMFContent[9] | (ANMFContent[10] << 8) | (ANMFContent[11] << 16)) + 1;
      // frameDuration = ANMFContent[12] | (ANMFContent[13] << 8) | (ANMFContent[14] << 16);
      frameFlags = ANMFContent[15];
      if ((frameX + frameWidth > ctx.width) || (frameY + frameHeight > ctx.height)) {
        throw new DataFilterException(
            l10n("invalidTitle"),
            l10n("invalidTitle"),
            "ANMF canvas size extends beyond image size");
      }
      if ((frameFlags & 0xfc) != 0) {
        throw new DataFilterException(
            l10n("invalidTitle"), l10n("invalidTitle"), "ANMF block contains reserved flag");
      }
      for (int i = 0; i < 16; i++) {
        params.output.writeByte(ANMFContent[i]);
      }
      int ANMFRemainingSize = size - 16;
      boolean ANMFHasVP8 = false;
      boolean ANMFHasALPH = false;
      byte[] ANMFBlockID = new byte[4];
      int ANMFBlockSize;
      while (ANMFRemainingSize >= 8) {
        params.input.readFully(ANMFBlockID);
        ANMFBlockSize = readLittleEndianInt(params.input);
        if (ANMFBlockID[0] == 'V'
            && ANMFBlockID[1] == 'P'
            && ANMFBlockID[2] == '8'
            && ANMFBlockID[3] == ' ') {
          // VP8
          if (ANMFHasVP8) {
            throw new DataFilterException(
                l10n("invalidTitle"),
                l10n("invalidTitle"),
                "Unexpected VP8 chunk was encountered inside ANMF block");
          } else {
            ANMFHasVP8 = true;
          }
          filterVP8Block(
              ANMFBlockID, ANMFBlockSize, params.input, params.output, LOG.isDebugEnabled());
        } else if (ANMFBlockID[0] == 'V'
            && ANMFBlockID[1] == 'P'
            && ANMFBlockID[2] == '8'
            && ANMFBlockID[3] == 'L') {
          // VP8L
          // TODO: Check for CVE-2023-4863 exploit!
          throw new DataFilterException(
              l10n("animUnsupportedTitle"), l10n("animUnsupportedTitle"), l10n("animUnsupported"));
        } else if (ANMFBlockID[0] == 'A'
            && ANMFBlockID[1] == 'L'
            && ANMFBlockID[2] == 'P'
            && ANMFBlockID[3] == 'H') {
          // ALPH
          if (ANMFHasALPH) {
            throw new DataFilterException(
                l10n("invalidTitle"),
                l10n("invalidTitle"),
                "Unexpected ALPH chunk was encountered inside ANMF block");
          } else {
            ANMFHasALPH = true;
          }
          filterALPHBlock(
              ANMFBlockID, ANMFBlockSize, params.input, params.output, LOG.isDebugEnabled());
        } else {
          // Unknown block
          if (LOG.isDebugEnabled())
            LOG.debug(
                "WebP image has Unknown block with "
                    + ANMFBlockSize
                    + " bytes within ANMF chunk converted into JUNK chunk.");
          writeJunkChunk(params.input, params.output, ANMFBlockSize);
        }
        ANMFRemainingSize -= (ANMFBlockSize + ANMFBlockSize % 2) + 8;
      }
      if (ANMFRemainingSize != 0) {
        throw new DataFilterException(
            l10n("invalidTitle"),
            l10n("invalidTitle"),
            "Unexpected data remaining at the end of ANMF chunk");
      }
      // ANMF without frame image can probably used to fill canvas with the background color.
    } else if (id[0] == 'V' && id[1] == 'P' && id[2] == '8' && id[3] == 'X') {
      // meta information
      if (ctx.hasVP8 || ctx.hasVP8L || ctx.hasANIM || ctx.hasVP8X) {
        // This should be the first chunk of the file
        throw new DataFilterException(
            l10n("invalidTitle"), l10n("invalidTitle"), "Unexpected VP8X chunk was encountered");
      }
      ctx.VP8XFlags = readLittleEndianInt(params.input);
      int ALL_VALID_FLAGS = 0x0000003e;
      if ((ctx.VP8XFlags & ~ALL_VALID_FLAGS) != 0) {
        // Has reserved flags or uses unsupported image fragmentation
        throw new DataFilterException(
            l10n("invalidTitle"), l10n("invalidTitle"), "VP8X header has reserved flags");
      }
      if (size != 10) {
        throw new DataFilterException(
            l10n("invalidTitle"), l10n("invalidTitle"), "VP8X header is too small or too big");
      }
      params.output.write(id);
      writeLittleEndianInt(params.output, size);
      int ICCP_FLAG = 0x00000020;
      int EXIF_FLAG = 0x00000008;
      int XMP_FLAG = 0x00000004;
      ctx.VP8XFlags &= ~(XMP_FLAG | EXIF_FLAG | ICCP_FLAG); // removing ICCP, EXIF and XMP bits
      writeLittleEndianInt(params.output, ctx.VP8XFlags);
      ctx.hasVP8X = true;
      int[] widthHeight = new int[6]; // Unsigned bytes, can't use Java signed bytes
      for (int i = 0; i < 6; i++) {
        widthHeight[i] = params.input.readUnsignedByte();
      }
      // width and height are 24 bits
      ctx.width = widthHeight[0] | widthHeight[1] << 8 | widthHeight[2] << 16;
      ctx.height = widthHeight[3] | widthHeight[4] << 8 | widthHeight[5] << 16;
      ctx.width++;
      ctx.height++;
      if (ctx.width > 16384 || ctx.height > 16384) {
        // VP8 lossy format couldn't encode more than 16384 pixels in width or height. Check again
        // when lossless format is supported.
        throw new DataFilterException(
            l10n("invalidTitle"), l10n("invalidTitle"), "WebP image size is too big");
      }
      for (int i = 0; i < 6; i++) {
        params.output.writeByte(widthHeight[i]);
      }
    } else if (id[0] == 'I' && id[1] == 'C' && id[2] == 'C' && id[3] == 'P') {
      // ICC Color Profile
      if (LOG.isDebugEnabled())
        LOG.debug("WebP image has ICCP block with " + size + " bytes converted into JUNK chunk.");
      writeJunkChunk(params.input, params.output, size);
    } else if (id[0] == 'E' && id[1] == 'X' && id[2] == 'I' && id[3] == 'F') {
      // EXIF metadata
      if (LOG.isDebugEnabled())
        LOG.debug("WebP image has EXIF block with " + size + " bytes converted into JUNK chunk.");
      writeJunkChunk(params.input, params.output, size);
    } else if (id[0] == 'X' && id[1] == 'M' && id[2] == 'P' && id[3] == ' ') {
      // XMP metadata
      if (LOG.isDebugEnabled())
        LOG.debug("WebP image has XMP block with " + size + " bytes converted into JUNK chunk.");
      writeJunkChunk(params.input, params.output, size);
    } else {
      // Unknown block
      if (LOG.isDebugEnabled())
        LOG.debug(
            "WebP image has Unknown block with " + size + " bytes converted into JUNK chunk.");
      writeJunkChunk(params.input, params.output, size);
    }
  }

  @Override
  protected void eofCheck(Object context) throws DataFilterException {
    WebPFilterContext ctx = (WebPFilterContext) context;
    if (!ctx.hasVP8 && !ctx.hasVP8L && !ctx.hasANMF) {
      throw new DataFilterException(
          l10n("invalidTitle"), l10n("invalidTitle"), "No image chunk in the WebP file is found");
    }
  }

  private void filterVP8Block(
      byte[] ID, int size, DataInputStream input, DataOutputStream output, boolean logDEBUG)
      throws IOException {
    // VP8 Lossy format: RFC 6386
    // Most WebP files just contain a single chunk of this kind
    if (size < 10) {
      throw new DataFilterException(
          l10n("invalidTitle"), l10n("invalidTitle"), "The VP8 chunk was too small to be valid");
    }
    output.write(ID);
    if (LOG.isTraceEnabled()) LOG.trace("Passing through WebP VP8 block with " + size + " bytes.");
    VP8PacketFilter VP8filter = new VP8PacketFilter(true);
    // Just read 6 bytes of the header to validate
    byte[] buf = new byte[6];
    input.readFully(buf);
    VP8filter.parse(buf, size);
    writeLittleEndianInt(output, size);
    output.write(buf);
    passthroughBytes(input, output, size - buf.length);
    if ((size & 1) != 0) { // Add padding if necessary
      output.writeByte(input.readByte());
    }
  }

  private void filterALPHBlock(
      byte[] ID, int size, DataInputStream input, DataOutputStream output, boolean logDEBUG)
      throws IOException {
    if (size == 0) {
      throw new DataFilterException(
          l10n("invalidTitle"), l10n("invalidTitle"), "Unexpected empty ALPH chunk");
    }
    // Alpha channel
    int flags = input.readUnsignedByte();
    if ((flags & 2) != 0) {
      // Compression is not uncompressed
      throw new DataFilterException(
          l10n("invalidTitle"), l10n("invalidTitle"), "WebP alpha channel contains reserved bits");
    }
    if ((flags & 0xc0) != 0) {
      // Compression is not uncompressed
      // TODO: Check for CVE-2023-4863 exploit!
      throw new DataFilterException(
          l10n("alphUnsupportedTitle"), l10n("alphUnsupportedTitle"), l10n("alphUnsupported"));
    }
    output.write(ID);
    if (LOG.isTraceEnabled()) LOG.trace("Passing through WebP ALPH block with " + size + " bytes.");
    writeLittleEndianInt(output, size);
    output.writeByte(flags);
    passthroughBytes(input, output, size - 1);
    if ((size & 1) != 0) { // Add padding if necessary
      output.writeByte(input.readByte());
    }
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("WebPFilter." + key);
  }
}
