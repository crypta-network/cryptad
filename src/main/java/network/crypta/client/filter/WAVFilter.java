package network.crypta.client.filter;

import java.io.IOException;
import network.crypta.l10n.NodeL10n;

public class WAVFilter extends RIFFFilter {
  // RFC 2361
  private final int WAVE_FORMAT_UNKNOWN = 0;

  @Override
  protected byte[] getChunkMagicNumber() {
    return new byte[] {'W', 'A', 'V', 'E'};
  }

  private static final class WAVFilterContext {
    boolean hasfmt = false;
    boolean hasdata = false;
    int nSamplesPerSec = 0;
    int nChannels = 0;
    int nBlockAlign = 0;
    int wBitsPerSample = 0;
    int format = 0;
  }

  @Override
  protected Object createContext() {
    return new WAVFilterContext();
  }

  @Override
  protected void readFilterChunk(byte[] id, int size, Object context, ReadFilterContext params)
      throws IOException {
    WAVFilterContext ctx = (WAVFilterContext) context;
    if (id[0] == 'f' && id[1] == 'm' && id[2] == 't' && id[3] == ' ') {
      if (ctx.hasfmt) {
        throw new DataFilterException(
            l10n("invalidTitle"), l10n("invalidTitle"), "Unexpected fmt chunk was encountered");
      }
      // fmt header with cbSize and extensions
      int FMT_SIZE_cbSize_extension = 40;
      // fmt header with cbSize = 0
      int FMT_SIZE_cbSize = 18;
      // Header sizes (https://www.mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/WAVE.html)
      // fmt header without cbSize field
      int FMT_SIZE_BASIC = 16;
      if (size != FMT_SIZE_BASIC && size != FMT_SIZE_cbSize && size != FMT_SIZE_cbSize_extension) {
        throw new DataFilterException(
            l10n("invalidTitle"), l10n("invalidTitle"), "fmt chunk size is invalid");
      }
      ctx.format = Short.reverseBytes(params.input.readShort());
      int WAVE_FORMAT_MULAW = 7;
      int WAVE_FORMAT_ALAW = 6;
      int WAVE_FORMAT_IEEE_FLOAT = 3;
      int WAVE_FORMAT_PCM = 1;
      if (ctx.format != WAVE_FORMAT_PCM
          && ctx.format != WAVE_FORMAT_IEEE_FLOAT
          && ctx.format != WAVE_FORMAT_ALAW
          && ctx.format != WAVE_FORMAT_MULAW) {
        throw new DataFilterException(
            l10n("invalidTitle"), l10n("invalidTitle"), "WAV file uses a not yet supported format");
      }
      ctx.nChannels = Short.reverseBytes(params.input.readShort());
      params.output.write(id);
      writeLittleEndianInt(params.output, size);
      params.output.writeInt(
          (Short.reverseBytes((short) ctx.format) << 16)
              | Short.reverseBytes((short) ctx.nChannels));
      ctx.nSamplesPerSec = readLittleEndianInt(params.input);
      writeLittleEndianInt(params.output, ctx.nSamplesPerSec);
      int nAvgBytesPerSec = readLittleEndianInt(params.input);
      writeLittleEndianInt(params.output, nAvgBytesPerSec);
      ctx.nBlockAlign = Short.reverseBytes(params.input.readShort());
      ctx.wBitsPerSample = Short.reverseBytes(params.input.readShort());
      params.output.writeInt(
          (Short.reverseBytes((short) ctx.nBlockAlign) << 16)
              | Short.reverseBytes((short) ctx.wBitsPerSample));
      ctx.hasfmt = true;
      if (size > FMT_SIZE_BASIC) {
        short cbSize = Short.reverseBytes(params.input.readShort());
        if (cbSize + FMT_SIZE_cbSize != size) {
          throw new DataFilterException(
              l10n("invalidTitle"), l10n("invalidTitle"), "fmt chunk size is invalid");
        }
        params.output.writeShort(Short.reverseBytes(cbSize));
      }
      if (size > FMT_SIZE_cbSize) {
        // wValidBitsPerSample, dwChannelMask, and SubFormat GUID
        passthroughBytes(params.input, params.output, FMT_SIZE_cbSize_extension - FMT_SIZE_cbSize);
      }
      // Further checks
      if ((ctx.format == WAVE_FORMAT_ALAW || ctx.format == WAVE_FORMAT_MULAW)
          && ctx.wBitsPerSample != 8) {
        // These formats are 8-bit
        throw new DataFilterException(
            l10n("invalidTitle"), l10n("invalidTitle"), "Unexpected bits per sample value");
      }
      return;
    }
    if (!ctx.hasfmt) {
      throw new DataFilterException(
          l10n("invalidTitle"),
          l10n("invalidTitle"),
          "Unexpected header chunk was encountered, instead of fmt chunk");
    }
    if (id[0] == 'd' && id[1] == 'a' && id[2] == 't' && id[3] == 'a') {
      // audio data
      params.output.write(id);
      writeLittleEndianInt(params.output, size);
      passthroughBytes(params.input, params.output, size);
      if ((size & 1) != 0) { // Add padding if necessary
        params.output.writeByte(params.input.readByte());
      }
      ctx.hasdata = true;
    } else if (id[0] == 'f' && id[1] == 'a' && id[2] == 'c' && id[3] == 't') {
      if (size != 4) {
        // It should be 4 bytes, so don't know what to do with the data other than discarding it.
        writeJunkChunk(params.input, params.output, size);
      } else {
        // Just dwSampleLength (Number of samples) here, pass through
        params.output.write(id);
        writeLittleEndianInt(params.output, size);
        passthroughBytes(params.input, params.output, size);
      }
    } else {
      // Unknown block
      writeJunkChunk(params.input, params.output, size);
    }
  }

  @Override
  protected void eofCheck(Object context) throws DataFilterException {
    WAVFilterContext ctx = (WAVFilterContext) context;
    if (!ctx.hasfmt || !ctx.hasdata) {
      throw new DataFilterException(
          l10n("invalidTitle"),
          l10n("invalidTitle"),
          "WAV file is missing fmt chunk or data chunk");
    }
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("WAVFilter." + key);
  }
}
