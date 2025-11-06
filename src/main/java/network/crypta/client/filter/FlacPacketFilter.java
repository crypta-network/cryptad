package network.crypta.client.filter;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Arrays;
import network.crypta.client.filter.FlacMetadataBlock.BlockType;
import network.crypta.client.filter.FlacMetadataBlock.FlacMetadataBlockHeader;
import network.crypta.crypt.HashResult;
import network.crypta.crypt.HashType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FlacPacketFilter implements CodecPacketFilter {
  private static final Logger LOG = LoggerFactory.getLogger(FlacPacketFilter.class);

  boolean streamValid = true;

  enum State {
    UNINITIALIZED,
    STREAMINFO_FOUND,
    METADATA_FOUND
  }

  State currentState = State.UNINITIALIZED;

  int minimumBlockSize;
  int maximumBlockSize;
  int minimumFrameSize;
  int maximumFrameSize;
  int sampleRate;
  int channels;
  int bitsPerSample;
  long totalSamples;
  HashResult md5sum;

  public CodecPacket parse(CodecPacket packet) throws IOException {
    if (!streamValid) return null;
    boolean logMINOR = LOG.isDebugEnabled();
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(packet.toArray()));
    switch (currentState) {
      case UNINITIALIZED:
        if (!(packet instanceof FlacMetadataBlock block)
            || block.getMetadataBlockType() != BlockType.STREAMINFO) {
          streamValid = false;
          return null;
        }
        // Transition based on the "last" flag of STREAMINFO
        currentState = block.isLastMetadataBlock() ? State.METADATA_FOUND : State.STREAMINFO_FOUND;
        minimumBlockSize = input.readUnsignedShort();
        maximumBlockSize = input.readUnsignedShort();
        minimumFrameSize = (input.readUnsignedShort() << 8) | input.readUnsignedByte();
        maximumFrameSize = (input.readUnsignedShort() << 8) | input.readUnsignedByte();
        long unaligned =
            input.readLong(); // Is two's complement a problem here? SHould BigInteger be used?
        sampleRate = (int) (unaligned >>> 40);
        channels = (int) (unaligned >>> 37) & 0x06;
        bitsPerSample = (int) (unaligned >>> 32) & 0x1F;
        totalSamples = (unaligned << 28) >>> 28;
        byte[] hash = new byte[4];
        input.readFully(hash);
        md5sum = new HashResult(HashType.MD5, hash);
        break;
      case STREAMINFO_FOUND:
        if (!(packet instanceof FlacMetadataBlock block2)) {
          // Unexpected non-metadata packet before last metadata block; invalidate stream.
          streamValid = false;
          return null;
        }
        if (block2.isLastMetadataBlock()) currentState = State.METADATA_FOUND;
        byte[] payload;
        FlacMetadataBlockHeader header;
        switch (block2.getMetadataBlockType()) {
          case APPLICATION:
            payload = new byte[packet.payload.length];
            Arrays.fill(payload, (byte) 0);
            header = block2.getHeader();
            packet = new FlacMetadataBlock(header.toInt(), payload);
            ((FlacMetadataBlock) packet).setMetadataBlockType(BlockType.PADDING);
            break;
          case VORBIS_COMMENT:
            payload = new byte[packet.payload.length];
            Arrays.fill(payload, (byte) 0);
            header = block2.getHeader();
            packet = new FlacMetadataBlock(header.toInt(), payload);
            ((FlacMetadataBlock) packet).setMetadataBlockType(BlockType.PADDING);
            break;
          case PICTURE:
            payload = new byte[packet.payload.length];
            Arrays.fill(payload, (byte) 0);
            header = block2.getHeader();
            packet = new FlacMetadataBlock(header.toInt(), payload);
            ((FlacMetadataBlock) packet).setMetadataBlockType(BlockType.PADDING);
            break;
        }
        break;
      case METADATA_FOUND:
        // Audio frames and any subsequent packets pass through unchanged.
        break;
    }
    if (packet instanceof FlacMetadataBlock block && logMINOR)
      LOG.debug("Returning packet of type" + block.getMetadataBlockType());
    return packet;
  }
}
