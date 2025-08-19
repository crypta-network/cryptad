package network.crypta.client.events;

/**
 * @param codec          Codec, -1 = uncompressed
 * @param originalSize   Original size
 * @param compressedSize Compressed size
 */
public record FinishedCompressionEvent(int codec, long originalSize, long compressedSize) implements ClientEvent {

    static final int code = 0x09;

    @Override
    public String getDescription() {
        return "Compressed data: codec="
                + codec
                + ", origSize="
                + originalSize
                + ", compressedSize="
                + compressedSize;
    }

    @Override
    public int getCode() {
        return code;
    }
}
