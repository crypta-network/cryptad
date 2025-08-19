package network.crypta.client.events;

import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;

/**
 * Event indicating that we are attempting to compress the file.
 */
public record StartedCompressionEvent(COMPRESSOR_TYPE codec) implements ClientEvent {

    static final int code = 0x08;

    @Override
    public String getDescription() {
        return "Started compression attempt with " + codec.name;
    }

    @Override
    public int getCode() {
        return code;
    }
}
