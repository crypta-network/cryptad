package network.crypta.client.events;

import network.crypta.client.InsertContext.CompatibilityMode;

public record SplitfileCompatibilityModeEvent(CompatibilityMode minCompatibilityMode,
                                              CompatibilityMode maxCompatibilityMode, byte[] splitfileCryptoKey,
                                              boolean dontCompress, boolean bottomLayer) implements ClientEvent {

    public static final int CODE = 0x0D;

    @Override
    public int getCode() {
        return CODE;
    }

    @Override
    public String getDescription() {
        return "CompatibilityMode between " + minCompatibilityMode + " and " + maxCompatibilityMode;
    }

}
