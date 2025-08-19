package network.crypta.client.events;

import network.crypta.crypt.HashResult;

public record ExpectedHashesEvent(HashResult[] hashes) implements ClientEvent {

    public static final int CODE = 0x0E;

    @Override
    public int getCode() {
        return CODE;
    }

    @Override
    public String getDescription() {
        return "Expected hashes";
    }
}
