package network.crypta.client.events;

public record ExpectedFileSizeEvent(long expectedSize) implements ClientEvent {

    static final int CODE = 0x0C;

    @Override
    public int getCode() {
        return CODE;
    }

    @Override
    public String getDescription() {
        return "Expected file size: " + expectedSize;
    }
}
