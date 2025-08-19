package network.crypta.client.events;

public record ExpectedMIMEEvent(String expectedMIMEType) implements ClientEvent {

    static final int CODE = 0x0B;

    @Override
    public int getCode() {
        return CODE;
    }

    @Override
    public String getDescription() {
        return "Expected MIME type: " + expectedMIMEType;
    }
}
