package network.crypta.client.events;

import network.crypta.support.TimeUtil;

public record EnterFiniteCooldownEvent(long wakeupTime) implements ClientEvent {

    static final int CODE = 0x10;

    @Override
    public String getDescription() {
        return "Wake up in " + TimeUtil.formatTime(wakeupTime - System.currentTimeMillis(), 2, true);
    }

    @Override
    public int getCode() {
        return CODE;
    }
}
