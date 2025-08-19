package network.crypta.clients.fcp;

import network.crypta.node.RequestClient;

public record FCPClientRequestClient(PersistentRequestClient client, boolean forever,
                                     boolean realTimeFlag) implements RequestClient {

    @Override
    public boolean persistent() {
        return forever;
    }
}
