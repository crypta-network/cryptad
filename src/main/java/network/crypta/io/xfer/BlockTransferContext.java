package network.crypta.io.xfer;

import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.MessageCore;
import network.crypta.io.comm.PeerContext;
import network.crypta.support.Ticker;

public record BlockTransferContext(
    MessageCore messageCore,
    Ticker ticker,
    PeerContext peer,
    long uid,
    PartiallyReceivedBlock block,
    ByteCounter byteCounter,
    boolean realTime) {}
