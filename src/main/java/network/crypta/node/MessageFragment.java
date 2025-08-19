package network.crypta.node;

record MessageFragment(boolean shortMessage, boolean isFragmented, boolean firstFragment, int messageID,
                       int fragmentLength, int messageLength, int fragmentOffset, byte[] fragmentData,
                       MessageWrapper wrapper) {

    public int length() {
        return 2 // Message id + flags
                + (shortMessage ? 1 : 2) // Fragment length
                + (isFragmented ? (shortMessage ? 1 : 2) : 0) // Fragment offset or message length
                + fragmentData.length;
    }

    @Override
    public String toString() {
        return "Fragment from message "
                + messageID
                + ": offset "
                + fragmentOffset
                + ", data length "
                + fragmentData.length;
    }
}
