/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package network.crypta.io.comm;

/**
 * Callback interface for async message sending.
 */
public interface AsyncMessageCallback {
    
    /** Called when the packet actually leaves the node.
     * This DOES NOT MEAN that it has been successfully received
     * by the partner node (on a lossy transport).
     */
    void sent();

    /** Called when the packet is actually acknowledged by the
     * other node. This is the end of the transaction. On a
     * non-lossy transport this may be called immediately after
     * sent().
     */
    void acknowledged();

    /** Called if the node is disconnected while the packet is
     * queued, or after it has been sent. Terminal.
     */
    void disconnected();
    
    /** Called if the packet is lost due to an internal error. */
    void fatalError();
}
