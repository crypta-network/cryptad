package network.crypta.node;

/*
 * A simple interface used to tell the node that a time skew has been detected
 * and that it should complain loudly to the user about it.
 *
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 */
public interface TimeSkewDetectorCallback {
  void setTimeSkewDetectedUserAlert();
}
