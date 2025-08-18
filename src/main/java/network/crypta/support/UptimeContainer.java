package network.crypta.support;

import java.io.Serial;
import java.io.Serializable;

/**
 * Contains uptime statistics.
 *
 * @author Artefact2
 */
public class UptimeContainer implements Serializable {
	@Serial private static final long serialVersionUID = 1L;
    public long creationTime = 0;
	public long totalUptime = 0;

	@Override
	public boolean equals(Object o) {
		if(o == null) return false;
	if(o.getClass() == UptimeContainer.class) {
		UptimeContainer oB = (UptimeContainer) o;
		return (oB.creationTime == this.creationTime) &&
			(oB.totalUptime == this.totalUptime);
		} else return false;
	}

	@Override
	public int hashCode() {
		int hash = 7;
		hash = 29 * hash + (int) (this.creationTime ^ (this.creationTime >>> 32));
		hash = 29 * hash + (int) (this.totalUptime ^ (this.totalUptime >>> 32));
		return hash;
	}

    public void addFrom(UptimeContainer latestUptime) {
        this.creationTime = latestUptime.creationTime;
        this.totalUptime += latestUptime.totalUptime;
    }
}
