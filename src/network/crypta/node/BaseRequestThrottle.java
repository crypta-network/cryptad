/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package network.crypta.node;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.MINUTES;

public interface BaseRequestThrottle {

	long DEFAULT_DELAY = MILLISECONDS.toMillis(200);
	long MAX_DELAY = MINUTES.toMillis(5);
	long MIN_DELAY = MILLISECONDS.toMillis(20);

	/**
	 * Get the current inter-request delay.
	 */
    long getDelay();

}