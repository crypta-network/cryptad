package network.crypta.support;

import static org.junit.Assert.*;

import network.crypta.support.SizeUtil;
import org.junit.Test;

/**
 * Test case for {@link SizeUtil} class.
 *
 * @author Alberto Bacchelli &lt;sback@freenetproject.org&gt;
 */
public class SizeUtilTest {

    @Test
    public void testFormatSizeLong() {
        Long methodLong;
        methodLong = Long.valueOf(valAndExpected[0][0]);
        assertEquals(SizeUtil.formatSize(methodLong), "1 " + valAndExpected[0][1]);

        for (int i = 1; i < valAndExpected.length; i++) {
            methodLong = Long.valueOf(valAndExpected[i][0]);
            assertEquals(SizeUtil.formatSize(methodLong), "1.0 " + valAndExpected[i][1]);
        }
    }

    /**
     * Tests if formatSize(long) method works correctly with intermediate values (i.e. 1/4,1/2,3/4)
     */
    @Test
    public void testFormatSizeLong_WithIntermediateValues() {
        Long methodLong;
        String[] actualValue = {"1.0", "1.25", "1.5", "1.75"};

        for (int i = 1; i < valAndExpected.length; i++) {
            methodLong = Long.valueOf(valAndExpected[i][0]);
			for (int j = 0; j < 4; j++) {
				assertEquals(SizeUtil.formatSize(methodLong + (methodLong * j / 4)),
							 actualValue[j] + " " + valAndExpected[i][1]);
			}
        }
    }
    String[][] valAndExpected = {
        //one byte
        {"1", "B"},
        //one kilobyte
        {"1024", "KiB"},
        //one megabyte
        {"1048576", "MiB"},
        //one gigabyte
        {"1073741824", "GiB"},
        //one terabyte
        {"1099511627776", "TiB"},
        //one petabyte
        //{"1125899906842624","1.0 PiB"},
        //one exabyte
        //{"1152921504606846976", "1.0 EiB"},
        //one zettabyte
        //{"1180591620717411303424", "1.0 ZiB"},
        //one yottabyte
        //{"1208925819614629174706176","1.0 YiB"},
    };

}
