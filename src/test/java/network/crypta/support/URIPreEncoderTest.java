package network.crypta.support;

import network.crypta.test.UTFUtil;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

/**
 * Test case for {@link URIPreEncoder} class
 *
 * @author Alberto Bacchelli &lt;sback@freenetproject.org&gt;
 */
public class URIPreEncoderTest {

    public static final String allChars = new String(UTFUtil.ALL_CHARACTERS);

    /**
     * Tests encode(String) method to verify if it converts all not safe chars into safe chars.
     */
    @Test
    public void testEncode() {
        String toEncode = prtblAscii + stressedUTF_8Chars;
        String encoded = URIPreEncoder.encode(toEncode);
        assertTrue(containsOnlyValidChars(encoded));

        encoded = URIPreEncoder.encode(allChars);
        assertTrue(containsOnlyValidChars(encoded));
    }

    /**
     * Tests encodeURI(String) method to verify if it converts all not safe chars into safe chars.
     */
    @Test
    public void testEncodeURI() {
        //String toEncode = prtblAscii+stressedUTF_8Chars;
        //URI encoded;
        //try {
        //	encoded = URIPreEncoder.encodeURI(toEncode);		this method will throw a not expected
        //	exception because '%' is included as a valid char
        //	assertTrue(containsOnlyValidChars(encoded.toString()));
        //} catch (URISyntaxException anException) {
        //	fail("Not expected exception thrown : " + anException.getMessage()); }
    }

    private boolean containsOnlyValidChars(String aString) {
        char eachChar;
        for (int i = 0; i < aString.length(); i++) {
            eachChar = aString.charAt(i);
            if (URIPreEncoder.allowedChars.indexOf(eachChar) < 0) {
                return false;
            }
        }
        return true;
    }

    private final String prtblAscii = new String(UTFUtil.PRINTABLE_ASCII);
    private final String stressedUTF_8Chars = new String(UTFUtil.STRESSED_UTF);

}
