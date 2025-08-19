package network.crypta.io.comm;

import java.io.Serial;

/**
 * Thrown if trying to set a field to a value of the wrong type
 *
 * @author ian
 */
public class IncorrectTypeException extends RuntimeException {

  public static final String VERSION =
      "$Id: IncorrectTypeException.java,v 1.1 2005/01/29 19:12:10 amphibian Exp $";

  @Serial private static final long serialVersionUID = 1L;

  public IncorrectTypeException(String s) {
    super(s);
  }
}
