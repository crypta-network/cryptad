package network.crypta.platform.devtools.fixtures;

import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.platform.trustgraph.TrustStatementParser;
import network.crypta.platform.trustgraph.TrustStatementVerifier;

/** Verifies one bounded PR-317 synthetic statement through the production parser and verifier. */
public final class Pr317SignedBudgetStatementVerifier {
  private Pr317SignedBudgetStatementVerifier() {}

  /**
   * Parses and cryptographically verifies the selected statement without printing its content.
   *
   * @param args exactly one statement path selected by the fixture preparer
   * @throws Exception when the file cannot be read, parsed, or cryptographically verified
   */
  static void main(String[] args) throws Exception {
    if (args.length != 1) throw new IllegalArgumentException("statement path required");
    var document = TrustStatementParser.parse(Files.readString(Path.of(args[0])));
    if (!TrustStatementVerifier.isSignatureVerified(document)) {
      throw new IllegalArgumentException("statement signature invalid");
    }
  }
}
