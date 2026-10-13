package network.crypta.platform.devtools.fixtures;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import network.crypta.platform.trustgraph.TrustStatementFingerprint;
import network.crypta.platform.trustgraph.TrustStatementParser;
import network.crypta.platform.trustgraph.TrustStatementVerifier;

/** Verifies one bounded synthetic budget statement through the production parser and verifier. */
public final class Pr317SignedBudgetStatementVerifier {
  private Pr317SignedBudgetStatementVerifier() {}

  /**
   * Parses and cryptographically verifies the selected statement. When a second path is supplied,
   * writes only its document fingerprint to a newly created private helper output.
   *
   * @param args exactly one statement path selected by the fixture preparer
   * @throws Exception when the file cannot be read, parsed, or cryptographically verified
   */
  static void main(String[] args) throws Exception {
    if (args.length < 1 || args.length > 2) {
      throw new IllegalArgumentException("statement path and optional fingerprint path required");
    }
    var document = TrustStatementParser.parse(Files.readString(Path.of(args[0])));
    if (!TrustStatementVerifier.isSignatureVerified(document)) {
      throw new IllegalArgumentException("statement signature invalid");
    }
    if (args.length == 2) {
      Files.writeString(
          Path.of(args[1]),
          TrustStatementFingerprint.documentFingerprint(document),
          StandardOpenOption.CREATE_NEW,
          StandardOpenOption.WRITE);
    }
  }
}
