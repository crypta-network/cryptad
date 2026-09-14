package network.crypta.platform.devtools.fixtures;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import network.crypta.platform.appdist.AppBundlePackager;
import network.crypta.platform.appdist.AppBundleSigner;
import network.crypta.platform.devtools.CryptaAppCli;
import network.crypta.platform.trustgraph.TrustDocumentTypes;
import network.crypta.platform.trustgraph.TrustIssuer;
import network.crypta.platform.trustgraph.TrustSignatureEnvelope;
import network.crypta.platform.trustgraph.TrustStatementCanonicalizer;
import network.crypta.platform.trustgraph.TrustStatementDocument;
import network.crypta.platform.trustgraph.TrustStatementFingerprint;
import network.crypta.platform.trustgraph.TrustStatementPayload;
import network.crypta.platform.trustgraph.TrustSubject;
import network.crypta.platform.trustgraph.TrustSubjectKind;
import picocli.CommandLine;

/** Creates signed disposable experimental apps and native signed synthetic trust documents. */
public final class Pr309SignedBudgetFixture {
  private Pr309SignedBudgetFixture() {}

  static void main(String[] args) throws Exception {
    Path root = Path.of(args[0]);
    Files.createDirectories(root);
    var publisher = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Files.writeString(
        root.resolve("publisher-keys.properties"),
        "trusted.keys.version=1\nkey.0.id=synthetic-budget\nkey.0.algorithm=Ed25519\n"
            + "key.0.public.key.base64="
            + Base64.getEncoder().encodeToString(publisher.getPublic().getEncoded())
            + "\n");
    for (String id :
        List.of("feed-reader", "budget-importer", "budget-no-trust", "budget-no-fetch")) {
      Path app = root.resolve(id);
      var output = new StringWriter();
      var command = new CommandLine(new CryptaAppCli());
      command.setOut(new PrintWriter(output));
      command.setErr(new PrintWriter(output));
      int result =
          command.execute(
              "init",
              "--dir",
              app.toString(),
              "--app-id",
              id,
              "--name",
              "Synthetic budget subject",
              "--version",
              "1",
              "--permission",
              "content.fetch");
      if (result != 0) throw new IllegalStateException("budget-fixture-init-failed");
      Files.writeString(app.resolve("bin/start.sh"), "#!/bin/sh\nset -eu\nexec sleep 600\n");
      Path manifest = app.resolve("cryptad-app.properties");
      String permissions =
          id.equals("budget-no-fetch")
              ? "trust.read,trust.write"
              : id.equals("budget-no-trust")
                  ? "content.fetch"
                  : "content.fetch,content.subscribe,trust.read,trust.write";
      String text =
          Files.readString(manifest)
              .replace("sandbox.mode=none", "sandbox.mode=restricted-process")
              .replace("sandbox.required=false", "sandbox.required=true")
              .replace("api.targetStability=stable", "api.targetStability=experimental")
              .replace(
                  "api.experimentalCapabilitiesAccepted=false",
                  "api.experimentalCapabilitiesAccepted=true");
      text = text.replaceAll("(?m)^app\\.permissions=.*$", "app.permissions=" + permissions);
      Files.writeString(manifest, text);
      AppBundleSigner.sign(app, "synthetic-budget", publisher.getPrivate());
      AppBundlePackager.packageBundle(app, root.resolve(id + ".zip"));
    }
    var signerKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    TrustIssuer issuer =
        new TrustIssuer(
            "PR309_PRIVATE_ISSUER_CANARY",
            TrustStatementFingerprint.sha256Hex(signerKey.getPublic().getEncoded()),
            Base64.getEncoder().encodeToString(signerKey.getPublic().getEncoded()),
            null);
    TrustStatementPayload payload =
        new TrustStatementPayload(
            issuer,
            new TrustSubject(
                TrustSubjectKind.PROFILE, "USK@synthetic/pr309-private-subject/0", null),
            "profile",
            50,
            80,
            "PR309_PRIVATE_BODY_CANARY",
            List.of("synthetic"),
            Instant.now().minusSeconds(60),
            null);
    Signature signer = Signature.getInstance("Ed25519");
    signer.initSign(signerKey.getPrivate());
    signer.update(TrustStatementCanonicalizer.canonicalPayloadBytes(payload));
    var document =
        new TrustStatementDocument(
            TrustDocumentTypes.TRUST_STATEMENT_V1,
            payload,
            new TrustSignatureEnvelope(
                TrustDocumentTypes.APP_VAULT_ED25519_PREVIEW_ALGORITHM,
                TrustDocumentTypes.TRUST_STATEMENT_V1,
                Base64.getEncoder().encodeToString(signer.sign())));
    Files.writeString(
        root.resolve("statement.json"), PlatformApiJsonWriter.write(document.toJson()));
  }
}
