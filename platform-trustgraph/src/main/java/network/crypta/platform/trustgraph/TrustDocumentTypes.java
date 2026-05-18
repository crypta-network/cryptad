package network.crypta.platform.trustgraph;

/**
 * Constants for public Trust Graph Preview document identifiers.
 *
 * <p>The values in this class are part of the preview app/platform contract. They are reused by the
 * parser, AppVault signing route, SDK publishing helper, and catalog/release evidence checks so the
 * document type, MIME type, target filename, and signature algorithm label stay aligned.
 */
public final class TrustDocumentTypes {
  /**
   * Public trust statement document type and signing domain.
   *
   * <p>The canonical signed byte sequence begins with this value followed by a newline and the
   * canonical payload JSON.
   */
  public static final String TRUST_STATEMENT_V1 = "crypta.trust.statement.v1";

  /**
   * Content type used when publishing trust statements as app-generated documents.
   *
   * <p>Reference apps use this MIME type for generated-document inserts so downstream import tools
   * can distinguish trust statements from profile, feed, or generic JSON content.
   */
  public static final String TRUST_STATEMENT_CONTENT_TYPE = "application/vnd.crypta.trust+json";

  /**
   * Default target filename for generated trust statement inserts.
   *
   * <p>The SDK helper uses this name unless a future contract explicitly broadens the allowed trust
   * statement publication shape.
   */
  @SuppressWarnings("unused")
  public static final String TRUST_STATEMENT_FILENAME = "trust.json";

  /**
   * Signature algorithm label used by the bounded AppVault preview signing route.
   *
   * <p>The label identifies AppVault-produced Ed25519 preview signatures. It is intentionally more
   * specific than {@code Ed25519} so readers do not confuse it with generic arbitrary identity use.
   */
  public static final String APP_VAULT_ED25519_PREVIEW_ALGORITHM = "app-vault-ed25519-preview";

  private TrustDocumentTypes() {}
}
