package network.crypta.platform.trustgraph;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Parser for the bounded {@code crypta.trust.statement.v1} JSON document format.
 *
 * <p>The parser converts raw imported or pasted JSON into the typed trust statement model. It is
 * intentionally strict: unknown fields, duplicate JSON object members, unsupported subject kinds,
 * invalid contexts, out-of-range scores, and oversized documents all fail before storage or
 * scoring. This keeps canonicalization deterministic and prevents different JSON consumers from
 * interpreting different members of the same document.
 *
 * <p>Parsing validates shape and bounds only. Local signature verification is performed by {@link
 * TrustStatementVerifier} during import so callers can retain unverified documents as
 * non-contributing evidence.
 */
public final class TrustStatementParser {
  private static final String OBJECT_DOCUMENT = "document";
  private static final String FIELD_TYPE = "type";
  private static final String FIELD_PAYLOAD = "payload";
  private static final String FIELD_SIGNATURE = "signature";
  private static final String FIELD_ISSUER = "issuer";
  private static final String FIELD_SUBJECT = "subject";
  private static final String FIELD_CONTEXT = "context";
  private static final String FIELD_SCORE = "score";
  private static final String FIELD_CONFIDENCE = "confidence";
  private static final String FIELD_REASON = "reason";
  private static final String FIELD_TAGS = "tags";
  private static final String FIELD_ISSUED_AT = "issuedAt";
  private static final String FIELD_EXPIRES_AT = "expiresAt";
  private static final String FIELD_IDENTITY_ID = "identityId";
  private static final String FIELD_PUBLIC_KEY_FINGERPRINT = "publicKeyFingerprint";
  private static final String FIELD_PUBLIC_KEY_BASE64 = "publicKeyBase64";
  private static final String FIELD_PROFILE_URI = "profileUri";
  private static final String FIELD_KIND = "kind";
  private static final String FIELD_URI = "uri";
  private static final String FIELD_FINGERPRINT = "fingerprint";
  private static final String FIELD_ALGORITHM = "algorithm";
  private static final String FIELD_DOMAIN = "domain";
  private static final String FIELD_VALUE = "value";
  private static final String FIELD_MESSAGE_PREFIX = "Field '";
  private static final String PAYLOAD_ISSUER = FIELD_PAYLOAD + "." + FIELD_ISSUER;
  private static final String PAYLOAD_SUBJECT = FIELD_PAYLOAD + "." + FIELD_SUBJECT;
  private static final String ISSUER_IDENTITY_ID = FIELD_ISSUER + "." + FIELD_IDENTITY_ID;
  private static final String ISSUER_PUBLIC_KEY_FINGERPRINT =
      FIELD_ISSUER + "." + FIELD_PUBLIC_KEY_FINGERPRINT;
  private static final String ISSUER_PUBLIC_KEY_BASE64 =
      FIELD_ISSUER + "." + FIELD_PUBLIC_KEY_BASE64;
  private static final String ISSUER_PROFILE_URI = FIELD_ISSUER + "." + FIELD_PROFILE_URI;
  private static final String SUBJECT_KIND = FIELD_SUBJECT + "." + FIELD_KIND;
  private static final String SUBJECT_URI = FIELD_SUBJECT + "." + FIELD_URI;
  private static final String SUBJECT_FINGERPRINT = FIELD_SUBJECT + "." + FIELD_FINGERPRINT;
  private static final String SIGNATURE_ALGORITHM = FIELD_SIGNATURE + "." + FIELD_ALGORITHM;
  private static final String SIGNATURE_DOMAIN = FIELD_SIGNATURE + "." + FIELD_DOMAIN;
  private static final String SIGNATURE_VALUE = FIELD_SIGNATURE + "." + FIELD_VALUE;

  private TrustStatementParser() {}

  /**
   * Parses and validates one trust statement JSON document.
   *
   * <p>Unknown object fields are rejected before signing/import. The preview format is
   * intentionally strict so canonicalization has exactly one bounded payload shape.
   *
   * @param documentJson raw JSON document
   * @return validated trust statement
   * @throws TrustGraphException when the document is malformed, unsupported, or outside bounds
   */
  public static TrustStatementDocument parse(String documentJson) {
    if (documentJson == null) {
      throw invalid("Trust statement document is required.");
    }
    byte[] bytes = documentJson.getBytes(StandardCharsets.UTF_8);
    if (bytes.length > TrustStatementValidator.MAX_DOCUMENT_BYTES) {
      throw new TrustGraphException(
          "trust_statement_too_large", "Trust statement document is too large.");
    }
    Object parsed = TrustJson.parse(documentJson);
    Map<String, Object> root = object(parsed, OBJECT_DOCUMENT);
    rejectUnknown(root, OBJECT_DOCUMENT, List.of(FIELD_TYPE, FIELD_PAYLOAD, FIELD_SIGNATURE));
    TrustStatementDocument document =
        new TrustStatementDocument(
            string(root.get(FIELD_TYPE), FIELD_TYPE),
            payload(object(root.get(FIELD_PAYLOAD), FIELD_PAYLOAD)),
            signature(object(root.get(FIELD_SIGNATURE), FIELD_SIGNATURE)));
    return TrustStatementValidator.validate(document);
  }

  private static TrustStatementPayload payload(Map<String, Object> json) {
    rejectUnknown(
        json,
        FIELD_PAYLOAD,
        List.of(
            FIELD_ISSUER,
            FIELD_SUBJECT,
            FIELD_CONTEXT,
            FIELD_SCORE,
            FIELD_CONFIDENCE,
            FIELD_REASON,
            FIELD_TAGS,
            FIELD_ISSUED_AT,
            FIELD_EXPIRES_AT));
    TrustIssuer issuer = issuer(object(json.get(FIELD_ISSUER), PAYLOAD_ISSUER));
    TrustSubject subject = subject(object(json.get(FIELD_SUBJECT), PAYLOAD_SUBJECT));
    Instant issuedAt =
        TrustStatementValidator.parseInstant(FIELD_ISSUED_AT, json.get(FIELD_ISSUED_AT), true);
    Instant expiresAt =
        TrustStatementValidator.parseInstant(FIELD_EXPIRES_AT, json.get(FIELD_EXPIRES_AT), false);
    Object tagsValue = json.get(FIELD_TAGS);
    List<String> tags;
    if (tagsValue == null) {
      tags = List.of();
    } else if (tagsValue instanceof List<?> rawTags) {
      ArrayList<String> parsedTags = new ArrayList<>();
      for (Object rawTag : rawTags) {
        parsedTags.add(string(rawTag, FIELD_TAGS));
      }
      tags = parsedTags;
    } else {
      throw invalid(fieldMessage(FIELD_TAGS, "' must be an array."));
    }
    return new TrustStatementPayload(
        issuer,
        subject,
        string(json.get(FIELD_CONTEXT), FIELD_CONTEXT),
        integer(json.get(FIELD_SCORE), FIELD_SCORE),
        integer(json.get(FIELD_CONFIDENCE), FIELD_CONFIDENCE),
        optionalString(json.get(FIELD_REASON), FIELD_REASON),
        tags,
        issuedAt,
        expiresAt);
  }

  private static TrustIssuer issuer(Map<String, Object> json) {
    rejectUnknown(
        json,
        FIELD_ISSUER,
        List.of(
            FIELD_IDENTITY_ID,
            FIELD_PUBLIC_KEY_FINGERPRINT,
            FIELD_PUBLIC_KEY_BASE64,
            FIELD_PROFILE_URI));
    return new TrustIssuer(
        string(json.get(FIELD_IDENTITY_ID), ISSUER_IDENTITY_ID),
        string(json.get(FIELD_PUBLIC_KEY_FINGERPRINT), ISSUER_PUBLIC_KEY_FINGERPRINT),
        optionalString(json.get(FIELD_PUBLIC_KEY_BASE64), ISSUER_PUBLIC_KEY_BASE64),
        optionalString(json.get(FIELD_PROFILE_URI), ISSUER_PROFILE_URI));
  }

  private static TrustSubject subject(Map<String, Object> json) {
    rejectUnknown(json, FIELD_SUBJECT, List.of(FIELD_KIND, FIELD_URI, FIELD_FINGERPRINT));
    return new TrustSubject(
        TrustSubjectKind.parse(string(json.get(FIELD_KIND), SUBJECT_KIND)),
        string(json.get(FIELD_URI), SUBJECT_URI),
        optionalString(json.get(FIELD_FINGERPRINT), SUBJECT_FINGERPRINT));
  }

  private static TrustSignatureEnvelope signature(Map<String, Object> json) {
    rejectUnknown(json, FIELD_SIGNATURE, List.of(FIELD_ALGORITHM, FIELD_DOMAIN, FIELD_VALUE));
    return new TrustSignatureEnvelope(
        string(json.get(FIELD_ALGORITHM), SIGNATURE_ALGORITHM),
        string(json.get(FIELD_DOMAIN), SIGNATURE_DOMAIN),
        string(json.get(FIELD_VALUE), SIGNATURE_VALUE));
  }

  private static Map<String, Object> object(Object value, String fieldName) {
    if (value instanceof Map<?, ?> map) {
      java.util.LinkedHashMap<String, Object> copy =
          java.util.LinkedHashMap.newLinkedHashMap(map.size());
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        if (!(entry.getKey() instanceof String key)) {
          throw invalid(fieldMessage(fieldName, "' contains a non-string key."));
        }
        copy.put(key, entry.getValue());
      }
      return copy;
    }
    throw invalid(fieldMessage(fieldName, "' must be an object."));
  }

  private static String string(Object value, String fieldName) {
    if (value instanceof String text) {
      if (containsUnsafeControl(text)) {
        throw invalid(fieldMessage(fieldName, "' must not contain control characters."));
      }
      return text;
    }
    throw invalid(fieldMessage(fieldName, "' must be a string."));
  }

  private static String optionalString(Object value, String fieldName) {
    if (value == null) {
      return null;
    }
    return string(value, fieldName);
  }

  private static int integer(Object value, String fieldName) {
    if (value instanceof Integer integer) {
      return integer;
    }
    if (value instanceof Long longValue
        && longValue >= Integer.MIN_VALUE
        && longValue <= Integer.MAX_VALUE) {
      return longValue.intValue();
    }
    throw invalid(fieldMessage(fieldName, "' must be an integer."));
  }

  private static void rejectUnknown(
      Map<String, Object> json, String objectName, List<String> allowedFields) {
    for (String key : json.keySet()) {
      if (!allowedFields.contains(key)) {
        throw invalid("Unknown field '" + objectName + "." + key + "' is not supported.");
      }
    }
  }

  private static String fieldMessage(String fieldName, String suffix) {
    return FIELD_MESSAGE_PREFIX + fieldName + suffix;
  }

  private static TrustGraphException invalid(String message) {
    return new TrustGraphException("invalid_trust_statement", message);
  }

  private static boolean containsUnsafeControl(String value) {
    for (int index = 0; index < value.length(); index++) {
      if (Character.isISOControl(value.charAt(index))) {
        return true;
      }
    }
    return false;
  }
}
