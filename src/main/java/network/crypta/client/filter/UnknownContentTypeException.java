package network.crypta.client.filter;

import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLEncoder;

import java.io.Serial;

public class UnknownContentTypeException extends UnsafeContentTypeException {
	@Serial private static final long serialVersionUID = -1;
	final String type;
	final String encodedType;
	
	public UnknownContentTypeException(String typeName) {
		this.type = typeName;
		encodedType = HTMLEncoder.encode(type);
	}
	
	public String getType() {
		return type;
	}

	@Override
	public String getHTMLEncodedTitle() {
		return l10n("title", "type", encodedType);
	}

	@Override
	public String getRawTitle() {
		return l10n("title", "type", type);
	}
	
	@Override
	public String getMessage() {
		return l10n("explanation", "type", type);
	}

	private static String l10n(String key, String pattern, String value) {
		return NodeL10n.getBase().getString("UnknownContentTypeException."+key, pattern, value);
	}

	@Override
	public FetchExceptionMode getFetchErrorCode() {
		return FetchExceptionMode.CONTENT_VALIDATION_UNKNOWN_MIME;
	}
}
