package us.kbase.auth2.service.common;

import us.kbase.auth2.lib.token.NewToken;

public class NewExternalToken extends ExternalToken {

	private final String token;
	
	//TODO TEST
	//TODO JAVADOC
	
	public NewExternalToken(final NewToken token) {
		super(token.getStoredToken().getTokenType(),
				token.getStoredToken().getTokenName(),
				token.getStoredToken().getId(),
				token.getStoredToken().getUserName(),
				token.getStoredToken().getCreationDate(),
				token.getStoredToken().getExpirationDate());
		this.token = token.getToken();
	}

	public String getToken() {
		return token;
	}
}
