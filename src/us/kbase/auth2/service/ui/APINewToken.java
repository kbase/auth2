package us.kbase.auth2.service.ui;

import us.kbase.auth2.lib.token.NewToken;

public class APINewToken extends APIToken {

	private final String token;
	
	//TODO TEST
	//TODO JAVADOC
	
	public APINewToken(final NewToken token) {
		super(token.getTokenType(), token.getTokenName(), token.getId(),
				token.getUserName(),
				token.getCreationDate(), token.getExpirationDate());
		this.token = token.getToken();
	}

	public String getToken() {
		return token;
	}
}
