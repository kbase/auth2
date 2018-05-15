package us.kbase.auth2.service.ui;

import static us.kbase.auth2.lib.Utils.nonNull;

import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.StoredToken;

public class NewUIToken extends UIToken {

	//TODO JAVADOC or swagger
	
	private final String token;
	
	public NewUIToken(final NewToken token) {
		super(getStoredToken(token));
		this.token = token.getToken();
	}

	private static StoredToken getStoredToken(final NewToken token) {
		nonNull(token, "token");
		return token.getStoredToken();
	}

	public String getToken() {
		return token;
	}
}
