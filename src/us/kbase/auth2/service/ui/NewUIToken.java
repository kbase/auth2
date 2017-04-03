package us.kbase.auth2.service.ui;

import us.kbase.auth2.lib.token.NewToken;

public class NewUIToken extends UIToken {

	//TODO TEST
	//TODO JAVADOC
	
	private final String token;
	
	public NewUIToken(final NewToken token) {
		super(token.getStoredToken());
		this.token = token.getToken();
	}

	public String getToken() {
		return token;
	}
}
