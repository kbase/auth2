package us.kbase.auth2.service.api;

import us.kbase.auth2.lib.token.NewToken;

public class NewAPIToken extends APIToken {

	//TODO TEST
	//TODO JAVADOC

	private final String token;
	
	public NewAPIToken(final NewToken token, final long tokenCacheTimeMillis) {
		super(token.getStoredToken(), tokenCacheTimeMillis);
		this.token = token.getToken();
	}

	public String getToken() {
		return token;
	}
	
}
