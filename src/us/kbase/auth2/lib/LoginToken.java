package us.kbase.auth2.lib;

import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.TemporaryToken;

public class LoginToken {

	//TODO TEST
	//TODO JAVADOC
	private final NewToken token;
	private final TemporaryToken temporaryToken;
	
	public LoginToken(final TemporaryToken token) {
		if (token == null) {
			throw new NullPointerException("token");
		}
		this.temporaryToken = token;
		this.token = null;
	}
	
	public LoginToken(final NewToken token) {
		if (token == null) {
			throw new NullPointerException("token");
		}
		this.temporaryToken = null;
		this.token = token;
	}

	public boolean isLoggedIn() {
		return token != null;
	}
	
	public NewToken getToken() {
		return token;
	}
	
	public TemporaryToken getTemporaryToken() {
		return temporaryToken;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("LoginResult [token=");
		builder.append(token);
		builder.append(", temporaryToken=");
		builder.append(temporaryToken);
		builder.append("]");
		return builder.toString();
	}
}
