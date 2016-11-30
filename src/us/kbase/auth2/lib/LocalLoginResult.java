package us.kbase.auth2.lib;

import us.kbase.auth2.lib.token.NewToken;

public class LocalLoginResult {

	//TODO TEST
	//TODO JAVADOC
	
	private final UserName userName;
	private final NewToken token;
	
	public LocalLoginResult(final UserName userName) {
		if (userName == null) {
			throw new NullPointerException("userName");
		}
		this.userName = userName;
		token = null;
	}
	
	public LocalLoginResult(final NewToken token) {
		if (token == null) {
			throw new NullPointerException("token");
		}
		userName = null;
		this.token = token;
	}

	public boolean isPwdResetRequired() {
		return token == null;
	}

	public NewToken getToken() {
		if (token == null) {
			throw new IllegalStateException("no token");
		}
		return token;
	}
	
	public UserName getUserName() {
		if (userName == null) {
			throw new IllegalStateException("no username");
		}
		return userName;
	}
}
