package us.kbase.auth2.lib.token;

import static us.kbase.auth2.lib.Utils.checkString;

public class IncomingToken {
	
	//TODO TEST
	//TODO JAVADOC
	
	private final String token;

	public IncomingToken(final String token) {
		checkString(token, "token", true);
		this.token = token;
	}

	public String getToken() {
		return token;
	}
	
	public IncomingHashedToken getHashedToken() {
		return new IncomingHashedToken(HashedToken.hash(token));
	}
}
