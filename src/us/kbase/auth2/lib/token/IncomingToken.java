package us.kbase.auth2.lib.token;

import static us.kbase.auth2.lib.Utils.checkString;

import us.kbase.auth2.lib.exceptions.MissingParameterException;

public class IncomingToken {
	
	//TODO TEST
	//TODO JAVADOC
	
	private final String token;

	public IncomingToken(final String token) throws MissingParameterException {
		checkString(token, "token");
		this.token = token.trim();
	}

	public String getToken() {
		return token;
	}
	
	public IncomingHashedToken getHashedToken() {
		return new IncomingHashedToken(HashedToken.hash(token));
	}
}
