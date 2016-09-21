package us.kbase.auth2.lib.token;

import static us.kbase.auth2.lib.Utils.checkString;

public class IncomingHashedToken {
	
	//TODO TEST
	//TODO JAVADOC

	private final String tokenHash;

	IncomingHashedToken(final String tokenHash) {
		super();
		checkString(tokenHash, "token", true);
		this.tokenHash = tokenHash;
	}

	public String getTokenHash() {
		return tokenHash;
	}

}
