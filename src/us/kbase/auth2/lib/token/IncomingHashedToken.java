package us.kbase.auth2.lib.token;

import static us.kbase.auth2.lib.Utils.checkStringNoCheckedException;

public class IncomingHashedToken {
	
	//TODO TEST
	//TODO JAVADOC

	private final String tokenHash;

	IncomingHashedToken(final String tokenHash) {
		super();
		checkStringNoCheckedException(tokenHash, "token");
		this.tokenHash = tokenHash;
	}

	public String getTokenHash() {
		return tokenHash;
	}

}
