package us.kbase.auth2.lib;

import us.kbase.auth2.lib.token.TemporaryToken;

public class LinkToken {
	
	//TODO JAVADOC
	//TODO TEST
	
	private final boolean linked;
	private final TemporaryToken token;
	
	public LinkToken() {
		this.linked = true;
		this.token = null;
	}
	
	public LinkToken(final TemporaryToken token) {
		if (token == null) {
			throw new NullPointerException("token");
		}
		this.linked = false;
		this.token = token;
	}

	public boolean isLinked() {
		return linked;
	}

	public TemporaryToken getTemporaryToken() {
		return token;
	}

}
