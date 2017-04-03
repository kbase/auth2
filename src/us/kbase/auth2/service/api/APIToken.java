package us.kbase.auth2.service.api;

import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.service.common.ExternalToken;

public class APIToken extends ExternalToken {

	//TODO TEST
	//TODO JAVADOC
	
	private final long cachefor;
	
	public APIToken(final StoredToken token, final long tokenCacheTimeMillis) {
		super(token);
		cachefor = tokenCacheTimeMillis;
	}

	public long getCachefor() {
		return cachefor;
	}
}
