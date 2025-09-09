package us.kbase.auth2.service.api;

import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.service.common.ExternalToken;

public class APIToken extends ExternalToken {

	//TODO JAVADOC or swagger
	
	private final long cachefor;
	
	public APIToken(final StoredToken token, final long tokenCacheTimeMillis) {
		super(token);
		cachefor = tokenCacheTimeMillis;
	}

	public long getCachefor() {
		return cachefor;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + (int) (cachefor ^ (cachefor >>> 32));
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj)) {
			return false;
		}
		APIToken other = (APIToken) obj;
		if (cachefor != other.cachefor) {
			return false;
		}
		return true;
	}
	
	
}
