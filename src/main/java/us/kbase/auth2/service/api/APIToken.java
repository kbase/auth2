package us.kbase.auth2.service.api;

import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.identity.MfaStatus;
import us.kbase.auth2.service.common.ExternalToken;

public class APIToken extends ExternalToken {

	//TODO JAVADOC or swagger
	
	private final long cachefor;
	private final MfaStatus mfa;
	
	public APIToken(final StoredToken token, final long tokenCacheTimeMillis) {
		super(token);
		cachefor = tokenCacheTimeMillis;
		mfa = token.getMfa();
	}

	public long getCachefor() {
		return cachefor;
	}
	
	/**
	 * Gets the MFA authentication status for this token.
	 * 
	 * @return the MFA authentication status.
	 */
	public MfaStatus getMfa() {
		return mfa;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + (int) (cachefor ^ (cachefor >>> 32));
		result = prime * result + ((mfa == null) ? 0 : mfa.name().hashCode());
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
		if (mfa == null) {
			if (other.mfa != null) {
				return false;
			}
		} else if (!mfa.equals(other.mfa)) {
			return false;
		}
		return true;
	}
	
	
}
