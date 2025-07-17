package us.kbase.auth2.service.api;

import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.service.common.ExternalToken;

public class APIToken extends ExternalToken {

	//TODO JAVADOC or swagger
	
	private final long cachefor;
	private final Boolean mfaAuthenticated;
	
	public APIToken(final StoredToken token, final long tokenCacheTimeMillis) {
		super(token);
		cachefor = tokenCacheTimeMillis;
		mfaAuthenticated = token.getMfaAuthenticated();
	}

	public long getCachefor() {
		return cachefor;
	}
	
	/**
	 * Gets the MFA authentication status for this token.
	 * 
	 * @return the MFA authentication status:
	 *         true - User authenticated with MFA during token creation
	 *         false - User explicitly chose not to use MFA when available  
	 *         null - MFA status unknown or not applicable to authentication method
	 */
	public Boolean getMfaAuthenticated() {
		return mfaAuthenticated;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + (int) (cachefor ^ (cachefor >>> 32));
		result = prime * result + ((mfaAuthenticated == null) ? 0 : mfaAuthenticated.hashCode());
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
		if (mfaAuthenticated == null) {
			if (other.mfaAuthenticated != null) {
				return false;
			}
		} else if (!mfaAuthenticated.equals(other.mfaAuthenticated)) {
			return false;
		}
		return true;
	}
	
	
}
