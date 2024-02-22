package us.kbase.auth2.service.api;

import us.kbase.auth2.lib.token.NewToken;

public class NewAPIToken extends APIToken {

	//TODO JAVADOC or swagger

	private final String token;
	
	public NewAPIToken(final NewToken token, final long tokenCacheTimeMillis) {
		super(token.getStoredToken(), tokenCacheTimeMillis);
		this.token = token.getToken();
	}

	public String getToken() {
		return token;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((token == null) ? 0 : token.hashCode());
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
		NewAPIToken other = (NewAPIToken) obj;
		if (token == null) {
			if (other.token != null) {
				return false;
			}
		} else if (!token.equals(other.token)) {
			return false;
		}
		return true;
	}
}
