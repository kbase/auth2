package us.kbase.auth2.service;

/* for configuration items that need to be accessible to the API classes but need not be
 * stored in the db
 */
public class AuthAPIStaticConfig {
	
	//TODO JAVADOC
	//TODO TEST
	
	private final String cookieName;
	private final String environmentHeaderName;

	public AuthAPIStaticConfig(final String tokenCookieName, final String environmentHeader) {
		if (tokenCookieName == null || tokenCookieName.trim().isEmpty()) {
			throw new IllegalArgumentException("tokenCookieName cannot be null or empty");
		}
		if (environmentHeader == null || environmentHeader.trim().isEmpty()) {
			throw new IllegalArgumentException("environmentHeader cannot be null or empty");
		}
		this.cookieName = tokenCookieName;
		this.environmentHeaderName = environmentHeader;
	}

	public String getTokenCookieName() {
		return cookieName;
	}

	public String getEnvironmentHeaderName() {
		return environmentHeaderName;
	}
}
