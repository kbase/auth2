package us.kbase.auth2.service;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import us.kbase.auth2.lib.config.ExternalConfig;
import us.kbase.auth2.lib.config.ExternalConfigMapper;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;

public class AuthExternalConfig implements ExternalConfig {

	/* might want to have separate current config state classes and config
	 * change classes. Try with the conflated semantics for now.
	 */
	
	//TODO TEST
	//TODO JAVADOC
	
	//TODO CONFIG nulls = no change doesn't work. What if you want to remove the url?
	
	private static final String ALLOWED_POST_LOGIN_REDIRECT_PREFIX =
			"allowedPostLoginRedirectPrefix";
	private static final String COMPLETE_LOGIN_REDIRECT = "completeLoginRedirect";
	private static final String POST_LINK_REDIRECT = "postLinkRedirect";
	private static final String COMPLETE_LINK_REDIRECT = "completeLinkRedirect";

	public static final ExternalConfig DEFAULT;
	public static final ExternalConfig NO_CHANGE;
	
	static {
		try {
			DEFAULT = new AuthExternalConfig(null, null, null, null, false, false);
			NO_CHANGE = new AuthExternalConfig(null, null, null, null, null, null);
		} catch (IllegalParameterException e) {
			throw new RuntimeException("this should be impossible", e);
		}
	}
	
	private final static String TRUE = "true";
	private final static String FALSE = "false";
	
	private final URL allowedPostLoginRedirectPrefix;
	private final URL completeLoginRedirect;
	private final URL postLinkRedirect;
	private final URL completeLinkRedirect;
	private final Boolean ignoreIPHeaders;
	private final Boolean includeStackTraceInResponse;
	
	public AuthExternalConfig(
			final URL allowedPostLoginRedirectPrefix,
			final URL completeLoginRedirect,
			final URL postLinkRedirect,
			final URL completeLinkRedirect,
			final Boolean ignoreIPHeaders,
			final Boolean includeStackTraceInResponse) throws IllegalParameterException {
		// nulls indicate no value or no change depending on context
		checkURI(allowedPostLoginRedirectPrefix);
		this.allowedPostLoginRedirectPrefix = allowedPostLoginRedirectPrefix; //null ok
		checkURI(completeLoginRedirect);
		this.completeLoginRedirect = completeLoginRedirect;
		checkURI(postLinkRedirect);
		this.postLinkRedirect = postLinkRedirect;
		checkURI(completeLinkRedirect);
		this.completeLinkRedirect = completeLinkRedirect;
		this.ignoreIPHeaders = ignoreIPHeaders;
		this.includeStackTraceInResponse = includeStackTraceInResponse;
	}

	private void checkURI(final URL url) throws IllegalParameterException {
		if (url == null) {
			return;
		}
		try {
			url.toURI();
		} catch (URISyntaxException e) {
			throw new IllegalParameterException("Illegal URL " + url + ":" + e.getMessage(), e);
		}
	}

	public URL getAllowedLoginRedirectPrefix() {
		return allowedPostLoginRedirectPrefix;
	}
	
	public URL getCompleteLoginRedirect() {
		return completeLoginRedirect;
	}
	
	public URL getPostLinkRedirect() {
		return postLinkRedirect;
	}
	
	public URL getCompleteLinkRedirect() {
		return completeLinkRedirect;
	}

	public Boolean isIgnoreIPHeaders() {
		return ignoreIPHeaders;
	}

	public Boolean isIncludeStackTraceInResponse() {
		return includeStackTraceInResponse;
	}

	@Override
	public Map<String, String> toMap() {
		final Map<String, String> ret = new HashMap<String, String>();
		ret.put(ALLOWED_POST_LOGIN_REDIRECT_PREFIX, allowedPostLoginRedirectPrefix == null ? null :
			allowedPostLoginRedirectPrefix.toString());
		ret.put(COMPLETE_LOGIN_REDIRECT, completeLoginRedirect == null ? null :
			completeLoginRedirect.toString());
		ret.put(POST_LINK_REDIRECT, postLinkRedirect == null ? null : postLinkRedirect.toString());
		ret.put(COMPLETE_LINK_REDIRECT, completeLinkRedirect == null ? null :
			completeLinkRedirect.toString());
		ret.put("ignoreIPHeaders", getBooleanRepresentation(ignoreIPHeaders));
		ret.put("includeStackTraceInResponse",
				getBooleanRepresentation(includeStackTraceInResponse));
		return ret;
	}
	
	private String getBooleanRepresentation(final Boolean b) {
		if (b == null) {
			return null;
		}
		if (b) {
			return TRUE;
		}
		return FALSE;
	}
	
	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("AuthExternalConfig [allowedPostLoginRedirectPrefix=");
		builder.append(allowedPostLoginRedirectPrefix);
		builder.append(", ignoreIPHeaders=");
		builder.append(ignoreIPHeaders);
		builder.append(", includeStackTraceInResponse=");
		builder.append(includeStackTraceInResponse);
		builder.append("]");
		return builder.toString();
	}


	public static class AuthExternalConfigMapper implements
			ExternalConfigMapper<AuthExternalConfig> {

		@Override
		public AuthExternalConfig fromMap(final Map<String, String> config)
				throws ExternalConfigMappingException {
			final URL allowedPostLogin = getURL(config, ALLOWED_POST_LOGIN_REDIRECT_PREFIX);
			final URL completeLogin = getURL(config, COMPLETE_LOGIN_REDIRECT);
			final URL postLink = getURL(config, POST_LINK_REDIRECT);
			final URL completeLink = getURL(config, COMPLETE_LINK_REDIRECT);
			final boolean ignoreIPs = getBoolean(config, "ignoreIPHeaders");
			final boolean includeStack = getBoolean(config, "includeStackTraceInResponse");
			try {
				return new AuthExternalConfig(allowedPostLogin, completeLogin, postLink,
						completeLink, ignoreIPs, includeStack);
			} catch (IllegalParameterException e) {
				throw new ExternalConfigMappingException(
						"Error in incoming config: " + e.getMessage(), e);
			}
		}

		private URL getURL(final Map<String, String> config, final String key)
				throws ExternalConfigMappingException {
			final String url = config.get(key);
			final URL allowed;
			if (url == null) {
				allowed = null;
			} else {
				try {
					allowed = new URL(url);
					allowed.toURI();
				} catch (MalformedURLException | URISyntaxException e) {
					throw new ExternalConfigMappingException(
							"Bad URL: " + e.getMessage(), e);
				}
			}
			return allowed;
		}

		private boolean getBoolean(
				final Map<String, String> config,
				final String paramName)
				throws ExternalConfigMappingException {
			final String value = config.get(paramName);
			final boolean b;
			if (TRUE.equals(value)) {
				b = true;
			} else if (FALSE.equals(value)) {
				b = false;
			} else {
				throw new ExternalConfigMappingException(String.format(
						"Expected value of %s or %s for parameter %s",
						TRUE, FALSE, paramName));
			}
			return b;
		}
	}

}
