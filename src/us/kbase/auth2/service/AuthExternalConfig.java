package us.kbase.auth2.service;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import us.kbase.auth2.lib.ExternalConfig;
import us.kbase.auth2.lib.ExternalConfigMapper;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;

public class AuthExternalConfig implements ExternalConfig {

	/* might want to have separate current config state classes and config
	 * change classes. Try with the conflated semantics for now.
	 */
	
	//TODO TEST
	//TODO JAVADOC
	
	public static final ExternalConfig DEFAULT =
			new AuthExternalConfig(null, false, false);
	
	private final static String TRUE = "true";
	private final static String FALSE = "false";
	
	private final URL allowedRedirectPrefix;
	private final Boolean ignoreIPHeaders;
	private final Boolean includeStackTraceInResponse;
	
	public AuthExternalConfig(
			final URL allowedRedirectPrefix,
			final Boolean ignoreIPHeaders,
			final Boolean includeStackTraceInResponse) {
		// nulls indicate no value or no change depending on context
		this.allowedRedirectPrefix = allowedRedirectPrefix; //null ok
		this.ignoreIPHeaders = ignoreIPHeaders;
		this.includeStackTraceInResponse = includeStackTraceInResponse;
	}

	public URL getAllowedRedirectPrefix() {
		return allowedRedirectPrefix;
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
		ret.put("allowedRedirectPrefix", allowedRedirectPrefix == null ?
				null : allowedRedirectPrefix.toString());
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

	public static class AuthExternalConfigMapper implements
			ExternalConfigMapper {

		@Override
		public ExternalConfig fromMap(final Map<String, String> config)
				throws ExternalConfigMappingException {
			final String url = config.get("allowedRedirectPrefix");
			final URL allowed;
			if (url == null) {
				allowed = null;
			} else {
				try {
					allowed = new URL(url);
				} catch (MalformedURLException e) {
					throw new ExternalConfigMappingException(
							"Bad allowed redirect prefix URL: " +
							e.getMessage(), e);
				}
			}
			
			final boolean ignoreIPs = getBoolean(config, "ignoreIPHeaders");
			final boolean includeStack = getBoolean(
					config, "includeStackTraceInResponse");
			return new AuthExternalConfig(allowed, ignoreIPs, includeStack);
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
