package us.kbase.auth2.service;

import static us.kbase.auth2.lib.Utils.nonNull;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import us.kbase.auth2.lib.config.ConfigAction;
import us.kbase.auth2.lib.config.ConfigAction.Action;
import us.kbase.auth2.lib.config.ConfigAction.State;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.config.ExternalConfig;
import us.kbase.auth2.lib.config.ExternalConfigMapper;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;

public class AuthExternalConfig<T extends ConfigAction> implements ExternalConfig {

	//TODO TEST
	//TODO JAVADOC
	
	private static final String ALLOWED_POST_LOGIN_REDIRECT_PREFIX =
			"allowedPostLoginRedirectPrefix";
	private static final String COMPLETE_LOGIN_REDIRECT = "completeLoginRedirect";
	private static final String POST_LINK_REDIRECT = "postLinkRedirect";
	private static final String COMPLETE_LINK_REDIRECT = "completeLinkRedirect";
	private static final String IGNORE_IP_HEADERS = "ignoreIPHeaders";
	private static final String INCLUDE_STACK_TRACE_IN_RESPONSE = "includeStackTraceInResponse";

	private static final ConfigItem<URL, Action> MT_URL = ConfigItem.noAction();
	private static final ConfigItem<Boolean, Action> SET_FALSE = ConfigItem.set(false);

	public static final AuthExternalConfig<Action> SET_DEFAULT;
	static {
		try {
			SET_DEFAULT = new AuthExternalConfig<>(
					MT_URL, MT_URL, MT_URL, MT_URL, SET_FALSE, SET_FALSE);
		} catch (IllegalParameterException e) {
			throw new RuntimeException("this should be impossible", e);
		}
	}
	
	private final static String TRUE = "true";
	private final static String FALSE = "false";
	
	private final ConfigItem<URL, T> allowedPostLoginRedirectPrefix;
	private final ConfigItem<URL, T> completeLoginRedirect;
	private final ConfigItem<URL, T> postLinkRedirect;
	private final ConfigItem<URL, T> completeLinkRedirect;
	private final ConfigItem<Boolean, T> ignoreIPHeaders;
	private final ConfigItem<Boolean, T> includeStackTraceInResponse;
	
	public AuthExternalConfig(
			final ConfigItem<URL, T> allowedPostLoginRedirectPrefix,
			final ConfigItem<URL, T> completeLoginRedirect,
			final ConfigItem<URL, T> postLinkRedirect,
			final ConfigItem<URL, T> completeLinkRedirect,
			final ConfigItem<Boolean, T> ignoreIPHeaders,
			final ConfigItem<Boolean, T> includeStackTraceInResponse)
			throws IllegalParameterException {
		// nulls indicate no value or no change depending on context
		nonNull(allowedPostLoginRedirectPrefix, ALLOWED_POST_LOGIN_REDIRECT_PREFIX);
		checkURI(allowedPostLoginRedirectPrefix);
		this.allowedPostLoginRedirectPrefix = allowedPostLoginRedirectPrefix; //null ok
		nonNull(completeLoginRedirect, COMPLETE_LOGIN_REDIRECT);
		checkURI(completeLoginRedirect);
		this.completeLoginRedirect = completeLoginRedirect;
		nonNull(postLinkRedirect, POST_LINK_REDIRECT);
		checkURI(postLinkRedirect);
		this.postLinkRedirect = postLinkRedirect;
		nonNull(completeLinkRedirect, COMPLETE_LINK_REDIRECT);
		checkURI(completeLinkRedirect);
		this.completeLinkRedirect = completeLinkRedirect;
		nonNull(ignoreIPHeaders, IGNORE_IP_HEADERS);
		this.ignoreIPHeaders = ignoreIPHeaders;
		nonNull(includeStackTraceInResponse, INCLUDE_STACK_TRACE_IN_RESPONSE);
		this.includeStackTraceInResponse = includeStackTraceInResponse;
	}

	private void checkURI(final ConfigItem<URL, T> url)
			throws IllegalParameterException {
		if (!url.hasItem()) {
			return;
		}
		try {
			url.getItem().toURI();
		} catch (URISyntaxException e) {
			throw new IllegalParameterException("Illegal URL " + url + ":" + e.getMessage(), e);
		}
	}

	public ConfigItem<URL, T> getAllowedLoginRedirectPrefix() {
		return allowedPostLoginRedirectPrefix;
	}
	
	public ConfigItem<URL, T> getCompleteLoginRedirect() {
		return completeLoginRedirect;
	}
	
	public ConfigItem<URL, T> getPostLinkRedirect() {
		return postLinkRedirect;
	}
	
	public ConfigItem<URL, T> getCompleteLinkRedirect() {
		return completeLinkRedirect;
	}

	public ConfigItem<Boolean, T> isIgnoreIPHeaders() {
		return ignoreIPHeaders;
	}
	
	public boolean isIgnoreIPHeadersOrDefault() {
		if (ignoreIPHeaders.getAction().isState() && ignoreIPHeaders.hasItem()) {
			return ignoreIPHeaders.getItem();
		}
		return SET_DEFAULT.isIgnoreIPHeaders().getItem();
	}

	public ConfigItem<Boolean, T> isIncludeStackTraceInResponse() {
		return includeStackTraceInResponse;
	}
	
	public boolean isIncludeStackTraceInResponseOrDefault() {
		if (includeStackTraceInResponse.getAction().isState() &&
				includeStackTraceInResponse.hasItem()) {
			return includeStackTraceInResponse.getItem();
		}
		return SET_DEFAULT.isIncludeStackTraceInResponse().getItem();
	}

	@Override
	public Map<String, ConfigItem<String, Action>> toMap() {
		final Map<String, ConfigItem<String, Action>> ret = new HashMap<>();
		processURL(ret, ALLOWED_POST_LOGIN_REDIRECT_PREFIX, allowedPostLoginRedirectPrefix);
		processURL(ret, COMPLETE_LOGIN_REDIRECT, completeLoginRedirect);
		processURL(ret, POST_LINK_REDIRECT, postLinkRedirect);
		processURL(ret, COMPLETE_LINK_REDIRECT, completeLinkRedirect);
		processBool(ret, IGNORE_IP_HEADERS, ignoreIPHeaders);
		processBool(ret, INCLUDE_STACK_TRACE_IN_RESPONSE, includeStackTraceInResponse);
		return ret;
	}
	

	private void processBool(
			final Map<String, ConfigItem<String, Action>> ret,
			final String key,
			final ConfigItem<Boolean, T> bool) {
		if (bool.getAction().isRemove()) {
			ret.put(key, ConfigItem.remove());
		} else if (bool.getAction().isSet()) {
			ret.put(key, ConfigItem.set(bool.getItem() ? TRUE : FALSE));
		}
		// otherwise do nothing
	}

	private void processURL(
			final Map<String, ConfigItem<String, Action>> ret,
			final String key,
			final ConfigItem<URL, T> url) {
		if (url.getAction().isRemove()) {
			ret.put(key, ConfigItem.remove());
		} else if (url.getAction().isSet()) {
			ret.put(key, ConfigItem.set(url.getItem().toString()));
		}
		// otherwise do nothing
	}
	
	public static class AuthExternalConfigMapper implements
			ExternalConfigMapper<AuthExternalConfig<State>> {

		@Override
		public AuthExternalConfig<State> fromMap(
				final Map<String, ConfigItem<String, State>> config)
				throws ExternalConfigMappingException {
			final ConfigItem<URL, State> allowedPostLogin =
					getURL(config, ALLOWED_POST_LOGIN_REDIRECT_PREFIX);
			final ConfigItem<URL, State> completeLogin =
					getURL(config, COMPLETE_LOGIN_REDIRECT);
			final ConfigItem<URL, State> postLink =
					getURL(config, POST_LINK_REDIRECT);
			final ConfigItem<URL, State> completeLink =
					getURL(config, COMPLETE_LINK_REDIRECT);
			final ConfigItem<Boolean, State> ignoreIPs =
					getBoolean(config, IGNORE_IP_HEADERS);
			final ConfigItem<Boolean, State> includeStack =
					getBoolean(config, INCLUDE_STACK_TRACE_IN_RESPONSE);
			try {
				return new AuthExternalConfig<State>(allowedPostLogin, completeLogin,
						postLink, completeLink, ignoreIPs, includeStack);
			} catch (IllegalParameterException e) {
				throw new ExternalConfigMappingException(
						"Error in incoming config: " + e.getMessage(), e);
			}
		}

		private ConfigItem<URL, State> getURL(
				final Map<String, ConfigItem<String, State>> config,
				final String key)
				throws ExternalConfigMappingException {
			final ConfigItem<String, State> url = config.get(key);
			final ConfigItem<URL, State> allowed;
			if (url == null || !url.hasItem()) {
				allowed = ConfigItem.emptyState();
			} else {
				try {
					final URL check = new URL(url.getItem());
					check.toURI();
					allowed = ConfigItem.state(check);
				} catch (MalformedURLException | URISyntaxException e) {
					throw new ExternalConfigMappingException(
							"Bad URL: " + e.getMessage(), e);
				}
			}
			return allowed;
		}

		private ConfigItem<Boolean, State> getBoolean(
				final Map<String, ConfigItem<String, State>> config,
				final String key)
				throws ExternalConfigMappingException {
			final ConfigItem<String, State> value = config.get(key);
			final ConfigItem<Boolean, State> ret;
			if (value == null || !value.hasItem()) {
				ret = ConfigItem.emptyState();
			} else if (TRUE.equals(value.getItem())) {
				ret = ConfigItem.state(true);
			} else if (FALSE.equals(value.getItem())) {
				ret = ConfigItem.state(false);
			} else {
				throw new ExternalConfigMappingException(String.format(
						"Expected value of %s or %s for parameter %s",
						TRUE, FALSE, key));
			}
			return ret;
		}
	}

}
