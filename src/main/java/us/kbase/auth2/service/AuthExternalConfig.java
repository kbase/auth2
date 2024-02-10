package us.kbase.auth2.service;

import static java.util.Objects.requireNonNull;
import static us.kbase.auth2.lib.Utils.noNulls;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.config.AuthConfigUpdate;
import us.kbase.auth2.lib.config.ConfigAction;
import us.kbase.auth2.lib.config.ConfigAction.Action;
import us.kbase.auth2.lib.config.ConfigAction.State;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.config.ExternalConfig;
import us.kbase.auth2.lib.config.ExternalConfigMapper;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchEnvironmentException;
import us.kbase.auth2.lib.token.IncomingToken;

/** Configuration items for the auth service UI.
 * 
 * The core auth code does not use these configuration items - only the UI is aware of and cares
 * about them. The UI can retrieve the state via
 * {@link Authentication#getExternalConfig(ExternalConfigMapper)} and modify the state via
 * {@link Authentication#updateConfig(IncomingToken, AuthConfigUpdate)}
 * 
 * This class can represent either the state of the configuration (when parameterized with
 * {@link State} or actions to be taken to modify the
 * configuration (when parameterized with {@link Action}.
 * 
 * The configuration supports sets of redirect urls for multiple environments - see
 * {@link Builder#withEnvironment(String, AuthExternalConfig.URLSet)}
 * 
 * @author gaprice@lbl.gov
 *
 * @param <T> Either {@link State} for the state of the configuration, or {@link Action} to
 * specify a change to the configuration.
 */
public class AuthExternalConfig<T extends ConfigAction> implements ExternalConfig {

	private static final String ALLOWED_POST_LOGIN_REDIRECT_PREFIX =
			"allowedPostLoginRedirectPrefix";
	private static final String COMPLETE_LOGIN_REDIRECT = "completeLoginRedirect";
	private static final String POST_LINK_REDIRECT = "postLinkRedirect";
	private static final String COMPLETE_LINK_REDIRECT = "completeLinkRedirect";
	private static final String IGNORE_IP_HEADERS = "ignoreIPHeaders";
	private static final String INCLUDE_STACK_TRACE_IN_RESPONSE = "includeStackTraceInResponse";

	private static final ConfigItem<Boolean, Action> SET_FALSE = ConfigItem.set(false);

	/** Get a default configuration. The default is that no URL are configured, and all 
	 * boolean parameters are set to false.
	 * @param environments the environments to configure.
	 * @return the configuration.
	 */
	public static AuthExternalConfig<Action> getDefaultConfig(final Set<String> environments) {
		requireNonNull(environments, "environments");
		noNulls(environments, "null item in environments");
		final Builder<Action> b = AuthExternalConfig.getBuilder(
				URLSet.remove(), SET_FALSE, SET_FALSE);
		for (final String e: environments) {
			b.withEnvironment(e, URLSet.remove());
		}
		return b.build();
	}
	
	private final static String TRUE = "true";
	private final static String FALSE = "false";
	
	private final URLSet<T> urlSet;
	private final ConfigItem<Boolean, T> ignoreIPHeaders;
	private final ConfigItem<Boolean, T> includeStackTraceInResponse;
	private final Map<String, URLSet<T>> environments;
	
	private AuthExternalConfig(
			final URLSet<T> urlSet,
			final ConfigItem<Boolean, T> ignoreIPHeaders,
			final ConfigItem<Boolean, T> includeStackTraceInResponse,
			final Map<String, URLSet<T>> environments) {
		this.urlSet = urlSet;
		this.ignoreIPHeaders = ignoreIPHeaders;
		this.includeStackTraceInResponse = includeStackTraceInResponse;
		this.environments = Collections.unmodifiableMap(environments);
	}

	/** Get the set of URLs for the default environment.
	 * @return the URL set.
	 */
	public URLSet<T> getURLSet() {
		return urlSet;
	}
	
	/** Get the set of environments for this configuration.
	 * @return the environments.
	 */
	public Set<String> getEnvironments() {
		return environments.keySet();
	}
	
	/** Get the set of URLs for a specific environment.
	 * @param environment the environment name.
	 * @return the URLs.
	 * @throws NoSuchEnvironmentException if no such environment exists.
	 */
	public URLSet<T> getURLSet(final String environment) throws NoSuchEnvironmentException {
		if (!environments.containsKey(environment)) {
			throw new NoSuchEnvironmentException(environment);
		}
		return environments.get(environment);
	}
	
	/** Get the set of URLs for a specific environment, or the default environment if null is
	 * passed.
	 * @param environment the environment name or null for the default environment.
	 * @return the URLs.
	 * @throws NoSuchEnvironmentException if no such environment exists.
	 */
	public URLSet<T> getURLSetOrDefault(final String environment)
			throws NoSuchEnvironmentException {
		if (environment == null) {
			return urlSet;
		}
		return getURLSet(environment);
	}
	
	/** Get the state or a configuration change action for whether the X-Real-IP and
	 * X-Forwarded-For headers should be ignored when determining a requests's IP address.
	 * @return the state or action.
	 */
	public ConfigItem<Boolean, T> isIgnoreIPHeaders() {
		return ignoreIPHeaders;
	}
	
	/** If the configuration class is state-parameterized and the ignore IP headers configuration
	 * item is present, returns its value. Otherwise returns false.
	 * @return the value of the ignore IP headers configuration item.
	 */
	public boolean isIgnoreIPHeadersOrDefault() {
		if (ignoreIPHeaders.getAction().isState() && ignoreIPHeaders.hasItem()) {
			return ignoreIPHeaders.getItem();
		}
		return SET_FALSE.getItem();
	}

	/** Get the state or a configuration change action for whether the full stack trace should
	 * be returned to users on error in the service response.
	 * @return the state or action.
	 */
	public ConfigItem<Boolean, T> isIncludeStackTraceInResponse() {
		return includeStackTraceInResponse;
	}

	/** If the configuration class is state-parameterized and the include stack trace configuration
	 * item is present, returns its value. Otherwise returns false.
	 * @return the value of the ignore IP headers configuration item.
	 */
	public boolean isIncludeStackTraceInResponseOrDefault() {
		if (includeStackTraceInResponse.getAction().isState() &&
				includeStackTraceInResponse.hasItem()) {
			return includeStackTraceInResponse.getItem();
		}
		return SET_FALSE.getItem();
	}

	@Override
	public Map<String, ConfigItem<String, Action>> toMap() {
		final Map<String, ConfigItem<String, Action>> ret = new HashMap<>();
		processURLSet(null, urlSet, ret);
		for (final String e: environments.keySet()) {
			processURLSet(e, environments.get(e), ret);
		}
		processBool(ret, IGNORE_IP_HEADERS, ignoreIPHeaders);
		processBool(ret, INCLUDE_STACK_TRACE_IN_RESPONSE, includeStackTraceInResponse);
		return ret;
	}

	private void processURLSet(
			String prefix,
			final URLSet<T> urlSet,
			final Map<String, ConfigItem<String, Action>> map) {
		if (prefix == null) {
			prefix = "";
		} else {
			prefix = prefix + "-";
		}
		processURL(map, prefix + ALLOWED_POST_LOGIN_REDIRECT_PREFIX,
				urlSet.getAllowedLoginRedirectPrefix());
		processURL(map, prefix + COMPLETE_LOGIN_REDIRECT, urlSet.getCompleteLoginRedirect());
		processURL(map, prefix + POST_LINK_REDIRECT, urlSet.getPostLinkRedirect());
		processURL(map, prefix + COMPLETE_LINK_REDIRECT, urlSet.getCompleteLinkRedirect());
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
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((environments == null) ? 0 : environments.hashCode());
		result = prime * result + ((ignoreIPHeaders == null) ? 0 : ignoreIPHeaders.hashCode());
		result = prime * result + ((includeStackTraceInResponse == null) ? 0 : includeStackTraceInResponse.hashCode());
		result = prime * result + ((urlSet == null) ? 0 : urlSet.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		@SuppressWarnings("unchecked")
		AuthExternalConfig<T> other = (AuthExternalConfig<T>) obj;
		if (environments == null) {
			if (other.environments != null) {
				return false;
			}
		} else if (!environments.equals(other.environments)) {
			return false;
		}
		if (ignoreIPHeaders == null) {
			if (other.ignoreIPHeaders != null) {
				return false;
			}
		} else if (!ignoreIPHeaders.equals(other.ignoreIPHeaders)) {
			return false;
		}
		if (includeStackTraceInResponse == null) {
			if (other.includeStackTraceInResponse != null) {
				return false;
			}
		} else if (!includeStackTraceInResponse.equals(other.includeStackTraceInResponse)) {
			return false;
		}
		if (urlSet == null) {
			if (other.urlSet != null) {
				return false;
			}
		} else if (!urlSet.equals(other.urlSet)) {
			return false;
		}
		return true;
	}
	
	/** Get a builder for an {@link AuthExternalConfig}.
	 * @param <T> Either {@link State} for the state of the configuration, or {@link Action} to
	 * specify a change to the configuration.
	 * @param urlSet the set of urls for the default environment.
	 * @param ignoreIPHeaders either the state or a change action for the ignore IP headers
	 * configuration item (see {@link #isIgnoreIPHeaders()}).
	 * @param includeStackTraceInResponse either the state or a change action for the include
	 * stack trace configuration item (see {@link #isIncludeStackTraceInResponse()}).
	 * @return a new builder.
	 */
	public static <T extends ConfigAction> Builder<T> getBuilder(
			final URLSet<T> urlSet,
			final ConfigItem<Boolean, T> ignoreIPHeaders,
			final ConfigItem<Boolean, T> includeStackTraceInResponse) {
		return new Builder<>(urlSet, ignoreIPHeaders, includeStackTraceInResponse);
	}
	
	/** A builder for an {@link AuthExternalConfig}.
	 * @author gaprice@lbl.gov
	 *
	 * @param <T> Either {@link State} for the state of the configuration, or {@link Action} to
	 * specify a change to the configuration.
	 */
	public static class Builder<T extends ConfigAction> {
		
		private final URLSet<T> urlSet;
		private final ConfigItem<Boolean, T> ignoreIPHeaders;
		private final ConfigItem<Boolean, T> includeStackTraceInResponse;
		private final Map<String, URLSet<T>> environments = new HashMap<>();
		
		private Builder(
				final URLSet<T> urlSet,
				final ConfigItem<Boolean, T> ignoreIPHeaders,
				final ConfigItem<Boolean, T> includeStackTraceInResponse) {
			requireNonNull(urlSet, "urlSet");
			this.urlSet = urlSet;
			requireNonNull(ignoreIPHeaders, IGNORE_IP_HEADERS);
			this.ignoreIPHeaders = ignoreIPHeaders;
			requireNonNull(includeStackTraceInResponse, INCLUDE_STACK_TRACE_IN_RESPONSE);
			this.includeStackTraceInResponse = includeStackTraceInResponse;
		}
		
		/** Add an environment to the builder.
		 * @param environment the name of the environment.
		 * @param urlSet the url set for the environment.
		 * @return this builder.
		 */
		public Builder<T> withEnvironment(final String environment, final URLSet<T> urlSet) {
			if (environment == null || environment.trim().isEmpty()) {
				throw new IllegalArgumentException("environment cannot be null or empty");
			}
			requireNonNull(urlSet, "urlSet");
			this.environments.put(environment, urlSet);
			return this;
		}
		
		/** Build the {@link AuthExternalConfig}.
		 * @return the config.
		 */
		public AuthExternalConfig<T> build() {
			return new AuthExternalConfig<>(
					urlSet, ignoreIPHeaders, includeStackTraceInResponse, environments);
		}
		
	}
	
	/** A set of redirect URLs for the authentication service UI. 
	 * @author gaprice@lbl.gov
	 *
	 * @param <T> Either {@link State} for the state of the URLs, or {@link Action} to
	 * specify a change to the URLs.
	 */
	public static class URLSet<T extends ConfigAction> {
		
		private final ConfigItem<URL, T> allowedPostLoginRedirectPrefix;
		private final ConfigItem<URL, T> completeLoginRedirect;
		private final ConfigItem<URL, T> postLinkRedirect;
		private final ConfigItem<URL, T> completeLinkRedirect;

		/** Create the URL set.
		 * @param allowedPostLoginRedirectPrefix either the state or a change action for
		 * what prefix is required for the user-specified redirect URL to be used after the 
		 * login process is complete.
		 * @param completeLoginRedirect either the state or a change action for
		 * the redirect URL to used when the login flow cannot be completed immediately after
		 * return from the 3rd party identity provider and control must be returned to the UI
		 * for user input.
		 * @param postLinkRedirect either the state or a change action for the redirect URL to
		 * be used after the linking process is complete.
		 * @param completeLinkRedirect either the state or a change action for
		 * the redirect URL to used when the link flow cannot be completed immediately after
		 * return from the 3rd party identity provider and control must be returned to the UI
		 * for user input.
		 * @throws IllegalParameterException if any of the URLs are invalid {@link URI}s.
		 */
		public URLSet(
				final ConfigItem<URL, T> allowedPostLoginRedirectPrefix,
				final ConfigItem<URL, T> completeLoginRedirect,
				final ConfigItem<URL, T> postLinkRedirect,
				final ConfigItem<URL, T> completeLinkRedirect)
				throws IllegalParameterException {
			requireNonNull(allowedPostLoginRedirectPrefix, ALLOWED_POST_LOGIN_REDIRECT_PREFIX);
			checkURI(allowedPostLoginRedirectPrefix);
			this.allowedPostLoginRedirectPrefix = allowedPostLoginRedirectPrefix;
			requireNonNull(completeLoginRedirect, COMPLETE_LOGIN_REDIRECT);
			checkURI(completeLoginRedirect);
			this.completeLoginRedirect = completeLoginRedirect;
			requireNonNull(postLinkRedirect, POST_LINK_REDIRECT);
			checkURI(postLinkRedirect);
			this.postLinkRedirect = postLinkRedirect;
			requireNonNull(completeLinkRedirect, COMPLETE_LINK_REDIRECT);
			checkURI(completeLinkRedirect);
			this.completeLinkRedirect = completeLinkRedirect;
		}

		private void checkURI(final ConfigItem<URL, T> url) throws IllegalParameterException {
			if (!url.hasItem()) {
				return;
			}
			try {
				url.getItem().toURI();
			} catch (URISyntaxException e) {
				throw new IllegalParameterException("Illegal URL " + url.getItem().toString() +
						": " + e.getMessage(), e);
			}
		}
		
		/** Get the state or change action for the allowed prefix for the user supplied
		 * login redirect URL.
		 * @return the state or change action for the prefix.
		 */
		public ConfigItem<URL, T> getAllowedLoginRedirectPrefix() {
			return allowedPostLoginRedirectPrefix;
		}
		
		/** Get the state or change action for the redirect URL to be used when the login flow
		 * cannot be completed immediately after return from the 3rd party identity provider
		 * and control must be returned to the UI for user input.
		 * @return the state or change action for the redirect url.
		 */
		public ConfigItem<URL, T> getCompleteLoginRedirect() {
			return completeLoginRedirect;
		}
		
		/** Get the state or change action for the redirect URL to
		 * be used after the linking process is complete.
		 * @return the state or change action for the redirect url.
		 */
		public ConfigItem<URL, T> getPostLinkRedirect() {
			return postLinkRedirect;
		}
		
		/** Get the state or change action for the redirect URL to be used when the link flow
		 * cannot be completed immediately after return from the 3rd party identity provider
		 * and control must be returned to the UI for user input.
		 * @return the state or change action for the redirect url.
		 */
		public ConfigItem<URL, T> getCompleteLinkRedirect() {
			return completeLinkRedirect;
		}
		
		private static final URLSet<Action> NO_ACTION;
		private static final URLSet<Action> REMOVE;
		private static final URLSet<State> EMPTY_STATE;
		static {
			final ConfigItem<URL, Action> na = ConfigItem.noAction();
			final ConfigItem<URL, Action> r = ConfigItem.remove();
			final ConfigItem<URL, State> es = ConfigItem.emptyState();
			try {
				NO_ACTION = new URLSet<>(na, na, na, na);
				REMOVE = new URLSet<>(r, r, r, r);
				EMPTY_STATE = new URLSet<>(es, es, es, es);
			} catch (IllegalParameterException e) {
				throw new RuntimeException("Programming error: ", e);
			}
		}
		
		/** Get a URL change set where no action will be taken for any of the URLs.
		 * @return the URL set.
		 */
		public static URLSet<Action> noAction() {
			return NO_ACTION;
		}
		
		/** Get a URL change set where all the URLs will be removed.
		 * @return the URL set.
		 */
		public static URLSet<Action> remove() {
			return REMOVE;
		}
		
		/** Get a URL set state where all the URls are empty.
		 * @return the URL set.
		 */
		public static URLSet<State> emptyState() {
			return EMPTY_STATE;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result
					+ ((allowedPostLoginRedirectPrefix == null) ? 0 : allowedPostLoginRedirectPrefix.hashCode());
			result = prime * result + ((completeLinkRedirect == null) ? 0 : completeLinkRedirect.hashCode());
			result = prime * result + ((completeLoginRedirect == null) ? 0 : completeLoginRedirect.hashCode());
			result = prime * result + ((postLinkRedirect == null) ? 0 : postLinkRedirect.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			@SuppressWarnings("unchecked")
			URLSet<T> other = (URLSet<T>) obj;
			if (allowedPostLoginRedirectPrefix == null) {
				if (other.allowedPostLoginRedirectPrefix != null) {
					return false;
				}
			} else if (!allowedPostLoginRedirectPrefix.equals(other.allowedPostLoginRedirectPrefix)) {
				return false;
			}
			if (completeLinkRedirect == null) {
				if (other.completeLinkRedirect != null) {
					return false;
				}
			} else if (!completeLinkRedirect.equals(other.completeLinkRedirect)) {
				return false;
			}
			if (completeLoginRedirect == null) {
				if (other.completeLoginRedirect != null) {
					return false;
				}
			} else if (!completeLoginRedirect.equals(other.completeLoginRedirect)) {
				return false;
			}
			if (postLinkRedirect == null) {
				if (other.postLinkRedirect != null) {
					return false;
				}
			} else if (!postLinkRedirect.equals(other.postLinkRedirect)) {
				return false;
			}
			return true;
		}
	}

	/** A mapper that maps a string to {@link ConfigItem} map to an {@link AuthExternalConfig}.
	 * Reverses the effects of {@link AuthExternalConfig#toMap()}.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static class AuthExternalConfigMapper implements
			ExternalConfigMapper<AuthExternalConfig<State>> {
		
		private final Set<String> environments;
		
		/** Create a mapper that ignores any configuration items that are not part of the
		 * default environment.
		 */
		public AuthExternalConfigMapper() {
			environments = Collections.emptySet();
		}
		
		/** Create a mapper.
		 * @param environments the environments the mapper will include in the configuration.
		 */
		public AuthExternalConfigMapper(final Set<String> environments) {
			requireNonNull(environments, "environments");
			noNulls(environments, "null item in environments");
			this.environments = environments;
		}

		@Override
		public AuthExternalConfig<State> fromMap(
				final Map<String, ConfigItem<String, State>> config)
				throws ExternalConfigMappingException {
			final ConfigItem<Boolean, State> ignoreIPs =
					getBoolean(config, IGNORE_IP_HEADERS);
			final ConfigItem<Boolean, State> includeStack =
					getBoolean(config, INCLUDE_STACK_TRACE_IN_RESPONSE);
			final Builder<State> b = AuthExternalConfig.getBuilder(
					getURLSet(null, config), ignoreIPs, includeStack);
			for (final String e: environments) {
				b.withEnvironment(e, getURLSet(e, config));
			}
			return b.build();
		}

		private URLSet<State> getURLSet(
				String prefix,
				final Map<String, ConfigItem<String, State>> config)
				throws ExternalConfigMappingException {
			if (prefix == null) {
				prefix = "";
			} else {
				prefix = prefix + "-";
			}
			final ConfigItem<URL, State> allowedPostLogin =
					getURL(config, prefix + ALLOWED_POST_LOGIN_REDIRECT_PREFIX);
			final ConfigItem<URL, State> completeLogin =
					getURL(config, prefix + COMPLETE_LOGIN_REDIRECT);
			final ConfigItem<URL, State> postLink =
					getURL(config, prefix + POST_LINK_REDIRECT);
			final ConfigItem<URL, State> completeLink =
					getURL(config, prefix + COMPLETE_LINK_REDIRECT);
			try {
				return new URLSet<>(allowedPostLogin, completeLogin, postLink, completeLink);
			} catch (IllegalParameterException e) {
				throw new RuntimeException("This should be impossible", e);
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
					throw new ExternalConfigMappingException(String.format(
							"Bad URL for parameter %s: %s", key, e.getMessage()), e);
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

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((environments == null) ? 0 : environments.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			AuthExternalConfigMapper other = (AuthExternalConfigMapper) obj;
			if (environments == null) {
				if (other.environments != null) {
					return false;
				}
			} else if (!environments.equals(other.environments)) {
				return false;
			}
			return true;
		}
	}

}
