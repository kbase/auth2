package us.kbase.auth2.service.ui;

import static us.kbase.auth2.service.common.ServiceCommon.nullOrEmpty;
import static us.kbase.auth2.service.ui.UIConstants.IN_PROCESS_LINK_COOKIE;
import static us.kbase.auth2.service.ui.UIConstants.IN_PROCESS_LOGIN_COOKIE;
import static us.kbase.auth2.lib.Utils.nonNull;
import static us.kbase.auth2.lib.Utils.checkStringNoCheckedException;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.UriInfo;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.config.ConfigAction.State;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchEnvironmentException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.auth2.service.AuthExternalConfig.AuthExternalConfigMapper;
import us.kbase.auth2.service.common.Fields;

/** Utility functions for the UI endpoints.
 * @author gaprice@lbl.gov
 *
 */
public class UIUtils {
	
	/** The name of the cookie in which the name of the environment in which the server is
	 * operating for the current login or link request is stored.
	 */
	public static final String ENVIRONMENT_COOKIE = "environment";

	// attempts to deal with the mess of returning a relative path to the
	// target from the current location that makes Jersey happy.
	/** Generates a string URL to a target relative to the current url.
	 * @param current the current url.
	 * @param target the target url, absolute from the root of the application.
	 * @return the target url, relativized to the current url.
	 * @throws InvalidPathException if the target is not a valid path.
	 */
	public static String relativize(final UriInfo current, final String target) {
		nonNull(current, "current");
		nonNull(target, "target");
		final Path t = Paths.get(target);
		if (!t.isAbsolute()) {
			throw new IllegalArgumentException("target must be absolute: " + target);
		}
		// jfc what a mess
		Path c = Paths.get("/" + current.getPath()).normalize();
		if (!current.getPath().endsWith("/")) {
			c = c.getParent();
		}
		// a UriInfo will always return at least /, so c can never be null here
		String rel = c.relativize(t).toString();
		if (target.endsWith("/") && !rel.isEmpty()) { // Path strips trailing slashes
			rel = rel + "/";
		}
		return rel;
	}
	
	/** Create a login cookie from a token that immediately expires.
	 * @param cookieName the name to give the cookie.
	 * @return a new cookie that immediately expires and contains a nonsense token.
	 */
	public static NewCookie removeLoginCookie(final String cookieName) {
		return getLoginCookie(cookieName, null, false);
	}

	/** Create a login cookie from a token.
	 * @param cookieName the name to give the cookie.
	 * @param token the source to use as the state of the cookie, or null to create a cookie that
	 * immediately expires.
	 * @param session true to create the cookie as a session cookie that expires when the browser
	 * is closed.
	 * @return a new cookie.
	 */
	public static NewCookie getLoginCookie(
			final String cookieName,
			final NewToken token,
			final boolean session) {
		checkStringNoCheckedException(cookieName, "cookieName");
		if (token != null && !token.getStoredToken().getTokenType().equals(TokenType.LOGIN)) {
			throw new IllegalArgumentException("token must be a login token");
		}
		return new NewCookie(
				new Cookie(cookieName, token == null ? "no token" : token.getToken(), "/", null),
				"authtoken",
				token == null ? 0 : getMaxCookieAge(
						token.getStoredToken().getExpirationDate(), session),
				UIConstants.SECURE_COOKIES);
	}
	
	/** Get a login in process cookie. Always returns a session cookie.
	 * @param token the token to cookieize, or null to create a cookie that immediately expires.
	 * @return a new cookie.
	 */
	public static NewCookie getLoginInProcessCookie(final TemporaryToken token) {
		return new NewCookie(new Cookie(IN_PROCESS_LOGIN_COOKIE,
				token == null ? "no token" : token.getToken(), UIPaths.LOGIN_ROOT, null),
				"logintoken",
				token == null ? 0 : NewCookie.DEFAULT_MAX_AGE,
				UIConstants.SECURE_COOKIES);
	}
	
	/** Get a link in process cookie. Always returns a session cookie.
	 * @param token the token to cookieize, or null to create a cookie that immediately expires.
	 * @return a new cookie
	 */
	public static NewCookie getLinkInProcessCookie(final TemporaryToken token) {
		return new NewCookie(new Cookie(IN_PROCESS_LINK_COOKIE,
				token == null ? "no token" : token.getToken(), UIPaths.LINK_ROOT, null),
				"linktoken",
				token == null ? 0 : NewCookie.DEFAULT_MAX_AGE,
				UIConstants.SECURE_COOKIES);
	}
	
	/** Get an environment cookie. The environment name tells the service which environment
	 * a login or link process is operating in, and therefore which redirect URLs to use.
	 * @param environment the name of the environment. Pass null to make a cookie that will
	 * be deleted immediately.
	 * @param path the path where the cookie is active, for example /login or /link.
	 * @param expirationTimeSec the expiration time of the cookie.
	 * @return the new cookie.
	 */
	public static NewCookie getEnvironmentCookie(
			final String environment,
			final String path,
			final int expirationTimeSec) {
		return new NewCookie(
				new Cookie(
						ENVIRONMENT_COOKIE,
						environment == null ? "no env" : environment,
						path,
						null),
				"environment",
				environment == null ? 0 : expirationTimeSec,
				UIConstants.SECURE_COOKIES);
	}
	

	/** Get the maximum age for a cookie given a temporary token.
	 * @param token the token.
	 * @return the maximum cookie age in seconds.
	 */
	public static int getMaxCookieAge(final TemporaryToken token) {
		nonNull(token, "token");
		return getMaxCookieAge(token.getExpirationDate(), false);
	}

	private static int getMaxCookieAge(
			final Instant expiration,
			final boolean session) {
	
		if (session) {
			return NewCookie.DEFAULT_MAX_AGE;
		}
		final long exp = (long) Math.floor(
				(expiration.toEpochMilli() - Instant.now().toEpochMilli()) / 1000.0);
		if (exp > Integer.MAX_VALUE) {
			return Integer.MAX_VALUE;
		}
		if (exp < 0) {
			return 0;
		}
		return (int) exp;
	}
	
	/** Get a token from a cookie.
	 * @param headers the request headers.
	 * @param tokenCookieName the name of the cookie.
	 * @return the incoming token.
	 * @throws NoTokenProvidedException if there is no cookie or the cookie contains no token.
	 */
	public static IncomingToken getTokenFromCookie(
			final HttpHeaders headers,
			final String tokenCookieName)
			throws NoTokenProvidedException {
		return getTokenFromCookie(headers, tokenCookieName, true).get();
	}
	
	/** Get a token from a cookie.
	 * @param headers the request headers.
	 * @param tokenCookieName the name of the cookie.
	 * @param throwException throw an exception if the cookie is missing.
	 * @return the incoming token. Absent if the cookie is missing and throwException is false.
	 * @throws NoTokenProvidedException if there is no cookie or the cookie contains no token.
	 */
	public static Optional<IncomingToken> getTokenFromCookie(
			final HttpHeaders headers,
			final String tokenCookieName,
			final boolean throwException)
			throws NoTokenProvidedException {
		nonNull(headers, "headers");
		checkStringNoCheckedException(tokenCookieName, "tokenCookieName");
		final Cookie c = headers.getCookies().get(tokenCookieName);
		if (c == null) {
			if (throwException) {
				throw new NoTokenProvidedException("No user token provided");
			}
			return Optional.empty();
		}
		if (nullOrEmpty(c.getValue())) {
			if (throwException) {
				throw new NoTokenProvidedException("No user token provided");
			}
			return Optional.empty();
		}
		try {
			return Optional.of(new IncomingToken(c.getValue()));
		} catch (MissingParameterException e) {
			throw new RuntimeException("This should be impossible", e);
		}
	}
	
	/** Get a header value from a header or an optional default.
	 * Returns, in order of precedence, the value of the header given by headerName if not
	 * null or whitespace only, the value of the stringValue if not null or whitespace only, or
	 * {@link Optional#empty()}.
	 * 
	 * All values are {@link String#trim()}ed before returning.
	 * 
	 * @param headers the headers to interrogate.
	 * @param headerName the name of the header to retrieve.
	 * @param stringValue the value to return if the header value is absent.
	 * @return the header value, string value, or {@link Optional#empty()}.
	 */
	public static Optional<String> getValueFromHeaderOrString(
			final HttpHeaders headers,
			final String headerName,
			final String stringValue) {
		nonNull(headers, "headers");
		checkStringNoCheckedException(headerName, "headerName");
		final String headerEnv = headers.getHeaderString(headerName);
		if (!nullOrEmpty(headerEnv)) {
			return Optional.of(headerEnv.trim());
		} else if (!nullOrEmpty(stringValue)) {
			return Optional.of(stringValue.trim());
		} else {
			return Optional.empty();
		}
	}
	
	/** Given a multivalued map as form input, return the set of roles that are contained as keys
	 * in the form and have non-null values (e.g. the form contains a list for that value).
	 * @param form the form to process.
	 * @return the roles.
	 */
	public static Set<Role> getRolesFromForm(final MultivaluedMap<String, String> form) {
		nonNull(form, "form");
		final Set<Role> roles = new HashSet<>();
		for (final Role r: Role.values()) {
			if (form.get(r.getID()) != null) {
				roles.add(r);
			}
		}
		return roles;
	}
	
	/** Converts a set of custom roles into a list of maps.
	 * @param roles the roles to convert.
	 * @return a list of maps.
	 */
	public static List<Map<String, String>> customRolesToList(final Set<CustomRole> roles) {
		nonNull(roles, "roles");
		final List<Map<String, String>> ret = new LinkedList<>();
		for (final CustomRole cr: roles) {
			nonNull(cr, "null role in set");
			ret.add(ImmutableMap.of(
					Fields.DESCRIPTION, cr.getDesc(),
					Fields.ID, cr.getID()));
		}
		return ret;
	}
	
	/** A selector for a configured URL from an Authentication instance.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static interface ExteralConfigURLSelector {
		
		/** Get a URL from an Authentication external configuration.
		 * @param externalConfig the external configuration.
		 * @return the requested URL.
		 * @throws NoSuchEnvironmentException if a configuration for the requested environment
		 * does not exist.
		 */
		ConfigItem<URL, State> getExternalConfigURL(
				final AuthExternalConfig<State> externalConfig)
				throws NoSuchEnvironmentException;
	}
	
	/** Get an externally configured URI from an Authentication instance.
	 * @param auth the Authentication instance.
	 * @param selector a selector for the URL to convert to a URI.
	 * @param deflt the default URL if no URL is configured. This is expected to be a valid URI;
	 * if not a runtime exception will be thrown.
	 * @return the requested URI.
	 * @throws AuthStorageException if an error occurred contacting the auth storage system.
	 * @throws NoSuchEnvironmentException if a configuration for the requested environment
	 * does not exist.
	 */
	public static URI getExternalConfigURI(
			final Authentication auth,
			final ExteralConfigURLSelector selector,
			final String deflt)
			throws AuthStorageException, NoSuchEnvironmentException {
		nonNull(auth, "auth");
		nonNull(selector, "selector");
		checkStringNoCheckedException(deflt, "deflt");
		final ConfigItem<URL, State> url;
		try {
			final AuthExternalConfig<State> externalConfig =
					auth.getExternalConfig(new AuthExternalConfigMapper(auth.getEnvironments()));
			url = selector.getExternalConfigURL(externalConfig);
		} catch (ExternalConfigMappingException e) {
			throw new RuntimeException("Dude, like, what just happened?", e);
		}
		if (!url.hasItem()) {
			return toURI(deflt);
		}
		try {
			return url.getItem().toURI();
		} catch (URISyntaxException e) {
			throw new RuntimeException("this should be impossible" , e);
		}
	}
	
	private static final String OBNOXIOUS_ERROR = "The javadoc explicitly said you can't pass " +
			"an invalid URI into this function, and you did it anyway. Good job.";
	
	/** Converts a valid URL to a URI, throwing a RuntimeException if the URL is an invalid URI.
	 * @param loginURL the URL to convert.
	 * @return the URI equivalent of the URL.
	 */
	public static URI toURI(final URL loginURL) {
		try {
			return loginURL.toURI();
		} catch (URISyntaxException e) {
			throw new RuntimeException(OBNOXIOUS_ERROR, e);
		}
	}
	
	/** Converts a valid string URI to a URI, throwing a RuntimeException if the URI is invalid.
	 * @param uri the string URI to convert.
	 * @return the URI equivalent of the URL.
	 */
	public static URI toURI(final String uri) {
		try {
			return new URI(uri);
		} catch (URISyntaxException e) {
			throw new RuntimeException(OBNOXIOUS_ERROR, e);
		}
	}
}
