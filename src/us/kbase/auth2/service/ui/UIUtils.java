package us.kbase.auth2.service.ui;

import static us.kbase.auth2.service.common.ServiceCommon.nullOrEmpty;
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
import java.util.Set;

import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.UriInfo;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.config.ConfigAction.State;
import us.kbase.auth2.lib.exceptions.AuthenticationException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.auth2.service.AuthExternalConfig.AuthExternalConfigMapper;

public class UIUtils {

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
	
	/** Check that the OAuth2 state returned from an identity provider matches the expected state.
	 * @param cookieSessionState the state as stored in a cookie.
	 * @param providerSuppliedState the state returned from the provider.
	 * @throws MissingParameterException if the state from the cookie is missing.
	 * @throws AuthenticationException if the state values don't match.
	 */
	public static void checkState(
			final String cookieSessionState,
			final String providerSuppliedState)
			throws MissingParameterException, AuthenticationException {
		if (nullOrEmpty(cookieSessionState)) {
			throw new MissingParameterException("Couldn't retrieve state value from cookie");
		}
		if (!cookieSessionState.equals(providerSuppliedState)) {
			throw new AuthenticationException(ErrorType.AUTHENTICATION_FAILED,
					"State values do not match, this may be a CXRF attack");
		}
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

	/** Get the maximum age for a cookie given a temporaray token.
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
			return Optional.absent();
		}
		if (nullOrEmpty(c.getValue())) {
			if (throwException) {
				throw new NoTokenProvidedException("No user token provided");
			}
			return Optional.absent();
		}
		try {
			return Optional.of(new IncomingToken(c.getValue()));
		} catch (MissingParameterException e) {
			throw new RuntimeException("This should be impossible", e);
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
	
	/** A selector for a configured URL from an Authentication instance.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static interface ExteralConfigURLSelector {
		
		/** Get a URL from an Authentication external configuration.
		 * @param externalConfig the external configuration.
		 * @return the requested URL.
		 */
		ConfigItem<URL, State> getExternalConfigURL(
				final AuthExternalConfig<State> externalConfig);
	}
	
	/** Get an externally configured URI from an Authentication instance.
	 * @param auth the Authentication instance.
	 * @param selector a selector for the URL to convert to a URI.
	 * @param deflt the default URL if no URL is configured. This is expected to be a valid URI;
	 * if not a runtime exception will be thrown.
	 * @return the requested URI.
	 * @throws AuthStorageException if an error occurred contacting the auth storage system.
	 */
	public static URI getExternalConfigURI(
			final Authentication auth,
			final ExteralConfigURLSelector selector,
			final String deflt)
			throws AuthStorageException {
		nonNull(auth, "auth");
		nonNull(selector, "selector");
		checkStringNoCheckedException(deflt, "deflt");
		final ConfigItem<URL, State> url;
		try {
			final AuthExternalConfig<State> externalConfig =
					auth.getExternalConfig(new AuthExternalConfigMapper());
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
