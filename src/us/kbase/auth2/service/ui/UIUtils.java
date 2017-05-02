package us.kbase.auth2.service.ui;

import static us.kbase.auth2.service.common.ServiceCommon.nullOrEmpty;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
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
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.auth2.service.AuthExternalConfig.AuthExternalConfigMapper;

public class UIUtils {

	//TODO TEST
	//TODO JAVADOC
	
	//target should be path from root of application
	//target should not be absolute
	public static String relativize(
			final UriInfo current,
			final URI target) {
		return relativize(current, target.toString());
	}
	
	// attempts to deal with the mess of returning a relative path to the
	// target from the current location that makes Jersey happy.
	public static String relativize(
			final UriInfo current,
			final String target) {
		// jfc what a mess
		Path c = Paths.get("/" + current.getPath()).normalize();
		if (!current.getPath().endsWith("/")) {
			c = c.getParent();
		}
		if (c == null) {
			c = Paths.get("");
		}
		final Path t = Paths.get(target);
		String rel = c.relativize(t).toString();
		if (target.endsWith("/") && !rel.isEmpty()) { // Path strips trailing slashes
			rel = rel + "/";
		}
		return rel;
	}
	
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

	public static NewCookie getLoginCookie(final String cookieName, final NewToken token) {
		return getLoginCookie(cookieName, token, false);
	}

	public static NewCookie getLoginCookie(
			final String cookieName,
			final NewToken token,
			final boolean session) {
		return new NewCookie(
				new Cookie(cookieName, token == null ? "no token" : token.getToken(), "/", null),
				"authtoken",
				token == null ? 0 : getMaxCookieAge(token, session),
				UIConstants.SECURE_COOKIES);
	}

	public static int getMaxCookieAge(
			final NewToken token,
			final boolean session) {
		return getMaxCookieAge(token.getStoredToken().getExpirationDate(), session);
	}

	public static int getMaxCookieAge(final TemporaryToken token) {
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
	
	public static IncomingToken getTokenFromCookie(
			final HttpHeaders headers,
			final String tokenCookieName)
			throws NoTokenProvidedException {
		return getTokenFromCookie(headers, tokenCookieName, true).get();
	}
	
	public static Optional<IncomingToken> getTokenFromCookie(
			final HttpHeaders headers,
			final String tokenCookieName,
			final boolean throwException)
			throws NoTokenProvidedException {
		
		final Cookie c = headers.getCookies().get(tokenCookieName);
		if (c == null) {
			if (throwException) {
				throw new NoTokenProvidedException("No user token provided");
			}
			return Optional.absent();
		}
		// can't be null when headers are actually gen'd by jaxrs
		final String val = c.getValue().trim();
		if (val.isEmpty()) {
			if (throwException) {
				throw new NoTokenProvidedException("No user token provided");
			}
			return Optional.absent();
		}
		try {
			return Optional.of(new IncomingToken(val));
		} catch (MissingParameterException e) {
			throw new RuntimeException("This should be impossible", e);
		}
	}
	
	public static Set<Role> getRolesFromForm(final MultivaluedMap<String, String> form) {
		final Set<Role> roles = new HashSet<>();
		for (final Role r: Role.values()) {
			if (form.get(r.getID()) != null) {
				roles.add(r);
			}
		}
		return roles;
	}
	
	public static interface ExteralConfigURLSelector {
		
		ConfigItem<URL, State> getExternalConfigURL(
				final AuthExternalConfig<State> externalConfig);
	}
	
	public static URI getExternalConfigURI(
			final Authentication auth,
			final ExteralConfigURLSelector selector,
			final String deflt)
			throws AuthStorageException {
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
	
	//Assumes valid URI in URL form
	public static URI toURI(final URL loginURL) {
		try {
			return loginURL.toURI();
		} catch (URISyntaxException e) {
			throw new RuntimeException("This should be impossible", e);
		}
	}
	
	//Assumes valid URI in String form
	public static URI toURI(final String uri) {
		try {
			return new URI(uri);
		} catch (URISyntaxException e) {
			throw new RuntimeException("This should be impossible", e);
		}
	}
}
