package us.kbase.auth2.service.ui;

import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;

import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.UriInfo;

import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.TemporaryToken;

public class APIUtils {

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
				APIConstants.SECURE_COOKIES);
	}

	public static int getMaxCookieAge(
			final NewToken token,
			final boolean session) {
		return getMaxCookieAge(token.getExpirationDate(), session);
	}

	public static int getMaxCookieAge(
			final TemporaryToken token,
			final boolean session) {
		return getMaxCookieAge(token.getExpirationDate(), session);
	}

	private static int getMaxCookieAge(
			final Date expiration,
			final boolean session) {
	
		if (session) {
			return NewCookie.DEFAULT_MAX_AGE;
		}
		final long exp = (long) Math.floor((expiration.getTime() - new Date().getTime()) / 1000.0);
		if (exp > Integer.MAX_VALUE) {
			return Integer.MAX_VALUE;
		}
		if (exp < 0) {
			return 0;
		}
		return (int) exp;
	}
	
	// assumes non-null, len > 0
	public static String upperCase(final String provider) {
		final String first = new String(Character.toChars(
				Character.toUpperCase(provider.codePointAt(0))));
		if (provider.length() == first.length()) {
			return first;
		}
		return first + provider.substring(first.length());
	}
	
	public static IncomingToken getTokenFromCookie(
			final HttpHeaders headers,
			final String tokenCookieName)
			throws NoTokenProvidedException {
		return getTokenFromCookie(headers, tokenCookieName, true);
	}
	
	public static IncomingToken getTokenFromCookie(
			final HttpHeaders headers,
			final String tokenCookieName,
			final boolean throwException)
			throws NoTokenProvidedException {
		
		final Cookie c = headers.getCookies().get(tokenCookieName);
		if (c == null) {
			if (throwException) {
				throw new NoTokenProvidedException("No user token provided");
			}
			return null;
		}
		final String val = c.getValue();
		if (val == null || val.trim().isEmpty()) {
			if (throwException) {
				throw new NoTokenProvidedException("No user token provided");
			}
			return null;
		}
		return new IncomingToken(val.trim());
	}
	
	public static IncomingToken getToken(final String token)
			throws NoTokenProvidedException {
		if (token == null || token.trim().isEmpty()) {
			throw new NoTokenProvidedException("No user token provided");
		}
		return new IncomingToken(token.trim());
	}
}
