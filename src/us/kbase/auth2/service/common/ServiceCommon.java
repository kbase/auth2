package us.kbase.auth2.service.common;

import static us.kbase.auth2.lib.Utils.nonNull;

import java.net.InetAddress;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.GitCommit;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.UserUpdate;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.service.UserAgentParser;
import us.kbase.auth2.service.AuthExternalConfig.AuthExternalConfigMapper;
import us.kbase.auth2.service.exceptions.AuthConfigurationException;

/** Helper methods that are useful for both the UI and API.
 * @author gaprice@lbl.gov
 *
 */
public class ServiceCommon {
	
	private static final String VERSION = "0.5.0-dev1";
	// TODO FEATURE make configurable. Will need to make this a class & inject into deps
	private static final String SERVICE_NAME = "Authentication Service";
	private static final String HEADER_USER_AGENT = "user-agent";
	private static final String X_FORWARDED_FOR = "X-Forwarded-For";
	private static final String X_REAL_IP = "X-Real-IP";

	//TODO ZLATER ROOT add paths to endpoints
	//TODO ZLATER ROOT add configurable contact email or link
	
	/** Get general information about the service intended to be returned with an HTTP GET request
	 * at the url root.
	 * @return general information about the service.
	 */
	public static Map<String, Object> root() {
		return ImmutableMap.of(
				Fields.VERSION, VERSION,
				Fields.SERVICE_NAME, SERVICE_NAME,
				Fields.SERVER_TIME, Instant.now().toEpochMilli(),
				Fields.GIT_HASH, GitCommit.COMMIT);
	}
	
	/** Create an incoming token from a string, throwing an appropriate exception if the token is
	 * null or empty.
	 * @param token the token.
	 * @return an incoming token object.
	 * @throws NoTokenProvidedException if the token is null or empty.
	 */
	public static IncomingToken getToken(final String token)
			throws NoTokenProvidedException {
		try {
			return new IncomingToken(token);
		} catch (MissingParameterException e) {
			throw new NoTokenProvidedException("No user token provided");
		}
	}

	/** Update a user's name and or email.
	 * @param auth the authentication instance upon which to perform the update.
	 * @param token the user's token.
	 * @param displayName the new display name for the user.
	 * @param email the new email address for the user.
	 * @throws IllegalParameterException if the display name or email address are illegal.
	 * @throws InvalidTokenException if the user's token is invalid.
	 * @throws AuthStorageException if an error occurs contacting the authentication storage
	 * system.
	 * @throws UnauthorizedException if the token is not a login token.
	 */
	public static void updateUser(
			final Authentication auth,
			final IncomingToken token,
			final String displayName,
			final String email)
			throws IllegalParameterException, InvalidTokenException, AuthStorageException,
				UnauthorizedException {
		nonNull(auth, "auth");
		nonNull(token, "token");
		final UserUpdate.Builder uu = UserUpdate.getBuilder();
		try {
			if (displayName != null && !displayName.trim().isEmpty()) {
				uu.withDisplayName(new DisplayName(displayName));
			}
			if (email != null && !email.trim().isEmpty()) {
				uu.withEmail(new EmailAddress(email));
			}
		} catch (MissingParameterException mpe) {
			throw new RuntimeException("This is impossible", mpe);
		}
		auth.updateUser(token, uu.build());
	}
	
	/** Load and instantiate a class with a given interface. Expects a no-argument constructor.
	 * @param <T> the class that will be instantiated.
	 * @param className the fully qualified class name.
	 * @param interfce the required interface.
	 * @return an instance of the class typed as the interface.
	 * @throws AuthConfigurationException if the instance could not be created.
	 */
	public static <T> T loadClassWithInterface(final String className, final Class<T> interfce)
			throws AuthConfigurationException {
		final Class<?> cls;
		try {
			cls = Class.forName(className);
		} catch (ClassNotFoundException e) {
			throw new AuthConfigurationException(String.format(
					"Cannot load class %s: %s", className, e.getMessage()), e);
		}
		final Set<Class<?>> interfaces = new HashSet<>(Arrays.asList(cls.getInterfaces()));
		if (!interfaces.contains(interfce)) {
			throw new AuthConfigurationException(String.format(
					"Module %s must implement %s interface",
					className, interfce.getName()));
		}
		@SuppressWarnings("unchecked")
		final Class<T> inter = (Class<T>) cls;
		try {
			return inter.newInstance();
		} catch (IllegalAccessException | InstantiationException e) {
			throw new AuthConfigurationException(String.format(
					"Module %s could not be instantiated: %s", className, e.getMessage()), e);
		}
	}

	/** Creates a context object for the creation of a token.
	 * @param userAgentParser a parser to parse a user agent string.
	 * @param request the servlet request from which the user agent and ip address will be
	 * retrieved.
	 * @param ignoreIPsInHeaders whether the x-forwarded-for and x-real-ip headers should be
	 * ignored.
	 * @param customContext and user-provided context to be included with the context object.
	 * @return a token creation context object.
	 * @throws MissingParameterException if any of the keys or values of the custom context are
	 * null or missing.
	 * @throws IllegalParameterException if any of the keys or values of the custom context are too
	 * large or too many keys are in the context.
	 */
	public static TokenCreationContext getTokenContext(
			final UserAgentParser userAgentParser,
			final HttpServletRequest request,
			final boolean ignoreIPsInHeaders,
			final Map<String, String> customContext)
			throws MissingParameterException, IllegalParameterException {
		nonNull(userAgentParser, "userAgentParser");
		nonNull(request, "request");
		nonNull(customContext, "customContext");
		final TokenCreationContext.Builder tcc = userAgentParser.getTokenContextFromUserAgent(
				request.getHeader(HEADER_USER_AGENT));
		addIPAddress(tcc, request, ignoreIPsInHeaders);
		for (final Entry<String, String> entry: customContext.entrySet()) {
			tcc.withCustomContext(entry.getKey(), entry.getValue());
		}
		return tcc.build();
	}
	
	private static void addIPAddress(
			final TokenCreationContext.Builder builder,
			final HttpServletRequest request,
			final boolean ignoreIPsInHeaders) {
		final String xFF = request.getHeader(X_FORWARDED_FOR);
		final String realIP = request.getHeader(X_REAL_IP);
		final String ip;
		if (!ignoreIPsInHeaders) {
			if (xFF != null && !xFF.trim().isEmpty()) {
				ip = xFF.split(",")[0].trim();
			} else if (realIP != null && !realIP.trim().isEmpty()) {
				ip = realIP.trim();
			} else {
				ip = request.getRemoteAddr();
			}
		} else {
			ip = request.getRemoteAddr();
		}
		// empty string is translated to loopback which is an error
		if (!ip.trim().isEmpty()) { // if null there's a bug in HttpServletRequest
			try {
				builder.withIpAddress(InetAddress.getByName(ip.trim()));
			} catch (Exception e) {
				// do nothing
			}
		}
	}
	
	/** A helper method to determine whether to ignore the x-forwarded-for and x-real-ip
	 * headers based on the authentication configuration.
	 * @param auth the authentication instance to query.
	 * @return whether to ignore the headers.
	 * @throws AuthStorageException if an error occurs contacting the authentication storage
	 * system.
	 */
	public static boolean isIgnoreIPsInHeaders(final Authentication auth)
			throws AuthStorageException {
		try {
			return auth.getExternalConfig(new AuthExternalConfigMapper())
				.isIgnoreIPHeadersOrDefault();
		} catch (ExternalConfigMappingException e) {
			throw new RuntimeException("There appears to be a programming error here...", e);
		}
	}
	
	/** Translate a comma and semicolon delimited string to a key-value map.
	 * @param customContext the string to translate.
	 * @return the key value context map.
	 * @throws IllegalParameterException if the string is not formatted correctly.
	 */
	public static Map<String, String> getCustomContextFromString(final String customContext)
			throws IllegalParameterException {
		final Map<String, String> ret = new HashMap<>();
		if (nullOrEmpty(customContext)) {
			return ret;
		}
		final String[] items = customContext.trim().split(";");
		for (String item: items) {
			item = item.trim();
			if (!item.isEmpty()) {
				final String[] keyvalue = item.split(",");
				if (keyvalue.length != 2) {
					throw new IllegalParameterException("Bad key/value pair in custom context: " +
							item);
				}
				ret.put(keyvalue[0].trim(), keyvalue[1].trim());
			}
		}
		return ret;
	}
	
	/** Check if a string is null or whitespace only.
	 * @param s the string to check.
	 * @return true if the string is null or consists only of whitespace, false otherwise.
	 */
	public static boolean nullOrEmpty(final String s) {
		return s == null || s.trim().isEmpty();
	}
}
