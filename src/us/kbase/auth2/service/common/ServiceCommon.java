package us.kbase.auth2.service.common;

import static us.kbase.auth2.lib.Utils.nonNull;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

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

/* methods that are useful for the UI and API */
public class ServiceCommon {
	
	private static final String HEADER_USER_AGENT = "user-agent";
	private static final String X_FORWARDED_FOR = "X-Forwarded-For";
	private static final String X_REAL_IP = "X-Real-IP";

	//TODO JAVADOC
	//TODO TEST
	
	public static IncomingToken getToken(final String token)
			throws NoTokenProvidedException {
		try {
			return new IncomingToken(token);
		} catch (MissingParameterException e) {
			throw new NoTokenProvidedException("No user token provided");
		}
	}

	public static void updateUser(
			final Authentication auth,
			final IncomingToken token,
			final String displayName,
			final String email)
			throws IllegalParameterException, InvalidTokenException, AuthStorageException,
				UnauthorizedException {
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
					"Module %s could not be instantiated: %s",
					className, e.getMessage()), e);
		}
	}

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
	
	//TODO TEST xff and realip headers
	private static void addIPAddress(
			final TokenCreationContext.Builder builder,
			final HttpServletRequest request,
			final boolean ignoreIPsInHeaders) {
		final String xFF = request.getHeader(X_FORWARDED_FOR);
		final String realIP = request.getHeader(X_REAL_IP);
		final String ip;
		if (!ignoreIPsInHeaders) {
			if (xFF != null && !xFF.isEmpty()) {
				ip = xFF.split(",")[0].trim();
			} else if (realIP != null && !realIP.isEmpty()) {
				ip = realIP.trim();
			} else {
				ip = request.getRemoteAddr();
			}
		} else {
			ip = request.getRemoteAddr();
		}
		try {
			builder.withIpAddress(InetAddress.getByName(ip));
		} catch (Exception e) {
			// do nothing
		}
	}
	
	public static boolean isIgnoreIPsInHeaders(final Authentication auth)
			throws AuthStorageException {
		try {
			return auth.getExternalConfig(new AuthExternalConfigMapper())
				.isIgnoreIPHeadersOrDefault();
		} catch (ExternalConfigMappingException e) {
			throw new RuntimeException("There appears to be a programming error here...", e);
		}
	}
	
	public static Map<String, String> getCustomContextFromString(final String customContext)
			throws IllegalParameterException {
		final Map<String, String> ret = new HashMap<>();
		if (customContext == null || customContext.trim().isEmpty()) {
			return ret;
		}
		final String[] items = customContext.trim().split(";");
		for (String item: items) {
			item = item.trim();
			if (!item.isEmpty()) {
				final String[] keyvalue = item.trim().split(",");
				if (keyvalue.length != 2) {
					throw new IllegalParameterException("Bad key/value pair in custom context: " +
							item);
				}
				ret.put(keyvalue[0].trim(), keyvalue[1].trim());
			}
		}
		return ret;
	}
	
	public static boolean nullOrEmpty(final String s) {
		return s == null || s.trim().isEmpty();
	}
}
