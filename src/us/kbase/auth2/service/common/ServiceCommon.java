package us.kbase.auth2.service.common;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.UserUpdate;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.service.exceptions.AuthConfigurationException;

/* methods that are useful for the UI and API */
public class ServiceCommon {

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
			throws IllegalParameterException, InvalidTokenException, AuthStorageException {
		final UserUpdate uu = new UserUpdate();
		try {
			if (displayName != null && !displayName.isEmpty()) {
				uu.withDisplayName(new DisplayName(displayName));
			}
			if (email != null && !email.isEmpty()) {
				uu.withEmail(new EmailAddress(email));
			}
		} catch (MissingParameterException mpe) {
			throw new RuntimeException("This is impossible", mpe);
		}
		auth.updateUser(token, uu);
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

}
