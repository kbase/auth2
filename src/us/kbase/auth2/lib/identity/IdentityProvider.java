package us.kbase.auth2.lib.identity;

import java.net.URL;
import java.util.Set;

import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;
import us.kbase.auth2.lib.exceptions.NoSuchEnvironmentException;

/** A provider of OAuth2 identities, for example Google, Globus, Facebook etc.
 * @author gaprice@lbl.gov
 * 
 * @see IdentityProviderFactory
 *
 */
public interface IdentityProvider {

	/** Get the name and storage key of the identity provider.
	 * This value is used as the unique identity provider ID in the authentication storage system.
	 * Changing the value for a provider will prevent users from accessing their accounts if the
	 * database is not also updated.
	 * @return the identity provider's name.
	 */
	String getProviderName();
	
	/** Get the url to which a user should be redirected to log in to the identity provider.
	 * @param state the OAuth2 state variable, generally random data large enough to be
	 * unguessable. The state will be url encoded.
	 * @param link whether the user should be redirected to a login or link url after completion of
	 * login at the identity provider.
	 * @param environment the name of the environment to use when configuring the redirect
	 * url. Pass null for the default environment.
	 * @return a login url for the identity provider.
	 * @throws NoSuchEnvironmentException if there is no such environment configured.
	 */
	URL getLoginURL(String state, boolean link, String environment)
			throws NoSuchEnvironmentException;
	
	/** Get a set of identities from an identity provider given an identity provider authcode.
	 * @param authcode the authcode returned from the identity provider on the redirect after
	 * login.
	 * @param link whether the authcode was associated with a login or link url.
	 * @param environment the name of the environment that was used when configuring the redirect
	 * url. Pass null for the default environment.
	 * @return the set of identities returned from the provider.
	 * @throws IdentityRetrievalException if getting the idenities failed.
	 * @throws NoSuchEnvironmentException if there is no such environment configured. 
	 */
	Set<RemoteIdentity> getIdentities(String authcode, boolean link, String environment)
			throws IdentityRetrievalException, NoSuchEnvironmentException;
	
	/** Get the names of the additional environments beyond the default environment that are
	 * configured. See {@link #getLoginURL(String, boolean, String)}.
	 * @return the environments.
	 */
	Set<String> getEnvironments();
}
