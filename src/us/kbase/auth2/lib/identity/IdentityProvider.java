package us.kbase.auth2.lib.identity;

import java.net.URI;
import java.net.URL;
import java.util.Set;

import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;
import us.kbase.auth2.lib.token.IncomingToken;

public interface IdentityProvider {

	//TODO JAVADOC
	
	String getProviderName();
	URI getImageURI();
	//note state will be url encoded.
	URL getLoginURL(String state, boolean link);
	String getAuthCodeQueryParamName();
	Set<RemoteIdentity> getIdentities(String authcode, boolean link)
			throws IdentityRetrievalException;
	// note incoming token is a provider token, not a local token
	RemoteIdentity getIdentity(IncomingToken providerToken, String user)
			throws IdentityRetrievalException;
	
}
