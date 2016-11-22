package us.kbase.auth2.lib.identity;

import java.net.URI;
import java.net.URL;
import java.util.Set;

import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;

public interface IdentityProvider {

	//TODO JAVADOC
	
	String getProviderName();
	URI getImageURI();
	//note state will be url encoded.
	URL getLoginURL(String state, boolean link);
	Set<RemoteIdentity> getIdentities(String authcode, boolean link)
			throws IdentityRetrievalException;
}
