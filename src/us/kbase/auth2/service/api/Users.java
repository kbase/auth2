package us.kbase.auth2.service.api;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;

@Path(APIPaths.API_V2_USERS)
public class Users {
	
	//TODO TEST
	//TODO JAVADOC

	@Inject
	private Authentication auth;

	/* It's completely stupid, but to pass a list in a query param in Jersey you have to do
	 * ?user=foo&user=bar&user=baz etc.
	 */
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, String> getUsers(
			@HeaderParam("authorization") final String token,
			@QueryParam("list") final String users)
			throws MissingParameterException, IllegalParameterException, NoTokenProvidedException,
			InvalidTokenException, AuthStorageException {
		if (token == null || token.trim().isEmpty()) {
			throw new NoTokenProvidedException();
		}
		final Map<String, String> ret = new HashMap<>();
		if (users == null || users.trim().isEmpty()) {
			return ret;
		}
		final String[] usersplt = users.split(",");
		final Set<UserName> uns = new HashSet<>();
		for (final String u: usersplt) {
			try {
				uns.add(new UserName(u));
			} catch (MissingParameterException | IllegalParameterException e) {
				throw new IllegalParameterException(String.format("Illegal username [%s]: %s",
						u, e.getMessage()));
			}
		}
		final Map<UserName, DisplayName> dns = auth.getUserDisplayNames(
				new IncomingToken(token), uns);
		for (final Entry<UserName, DisplayName> e: dns.entrySet()) {
			ret.put(e.getKey().getName(), e.getValue().getName());
		}
		return ret;
	}
}
