package us.kbase.auth2.service.api;

import static us.kbase.auth2.service.common.ServiceCommon.getToken;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.SearchField;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;

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
			@HeaderParam(APIConstants.HEADER_TOKEN) final String token,
			@QueryParam("list") final String users)
			throws MissingParameterException, IllegalParameterException, NoTokenProvidedException,
			InvalidTokenException, AuthStorageException {
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
		final Map<UserName, DisplayName> dns = auth.getUserDisplayNames(getToken(token), uns);
		for (final Entry<UserName, DisplayName> e: dns.entrySet()) {
			ret.put(e.getKey().getName(), e.getValue().getName());
		}
		return ret;
	}
	
	@GET
	@Path(APIPaths.USERS_SEARCH)
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, String> getUsersByPrefix(
			@HeaderParam(APIConstants.HEADER_TOKEN) final String token,
			@PathParam("prefix") final String prefix,
			@QueryParam("fields") final String fields)
			throws InvalidTokenException, NoTokenProvidedException, AuthStorageException,
			IllegalParameterException {
		//TODO NOW limit to 10K names
		final Set<SearchField> searchFields = new HashSet<>();
		if (fields != null) {
			final String[] splitFields = fields.split(",");
			for (String s: splitFields) {
				s = s.trim();
				if (s.equals("username")) {
					searchFields.add(SearchField.USERNAME);
				} else if (s.equals("displayname")) {
					searchFields.add(SearchField.DISPLAYNAME);
				}
			}
		}
		final Map<UserName, DisplayName> dns = auth.getUserDisplayNames(
				getToken(token), prefix, searchFields);
		final Map<String, String> ret = new HashMap<>();
		for (final Entry<UserName, DisplayName> e: dns.entrySet()) {
			ret.put(e.getKey().getName(), e.getValue().getName());
		}
		return ret;
	}
}
