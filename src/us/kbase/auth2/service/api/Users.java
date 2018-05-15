package us.kbase.auth2.service.api;

import static us.kbase.auth2.service.common.ServiceCommon.getToken;
import static us.kbase.auth2.service.common.ServiceCommon.nullOrEmpty;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

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
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.UserSearchSpec;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.service.common.Fields;

@Path(APIPaths.API_V2_USERS)
public class Users {
	
	//TODO JAVADOC or swagger

	@Inject
	private Authentication auth;

	/* It's completely stupid, but to pass a list in a query param in Jersey you have to do
	 * ?user=foo&user=bar&user=baz etc.
	 */
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, String> getUsers(
			@HeaderParam(APIConstants.HEADER_TOKEN) final String token,
			@QueryParam(Fields.LIST) final String users)
			throws IllegalParameterException, NoTokenProvidedException,
			InvalidTokenException, AuthStorageException {
		final Set<UserName> uns = processUserListString(users);
		final Map<UserName, DisplayName> dns = auth.getUserDisplayNames(getToken(token), uns);
		return dns.entrySet().stream().collect(
				Collectors.toMap(e -> e.getKey().getName(), e -> e.getValue().getName()));
	}

	static Set<UserName> processUserListString(final String users)
			throws IllegalParameterException {
		final Set<UserName> uns = new HashSet<>();
		if (nullOrEmpty(users)) {
			return uns;
		}
		final String[] usersplt = users.split(",");
		for (final String u: usersplt) {
			try {
				uns.add(new UserName(u.trim()));
			} catch (MissingParameterException | IllegalParameterException e) {
				//TODO CODE this exception could use some clean up
				throw new IllegalParameterException(ErrorType.ILLEGAL_USER_NAME, String.format(
						"Illegal user name [%s]: %s", u, e.getMessage()));
			}
		}
		return uns;
	}
	
	@GET
	@Path(APIPaths.USERS_SEARCH)
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, String> getUsersByPrefix(
			@HeaderParam(APIConstants.HEADER_TOKEN) final String token,
			@PathParam(APIPaths.PREFIX) final String prefix,
			@QueryParam(Fields.FIELDS) final String fields)
			throws InvalidTokenException, NoTokenProvidedException, AuthStorageException,
				IllegalParameterException {
		
		//prefix cannot be null or empty since it's a path param
		final UserSearchSpec.Builder build = UserSearchSpec.getBuilder();
		build.withSearchPrefix(prefix);
		if (!nullOrEmpty(fields)) {
			final String[] splitFields = fields.split(",");
			for (String s: splitFields) {
				s = s.trim();
				if (s.equals(Fields.SEARCH_USER)) {
					build.withSearchOnUserName(true);
				} else if (s.equals(Fields.SEARCH_DISPLAY)) {
					build.withSearchOnDisplayName(true);
				}
			}
		}
		try {
			final Map<UserName, DisplayName> dns = auth.getUserDisplayNames(
					getToken(token), build.build());
			return dns.entrySet().stream().collect(
					Collectors.toMap(e -> e.getKey().getName(), e -> e.getValue().getName()));
		} catch (UnauthorizedException e) {
			throw new RuntimeException("this should be impossible", e);
		}
	}
}
