package us.kbase.auth2.service.api;

import static us.kbase.auth2.service.common.ServiceCommon.getToken;
import static us.kbase.auth2.service.common.ServiceCommon.nullOrEmpty;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.service.common.Fields;

@Path(APIPaths.API_V2_ADMIN)
public class Admin {
	
	// TODO JAVADOC or better OpenAPI
	
	private final Authentication auth;
	
	@Inject
	public Admin(final Authentication auth) {
		this.auth = auth;
	}
	
	@GET
	@Path(APIPaths.ANONYMOUS_ID_LOOKUP)
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, String> anonIDsToUserNames(
			@HeaderParam(APIConstants.HEADER_TOKEN) final String token,
			@QueryParam(Fields.LIST) final String anonymousIDs)
			throws NoTokenProvidedException, InvalidTokenException, AuthStorageException,
				DisabledUserException, IllegalParameterException, UnauthorizedException {
		final Set<UUID> ids = processAnonymousIDListString(anonymousIDs);
		final Map<UUID, UserName> map = auth.getUserNamesFromAnonymousIDs(getToken(token), ids);
		return map.keySet().stream().collect(
				Collectors.toMap(k -> k.toString(), k -> map.get(k).getName()));
	}
	
	static Set<UUID> processAnonymousIDListString(final String anonIDs)
			throws IllegalParameterException {
		if (nullOrEmpty(anonIDs)) {
			return Collections.emptySet();
		}
		final Set<UUID> ids = new HashSet<>();
		for (final String id: anonIDs.split(",")) {
			try {
				ids.add(UUID.fromString(id.trim()));
			} catch (IllegalArgumentException e) {
				throw new IllegalParameterException(String.format(
						"Illegal anonymous user ID [%s]: %s", id.trim(), e.getMessage()));
			}
		}
		return ids;
	}

}
