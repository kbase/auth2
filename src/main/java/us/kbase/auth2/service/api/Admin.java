package us.kbase.auth2.service.api;

import static us.kbase.auth2.service.common.ServiceCommon.getToken;
import static us.kbase.auth2.service.common.ServiceCommon.nullOrEmpty;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.service.common.Fields;
import us.kbase.auth2.service.common.IncomingJSON;

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

	/** Request body for updating user roles. */
	public static class UpdateUserRoles extends IncomingJSON {

		public final List<String> addRoles;
		public final List<String> removeRoles;
		public final List<String> addCustomRoles;
		public final List<String> removeCustomRoles;

		@JsonCreator
		public UpdateUserRoles(
				@JsonProperty(Fields.ADD_ROLES) final List<String> addRoles,
				@JsonProperty(Fields.REMOVE_ROLES) final List<String> removeRoles,
				@JsonProperty(Fields.ADD_CUSTOM_ROLES) final List<String> addCustomRoles,
				@JsonProperty(Fields.REMOVE_CUSTOM_ROLES) final List<String> removeCustomRoles) {
			this.addRoles = addRoles;
			this.removeRoles = removeRoles;
			this.addCustomRoles = addCustomRoles;
			this.removeCustomRoles = removeCustomRoles;
		}
	}

	@PUT
	@Path(APIPaths.ADMIN_USER_ROLES)
	@Consumes(MediaType.APPLICATION_JSON)
	public void updateUserRoles(
			@HeaderParam(APIConstants.HEADER_TOKEN) final String token,
			@PathParam(APIPaths.USERNAME) final String userName,
			final UpdateUserRoles update)
			throws NoTokenProvidedException, InvalidTokenException, AuthStorageException,
				UnauthorizedException, NoSuchUserException, NoSuchRoleException,
				IllegalParameterException, MissingParameterException, DisabledUserException {

		if (update == null) {
			throw new MissingParameterException("JSON body missing");
		}
		update.exceptOnAdditionalProperties();

		final UserName user = new UserName(userName);

		// Convert string lists to appropriate sets, handling nulls
		final Set<Role> addRoles = toRoleSet(
				update.addRoles == null ? Collections.emptyList() : update.addRoles);
		final Set<Role> removeRoles = toRoleSet(
				update.removeRoles == null ? Collections.emptyList() : update.removeRoles);
		final Set<String> addCustomRoles = toStringSet(
				update.addCustomRoles == null ? Collections.emptyList() : update.addCustomRoles);
		final Set<String> removeCustomRoles = toStringSet(
				update.removeCustomRoles == null ? Collections.emptyList() : update.removeCustomRoles);

		// Update built-in roles if any specified
		if (!addRoles.isEmpty() || !removeRoles.isEmpty()) {
			auth.updateRoles(getToken(token), user, addRoles, removeRoles);
		}

		// Update custom roles if any specified
		if (!addCustomRoles.isEmpty() || !removeCustomRoles.isEmpty()) {
			auth.updateCustomRoles(getToken(token), user, addCustomRoles, removeCustomRoles);
		}
	}

	private Set<Role> toRoleSet(final List<String> roles) throws IllegalParameterException {
		final Set<Role> ret = new HashSet<>();
		for (final String role : roles) {
			if (role == null) {
				throw new IllegalParameterException("Null item in roles list");
			}
			try {
				ret.add(Role.getRole(role));
			} catch (IllegalArgumentException e) {
				throw new IllegalParameterException("Invalid role: " + role);
			}
		}
		return ret;
	}

	private Set<String> toStringSet(final List<String> items) throws IllegalParameterException {
		final Set<String> ret = new HashSet<>();
		for (final String item : items) {
			if (item == null) {
				throw new IllegalParameterException("Null item in custom roles list");
			}
			ret.add(item);
		}
		return ret;
	}

}
