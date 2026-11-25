package us.kbase.auth2.service.api;

import static us.kbase.auth2.service.common.ServiceCommon.getToken;
import static us.kbase.auth2.service.common.ServiceCommon.nullOrEmpty;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.UserSearchSpec;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.user.AuthUser;
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

	@GET
	@Path(APIPaths.ADMIN_USERS)
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, String> searchUsers(
			@HeaderParam(APIConstants.HEADER_TOKEN) final String token,
			@QueryParam(Fields.SEARCH_PREFIX) final String prefix,
			@QueryParam(Fields.FIELDS) final String fields,
			@QueryParam(Fields.ROLES) final String roles,
			@QueryParam(Fields.CUSTOM_ROLES) final String customRoles)
			throws NoTokenProvidedException, InvalidTokenException, AuthStorageException,
				UnauthorizedException, IllegalParameterException {
		// including disabled users makes the library require an admin for every search here
		final UserSearchSpec.Builder build = UserSearchSpec.getBuilder()
				.withIncludeDisabled(true);
		if (!nullOrEmpty(prefix)) {
			build.withSearchPrefix(prefix);
			for (final String f: splitList(fields)) {
				if (f.equals(Fields.SEARCH_USER)) {
					build.withSearchOnUserName(true);
				} else if (f.equals(Fields.SEARCH_DISPLAY)) {
					build.withSearchOnDisplayName(true);
				}
			}
		}
		for (final Role r: toRoles(splitList(roles))) {
			build.withSearchOnRole(r);
		}
		for (final String r: splitList(customRoles)) {
			build.withSearchOnCustomRole(r);
		}
		final Map<UserName, DisplayName> users = auth.getUserDisplayNames(
				getToken(token), build.build());
		return users.entrySet().stream().collect(
				Collectors.toMap(e -> e.getKey().getName(), e -> e.getValue().getName()));
	}

	@GET
	@Path(APIPaths.ADMIN_USER)
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> getUser(
			@HeaderParam(APIConstants.HEADER_TOKEN) final String token,
			@PathParam(APIPaths.USERNAME) final String userName)
			throws NoTokenProvidedException, InvalidTokenException, AuthStorageException,
				UnauthorizedException, NoSuchUserException, MissingParameterException,
				IllegalParameterException {
		final AuthUser u = auth.getUserAsAdmin(getToken(token), new UserName(userName));
		final Map<String, Object> ret = new HashMap<>();
		ret.put(Fields.USER, u.getUserName().getName());
		ret.put(Fields.DISPLAY, u.getDisplayName().getName());
		ret.put(Fields.EMAIL, u.getEmail().getAddress());
		ret.put(Fields.LOCAL, u.isLocal());
		ret.put(Fields.CREATED, u.getCreated().toEpochMilli());
		ret.put(Fields.LAST_LOGIN, u.getLastLogin().map(Instant::toEpochMilli).orElse(null));
		ret.put(Fields.DISABLED, u.isDisabled());
		ret.put(Fields.DISABLED_REASON,
				u.getDisabledState().getDisabledReason().orElse(null));
		final List<Map<String, String>> roles = new LinkedList<>();
		for (final Role r: u.getRoles()) {
			final Map<String, String> role = new HashMap<>();
			role.put(Fields.ID, r.getID());
			role.put(Fields.DESCRIPTION, r.getDescription());
			roles.add(role);
		}
		ret.put(Fields.ROLES, roles);
		ret.put(Fields.CUSTOM_ROLES, u.getCustomRoles());
		return ret;
	}

	private static List<String> splitList(final String list) {
		if (nullOrEmpty(list)) {
			return Collections.emptyList();
		}
		final List<String> ret = new LinkedList<>();
		for (final String s: list.split(",")) {
			if (!s.trim().isEmpty()) {
				ret.add(s.trim());
			}
		}
		return ret;
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

	@POST
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
		final List<String> addRolesList = update.addRoles == null ?
				Collections.emptyList() : update.addRoles;
		final List<String> removeRolesList = update.removeRoles == null ?
				Collections.emptyList() : update.removeRoles;
		final List<String> addCustomList = update.addCustomRoles == null ?
				Collections.emptyList() : update.addCustomRoles;
		final List<String> removeCustomList = update.removeCustomRoles == null ?
				Collections.emptyList() : update.removeCustomRoles;

		noNulls(addRolesList, "Null item in roles");
		noNulls(removeRolesList, "Null item in roles");
		noNulls(addCustomList, "Null item in custom roles");
		noNulls(removeCustomList, "Null item in custom roles");

		final Set<Role> addRoles = toRoles(addRolesList);
		final Set<Role> removeRoles = toRoles(removeRolesList);

		// Update built-in roles if any specified
		if (!addRoles.isEmpty() || !removeRoles.isEmpty()) {
			auth.updateRoles(getToken(token), user, addRoles, removeRoles);
		}

		// Update custom roles if any specified
		if (!addCustomList.isEmpty() || !removeCustomList.isEmpty()) {
			auth.updateCustomRoles(
					getToken(token), user,
					new HashSet<>(addCustomList),
					new HashSet<>(removeCustomList));
		}
	}

	private Set<Role> toRoles(final List<String> roles) throws IllegalParameterException {
		final Set<Role> ret = new HashSet<>();
		for (final String role : roles) {
			try {
				ret.add(Role.getRole(role));
			} catch (IllegalArgumentException e) {
				throw new IllegalParameterException(e.getMessage(), e);
			}
		}
		return ret;
	}

	private void noNulls(final List<String> list, final String message)
			throws IllegalParameterException {
		for (final String item : list) {
			if (item == null) {
				throw new IllegalParameterException(message);
			}
		}
	}

}
