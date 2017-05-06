package us.kbase.auth2.service.api;

import static us.kbase.auth2.service.common.ServiceCommon.getToken;
import static us.kbase.auth2.service.common.ServiceCommon.updateUser;

import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableMap;


import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.service.common.Fields;

@Path(APIPaths.API_V2_ME)
public class Me {
	
	//TODO TEST
	//TODO JAVADOC or swagger
	
	@Inject
	private Authentication auth;
	
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> me(@HeaderParam(APIConstants.HEADER_TOKEN) final String token)
			throws NoTokenProvidedException, InvalidTokenException, AuthStorageException,
			DisabledUserException {
		// this code is almost identical to ui.Me but I don't want to couple the API and UI outputs
		final AuthUser u = auth.getUser(getToken(token));
		final Map<String, Object> ret = new HashMap<String, Object>();
		ret.put(Fields.USER, u.getUserName().getName());
		ret.put(Fields.LOCAL, u.isLocal());
		ret.put(Fields.DISPLAY, u.getDisplayName().getName());
		ret.put(Fields.EMAIL, u.getEmail().getAddress());
		ret.put(Fields.CREATED, u.getCreated().toEpochMilli());
		final Optional<Instant> ll = u.getLastLogin();
		ret.put(Fields.LAST_LOGIN, ll.isPresent() ? ll.get().toEpochMilli() : null);
		ret.put(Fields.CUSTOM_ROLES, u.getCustomRoles());
		final List<Map<String, String>> roles = new LinkedList<>();
		for (final Role r: u.getRoles()) {
			final Map<String, String> role = new HashMap<>();
			role.put(Fields.ID, r.getID());
			role.put(Fields.DESCRIPTION, r.getDescription());
			roles.add(role);
		}
		ret.put(Fields.ROLES, roles);
		final List<Map<String, String>> idents = new LinkedList<>();
		ret.put(Fields.IDENTITIES, idents);
		for (final RemoteIdentity ri: u.getIdentities()) {
			final Map<String, String> i = new HashMap<>();
			i.put(Fields.PROVIDER, ri.getRemoteID().getProviderName());
			i.put(Fields.PROV_USER, ri.getDetails().getUsername());
			i.put(Fields.ID, ri.getRemoteID().getID());
			idents.add(i);
		}
		ret.put(Fields.POLICY_IDS, u.getPolicyIDs().keySet().stream().map(id -> ImmutableMap.of(
			Fields.ID, id.getName(),
			Fields.AGREED_ON, u.getPolicyIDs().get(id).toEpochMilli()))
			.collect(Collectors.toSet()));
		return ret;
	}
	
	@PUT
	@Consumes(MediaType.APPLICATION_JSON)
	public void updateJSON(
			@HeaderParam(APIConstants.HEADER_TOKEN) final String token,
			final Map<String, String> params)
			throws NoTokenProvidedException, InvalidTokenException, AuthStorageException,
			IllegalParameterException, UnauthorizedException {
		updateUser(auth, getToken(token), params.get(Fields.DISPLAY), params.get(Fields.EMAIL));
	}
}
