package us.kbase.auth2.service.api;

import static us.kbase.auth2.service.common.ServiceCommon.getToken;
import static us.kbase.auth2.service.common.ServiceCommon.updateUser;

import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import us.kbase.auth2.lib.AuthUser;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.identity.RemoteIdentityWithID;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;

@Path(APIPaths.API_V2_ME)
public class Me {
	
	//TODO TEST
	//TODO JAVADOC
	
	@Inject
	private Authentication auth;
	
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> me(@HeaderParam(APIConstants.HEADER_TOKEN) final String token)
			throws NoTokenProvidedException, InvalidTokenException, AuthStorageException {
		// this code is almost identical to ui.Me but I don't want to couple the API and UI outputs
		final AuthUser u = auth.getUser(getToken(token));
		final Map<String, Object> ret = new HashMap<String, Object>();
		ret.put("user", u.getUserName().getName());
		ret.put("local", u.isLocal());
		ret.put("display", u.getDisplayName().getName());
		ret.put("email", u.getEmail().getAddress());
		ret.put("created", u.getCreated().getTime());
		final Date ll = u.getLastLogin();
		ret.put("lastlogin", ll == null ? null : ll.getTime());
		ret.put("customroles", u.getCustomRoles());
		ret.put("roles", u.getRoles().stream().map(r -> r.getDescription())
				.collect(Collectors.toList()));
		final List<Map<String, String>> idents = new LinkedList<>();
		ret.put("idents", idents);
		for (final RemoteIdentityWithID ri: u.getIdentities()) {
			final Map<String, String> i = new HashMap<>();
			i.put("provider", ri.getRemoteID().getProvider());
			i.put("username", ri.getDetails().getUsername());
			i.put("id", ri.getID().toString());
			idents.add(i);
		}
		return ret;
	}
	
	@PUT
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public void updateForm(
			@HeaderParam(APIConstants.HEADER_TOKEN) final String token,
			@FormParam("display") final String displayName,
			@FormParam("email") final String email)
			throws NoTokenProvidedException, InvalidTokenException, AuthStorageException,
			IllegalParameterException {
		updateUser(auth, getToken(token), displayName, email);
	}
	
	@PUT
	@Consumes(MediaType.APPLICATION_JSON)
	public void updateJSON(
			@HeaderParam(APIConstants.HEADER_TOKEN) final String token,
			final Map<String, String> params)
			throws NoTokenProvidedException, InvalidTokenException, AuthStorageException,
			IllegalParameterException {
		updateUser(auth, getToken(token), params.get("display"), params.get("email"));
	}
}
