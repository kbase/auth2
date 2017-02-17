package us.kbase.auth2.service.ui;

import static us.kbase.auth2.service.common.ServiceCommon.updateUser;
import static us.kbase.auth2.service.ui.UIUtils.getRolesFromForm;
import static us.kbase.auth2.service.ui.UIUtils.getTokenFromCookie;
import static us.kbase.auth2.service.ui.UIUtils.relativize;

import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.inject.Inject;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriInfo;

import org.glassfish.jersey.server.mvc.Template;

import us.kbase.auth2.lib.AuthUser;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnLinkFailedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.service.AuthAPIStaticConfig;

@Path(UIPaths.ME_ROOT)
public class Me {

	//TODO TEST
	//TODO JAVADOC
	
	@Inject
	private Authentication auth;
	
	@Inject
	private AuthAPIStaticConfig cfg;
	
	@GET
	@Template(name = "/me")
	public Map<String, Object> me(
			@Context final HttpHeaders headers,
			@Context final UriInfo uriInfo)
			throws NoTokenProvidedException, InvalidTokenException,
			AuthStorageException, DisabledUserException {
		final AuthUser u = auth.getUser(getTokenFromCookie(headers, cfg.getTokenCookieName()));
		final Map<String, Object> ret = new HashMap<>();
		ret.put("userupdateurl", relativize(uriInfo, UIPaths.ME_ROOT));
		ret.put("unlinkprefixurl", relativize(uriInfo, UIPaths.ME_ROOT));
		ret.put("rolesurl", relativize(uriInfo, UIPaths.ME_ROOT_ROLES));
		ret.put("user", u.getUserName().getName());
		ret.put("local", u.isLocal());
		ret.put("display", u.getDisplayName().getName());
		ret.put("email", u.getEmail().getAddress());
		ret.put("created", u.getCreated().getTime());
		final Date ll = u.getLastLogin();
		ret.put("lastlogin", ll == null ? null : ll.getTime());
		ret.put("customroles", u.getCustomRoles());
		ret.put("unlink", u.getIdentities().size() > 1);
		final List<Map<String, String>> roles = new LinkedList<>();
		for (final Role r: u.getRoles()) {
			final Map<String, String> role = new HashMap<>();
			role.put("id", r.getID());
			role.put("desc", r.getDescription());
			roles.add(role);
		}
		ret.put("roles", roles);
		ret.put("hasRoles", !roles.isEmpty());
		final List<Map<String, String>> idents = new LinkedList<>();
		ret.put("idents", idents);
		for (final RemoteIdentityWithLocalID ri: u.getIdentities()) {
			final Map<String, String> i = new HashMap<>();
			i.put("provider", ri.getRemoteID().getProvider());
			i.put("username", ri.getDetails().getUsername());
			i.put("id", ri.getID().toString());
			idents.add(i);
		}
		return ret;
	}
	
	@POST
	public void update(
			@Context final HttpHeaders headers,
			@FormParam("display") final String displayName,
			@FormParam("email") final String email)
			throws NoTokenProvidedException, InvalidTokenException, AuthStorageException,
			IllegalParameterException {
		updateUser(auth, getTokenFromCookie(headers, cfg.getTokenCookieName()),
				displayName, email);
	}
	
	@POST
	@Path(UIPaths.ME_PARAM_ID)
	public void unlink(
			@Context final HttpHeaders headers,
			@PathParam("id") final UUID id)
			throws NoTokenProvidedException, InvalidTokenException,
			AuthStorageException, UnLinkFailedException, DisabledUserException {
		// id can't be null
		auth.unlink(getTokenFromCookie(headers, cfg.getTokenCookieName()), id);
	}
	
	@POST
	@Path(UIPaths.ME_ROLES)
	public void removeRoles(
			@Context final HttpHeaders headers,
			final MultivaluedMap<String, String> form)
			throws NoSuchUserException, AuthStorageException, UnauthorizedException,
			InvalidTokenException, NoTokenProvidedException {
		final IncomingToken token = getTokenFromCookie(headers, cfg.getTokenCookieName());
		auth.removeRoles(token, getRolesFromForm(form));
	}
}
