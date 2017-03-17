package us.kbase.auth2.service.ui;

import static us.kbase.auth2.service.common.ServiceCommon.getToken;
import static us.kbase.auth2.service.common.ServiceCommon.updateUser;
import static us.kbase.auth2.service.ui.UIUtils.getRolesFromForm;
import static us.kbase.auth2.service.ui.UIUtils.getTokenFromCookie;
import static us.kbase.auth2.service.ui.UIUtils.relativize;

import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriInfo;

import org.glassfish.jersey.server.mvc.Template;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Optional;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnLinkFailedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.service.AuthAPIStaticConfig;
import us.kbase.auth2.service.common.IncomingJSON;

@Path(UIPaths.ME_ROOT)
public class Me {

	//TODO TEST
	//TODO JAVADOC
	
	@Inject
	private Authentication auth;
	
	@Inject
	private AuthAPIStaticConfig cfg;
	
	@GET
	@Produces(MediaType.TEXT_HTML)
	@Template(name = "/me")
	public Map<String, Object> me(
			@Context final HttpHeaders headers,
			@Context final UriInfo uriInfo)
			throws NoTokenProvidedException, InvalidTokenException,
			AuthStorageException, DisabledUserException {
		final IncomingToken token = getTokenFromCookie(headers, cfg.getTokenCookieName());
		return me(token, uriInfo);
	}
	
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> me(
			@HeaderParam(UIConstants.HEADER_TOKEN) final String token,
			@Context final UriInfo uriInfo)
			throws InvalidTokenException, DisabledUserException, NoTokenProvidedException,
			AuthStorageException {
		return me(getToken(token), uriInfo);
	}

	private Map<String, Object> me(final IncomingToken token, final UriInfo uriInfo)
			throws InvalidTokenException, AuthStorageException, DisabledUserException {
		final AuthUser u = auth.getUser(token);
		final Map<String, Object> ret = new HashMap<>();
		ret.put("userupdateurl", relativize(uriInfo, UIPaths.ME_ROOT));
		ret.put("unlinkurl", relativize(uriInfo, UIPaths.ME_ROOT_UNLINK));
		ret.put("rolesurl", relativize(uriInfo, UIPaths.ME_ROOT_ROLES));
		ret.put("user", u.getUserName().getName());
		ret.put("local", u.isLocal());
		ret.put("display", u.getDisplayName().getName());
		ret.put("email", u.getEmail().getAddress());
		ret.put("created", u.getCreated().toEpochMilli());
		final Optional<Instant> ll = u.getLastLogin();
		ret.put("lastlogin", ll.isPresent() ? ll.get().toEpochMilli() : null);
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
		for (final RemoteIdentity ri: u.getIdentities()) {
			final Map<String, String> i = new HashMap<>();
			i.put("provider", ri.getRemoteID().getProviderName());
			i.put("username", ri.getDetails().getUsername());
			i.put("id", ri.getRemoteID().getID());
			idents.add(i);
		}
		return ret;
	}
	
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public void update(
			@Context final HttpHeaders headers,
			@FormParam("display") final String displayName,
			@FormParam("email") final String email)
			throws NoTokenProvidedException, InvalidTokenException, AuthStorageException,
			IllegalParameterException {
		updateUser(auth, getTokenFromCookie(headers, cfg.getTokenCookieName()),
				displayName, email);
	}
	
	private static class Update extends IncomingJSON {
		
		public final String display;
		public final String email;
		
		@JsonCreator
		public Update(
				@JsonProperty("display") final String display,
				@JsonProperty("email") final String email) {
			this.display = display;
			this.email = email;
		}
	}
	
	@PUT
	@Consumes(MediaType.APPLICATION_JSON)
	public void update(
			@HeaderParam(UIConstants.HEADER_TOKEN) final String token,
			final Update update)
			throws NoTokenProvidedException, InvalidTokenException, AuthStorageException,
			IllegalParameterException, MissingParameterException {
		
		if (update == null) {
			throw new MissingParameterException("Missing JSON body");
		}
		update.exceptOnAdditionalProperties();
		updateUser(auth, getToken(token), update.display, update.email);
	}
	
	@POST // not DELETE since non-idempotent, diff results based on # of IDs the user has
	@Path(UIPaths.ME_UNLINK_ID)
	public void unlink(
			@Context final HttpHeaders headers,
			@HeaderParam(UIConstants.HEADER_TOKEN) final String headerToken,
			@PathParam("id") final String id)
			throws NoTokenProvidedException, InvalidTokenException, AuthStorageException,
			UnLinkFailedException, DisabledUserException, NoSuchIdentityException {
		// id can't be null
		final Optional<IncomingToken> token = getTokenFromCookie(
				headers, cfg.getTokenCookieName(), false);
		auth.unlink(token.isPresent() ? token.get() : getToken(headerToken), id);
	}
	
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Path(UIPaths.ME_ROLES)
	public void removeRoles(
			@Context final HttpHeaders headers,
			final MultivaluedMap<String, String> form)
			throws NoSuchUserException, AuthStorageException, UnauthorizedException,
			InvalidTokenException, NoTokenProvidedException {
		final IncomingToken token = getTokenFromCookie(headers, cfg.getTokenCookieName());
		auth.removeRoles(token, getRolesFromForm(form));
	}
	
	private static class RolesToRemove extends IncomingJSON {
		
		public List<String> roles;
		
		@JsonCreator
		public RolesToRemove(@JsonProperty("roles") final List<String> roles) {
			this.roles = roles;
		}
		
		public Set<Role> getRoles() throws MissingParameterException, IllegalParameterException,
				NoSuchRoleException {
			if (roles == null || roles.isEmpty()) {
				throw new MissingParameterException("No roles provided");
			}
			final Set<Role> newRoles = new HashSet<>();
			for (final String role: roles) {
				if (!Role.isRole(role)) {
					throw new NoSuchRoleException(role);
				}
				newRoles.add(Role.getRole(role));
			}
			return newRoles;
		}
	}
	
	@DELETE
	@Consumes(MediaType.APPLICATION_JSON)
	@Path(UIPaths.ME_ROLES)
	public void removeRoles(
			@HeaderParam(UIConstants.HEADER_TOKEN) final String headerToken,
			final RolesToRemove roles)
			throws NoSuchUserException, AuthStorageException, UnauthorizedException,
			InvalidTokenException, NoTokenProvidedException, MissingParameterException,
			IllegalParameterException, NoSuchRoleException {
		if (roles == null) {
			throw new MissingParameterException("Missing JSON body");
		}
		final IncomingToken token = getToken(headerToken);
		auth.removeRoles(token, roles.getRoles());
	}
}
