package us.kbase.auth2.service.ui;

import static us.kbase.auth2.service.common.ServiceCommon.getToken;
import static us.kbase.auth2.service.common.ServiceCommon.updateUser;
import static us.kbase.auth2.service.ui.UIUtils.getRolesFromForm;
import static us.kbase.auth2.service.ui.UIUtils.getTokenFromCookie;
import static us.kbase.auth2.service.ui.UIUtils.relativize;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
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
import com.google.common.collect.ImmutableMap;

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
import us.kbase.auth2.service.common.Fields;
import us.kbase.auth2.service.common.IncomingJSON;

@Path(UIPaths.ME_ROOT)
public class Me {

	//TODO JAVADOC or swagger
	
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
		ret.put(Fields.URL_USER_UPDATE, relativize(uriInfo, UIPaths.ME_ROOT));
		ret.put(Fields.URL_UNLINK, relativize(uriInfo, UIPaths.ME_ROOT_UNLINK));
		ret.put(Fields.URL_ROLE, relativize(uriInfo, UIPaths.ME_ROOT_ROLES));
		ret.put(Fields.USER, u.getUserName().getName());
		ret.put(Fields.ANONYMOUS_ID, u.getAnonymousID().toString());
		ret.put(Fields.LOCAL, u.isLocal());
		ret.put(Fields.DISPLAY, u.getDisplayName().getName());
		ret.put(Fields.EMAIL, u.getEmail().getAddress());
		ret.put(Fields.CREATED, u.getCreated().toEpochMilli());
		final Optional<Instant> ll = u.getLastLogin();
		ret.put(Fields.LAST_LOGIN, ll.isPresent() ? ll.get().toEpochMilli() : null);
		ret.put(Fields.CUSTOM_ROLES, u.getCustomRoles());
		ret.put(Fields.UNLINK, u.getIdentities().size() > 1);
		final List<Map<String, String>> roles = new LinkedList<>();
		for (final Role r: u.getRoles()) {
			final Map<String, String> role = new HashMap<>();
			role.put(Fields.ID, r.getID());
			role.put(Fields.DESCRIPTION, r.getDescription());
			roles.add(role);
		}
		ret.put(Fields.ROLES, roles);
		ret.put(Fields.HAS_ROLES, !roles.isEmpty());
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
	
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public void update(
			@Context final HttpHeaders headers,
			@FormParam(Fields.DISPLAY) final String displayName,
			@FormParam(Fields.EMAIL) final String email)
			throws NoTokenProvidedException, InvalidTokenException, AuthStorageException,
				IllegalParameterException, UnauthorizedException {
		updateUser(auth, getTokenFromCookie(headers, cfg.getTokenCookieName()),
				displayName, email);
	}
	
	private static class Update extends IncomingJSON {
		
		public final String display;
		public final String email;
		
		@JsonCreator
		public Update(
				@JsonProperty(Fields.DISPLAY) final String display,
				@JsonProperty(Fields.EMAIL) final String email) {
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
				IllegalParameterException, MissingParameterException, UnauthorizedException {
		
		if (update == null) {
			throw new MissingParameterException("JSON body missing");
		}
		update.exceptOnAdditionalProperties();
		updateUser(auth, getToken(token), update.display, update.email);
	}
	
	@POST // not DELETE since non-idempotent, diff results based on # of IDs the user has
	@Path(UIPaths.ME_UNLINK_ID)
	public void unlink(
			@Context final HttpHeaders headers,
			@HeaderParam(UIConstants.HEADER_TOKEN) final String headerToken,
			@PathParam(Fields.ID) final String id)
			throws NoTokenProvidedException, InvalidTokenException, AuthStorageException,
				UnLinkFailedException, NoSuchIdentityException, UnauthorizedException,
				MissingParameterException {
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
		public RolesToRemove(@JsonProperty(Fields.ROLES) final List<String> roles) {
			this.roles = roles;
		}
		
		public Set<Role> getRoles() throws NoSuchRoleException {
			if (roles == null || roles.isEmpty()) {
				return Collections.emptySet();
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
	
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	@Path(UIPaths.ME_ROLES)
	public void removeRoles(
			@HeaderParam(UIConstants.HEADER_TOKEN) final String headerToken,
			final RolesToRemove roles)
			throws AuthStorageException, UnauthorizedException, InvalidTokenException,
				NoTokenProvidedException, MissingParameterException, NoSuchRoleException {
		if (roles == null) {
			throw new MissingParameterException("JSON body missing");
		}
		final IncomingToken token = getToken(headerToken);
		auth.removeRoles(token, roles.getRoles());
	}
}
