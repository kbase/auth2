package us.kbase.auth2.service.api;

import static us.kbase.auth2.service.api.APIUtils.getToken;
import static us.kbase.auth2.service.api.APIUtils.relativize;

import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.ws.rs.CookieParam;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.UriInfo;

import org.glassfish.jersey.server.mvc.Template;

import us.kbase.auth2.lib.AuthUser;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.UserUpdate;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnLinkFailedException;
import us.kbase.auth2.lib.identity.RemoteIdentityWithID;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;

@Path("/me")
public class Me {

	//TODO TEST
	//TODO JAVADOC
	
	@Inject
	private Authentication auth;
	
	@GET
	@Template(name = "/me")
	public Map<String, Object> me(
			@CookieParam("token") final String token,
			@Context final UriInfo uriInfo)
			throws NoTokenProvidedException, InvalidTokenException,
			AuthStorageException {
		//TODO CONFIG_USER handle keep logged in, private
		final AuthUser u = auth.getUser(getToken(token));
		final Map<String, Object> ret = new HashMap<>();
		ret.put("userupdateurl", relativize(uriInfo, "/me"));
		ret.put("unlinkprefixurl", relativize(uriInfo, "/me/"));
		ret.put("user", u.getUserName().getName());
		ret.put("local", u.isLocal());
		ret.put("fullname", u.getFullName());
		ret.put("email", u.getEmail());
		ret.put("created", u.getCreated().getTime());
		final Date ll = u.getLastLogin();
		ret.put("lastlogin", ll == null ? null : ll.getTime());
		ret.put("customroles", u.getCustomRoles());
		ret.put("unlink", u.getIdentities().size() > 1);
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
	
	@POST
	public void update(
			@CookieParam("token") final String token,
			@FormParam("fullname") final String fullname,
			@FormParam("email") final String email)
			throws NoTokenProvidedException, InvalidTokenException,
			AuthStorageException {
		//TODO INPUT check inputs
		//TODO CONFIG_USER handle keep logged in, private
		final UserUpdate uu = new UserUpdate().withEmail(email)
				.withFullName(fullname);
		auth.updateUser(getToken(token), uu);
	}
	
	@POST
	@Path("/{id}")
	public void unlink(
			@CookieParam("token") final String token,
			@PathParam("id") final UUID id)
			throws NoTokenProvidedException, InvalidTokenException,
			AuthStorageException, UnLinkFailedException {
		// id can't be null
		auth.unlink(getToken(token), id);
	}
}
