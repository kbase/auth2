package us.kbase.auth2.service.api;

import static us.kbase.auth2.service.api.APIUtils.getToken;
import static us.kbase.auth2.service.api.APIUtils.getLoginCookie;
import static us.kbase.auth2.service.api.APIUtils.relativize;

import java.util.Map;

import javax.inject.Inject;
import javax.ws.rs.CookieParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.glassfish.jersey.server.mvc.Template;
import org.glassfish.jersey.server.mvc.Viewable;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.HashedToken;

@Path("/logout")
public class Logout {

	@Inject
	private Authentication auth;
	
	@GET
	@Template(name = "/logout")
	public Map<String, String> logout(
			@CookieParam("token") final String token,
			@Context final UriInfo uriInfo)
			throws AuthStorageException, NoTokenProvidedException,
			InvalidTokenException {
		final HashedToken ht = auth.getToken(getToken(token));
		return ImmutableMap.of("user", ht.getUserName().getName(),
				"logouturl", relativize(uriInfo, "/logout/result"));
	}
	
	@POST
	@Path("/result")
	public Response logoutResult(
			@CookieParam("token") final String token)
			throws AuthStorageException, NoTokenProvidedException {
		final HashedToken ht = auth.revokeToken(getToken(token));
		return Response.ok(
				new Viewable("/logoutresult",
						ImmutableMap.of("user", ht == null ? null :
							ht.getUserName().getName())))
				.cookie(getLoginCookie(null))
				.build();
	}
}
