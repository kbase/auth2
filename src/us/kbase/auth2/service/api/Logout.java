package us.kbase.auth2.service.api;

import static us.kbase.auth2.service.api.APIUtils.getLoginCookie;
import static us.kbase.auth2.service.api.APIUtils.getTokenFromCookie;
import static us.kbase.auth2.service.api.APIUtils.relativize;

import java.util.Map;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
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
import us.kbase.auth2.service.AuthAPIStaticConfig;

@Path("/logout")
public class Logout {

	@Inject
	private Authentication auth;
	
	@Inject
	private AuthAPIStaticConfig cfg;
	
	@GET
	@Template(name = "/logout")
	public Map<String, String> logout(
			@Context final HttpHeaders headers,
			@Context final UriInfo uriInfo)
			throws AuthStorageException, NoTokenProvidedException,
			InvalidTokenException {
		final HashedToken ht = auth.getToken(
				getTokenFromCookie(headers, cfg.getTokenCookieName()));
		return ImmutableMap.of("user", ht.getUserName().getName(),
				"logouturl", relativize(uriInfo, "/logout/result"));
	}
	
	@POST
	@Path("/result")
	public Response logoutResult(@Context final HttpHeaders headers)
			throws AuthStorageException, NoTokenProvidedException {
		final HashedToken ht = auth.revokeToken(
				getTokenFromCookie(headers, cfg.getTokenCookieName()));
		return Response.ok(
				new Viewable("/logoutresult",
						ImmutableMap.of("user", ht == null ? null : ht.getUserName().getName())))
				.cookie(getLoginCookie(cfg.getTokenCookieName(), null))
				.build();
	}
}
