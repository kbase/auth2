package us.kbase.auth2.service.ui;

import static us.kbase.auth2.service.ui.UIUtils.removeLoginCookie;
import static us.kbase.auth2.service.ui.UIUtils.getTokenFromCookie;
import static us.kbase.auth2.service.ui.UIUtils.relativize;

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

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.service.AuthAPIStaticConfig;
import us.kbase.auth2.service.common.Fields;

@Path(UIPaths.LOGOUT_ROOT)
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
		final StoredToken ht = auth.getToken(
				getTokenFromCookie(headers, cfg.getTokenCookieName()));
		return ImmutableMap.of(Fields.USER, ht.getUserName().getName(),
				Fields.URL_LOGOUT, relativize(uriInfo, UIPaths.LOGOUT_ROOT_RESULT));
	}
	
	@POST
	@Path(UIPaths.LOGOUT_RESULT)
	public Response logoutResult(@Context final HttpHeaders headers)
			throws AuthStorageException, NoTokenProvidedException {
		final Optional<StoredToken> ht = auth.revokeToken(
				getTokenFromCookie(headers, cfg.getTokenCookieName()));
		return Response.ok(
				new Viewable("/logoutresult", ImmutableMap.of(Fields.USER, ht.isPresent() ?
						ht.get().getUserName().getName() : null)))
				.cookie(removeLoginCookie(cfg.getTokenCookieName()))
				.build();
	}
}
