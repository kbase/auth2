package us.kbase.auth2.service.ui;

import static us.kbase.auth2.service.common.ServiceCommon.getToken;
import static us.kbase.auth2.service.ui.UIUtils.removeLoginCookie;
import static us.kbase.auth2.service.ui.UIUtils.getLoginInProcessCookie;
import static us.kbase.auth2.service.ui.UIUtils.getLinkInProcessCookie;
import static us.kbase.auth2.service.ui.UIUtils.getTokenFromCookie;
import static us.kbase.auth2.service.ui.UIUtils.relativize;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.glassfish.jersey.server.mvc.Template;
import org.glassfish.jersey.server.mvc.Viewable;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.service.AuthAPIStaticConfig;
import us.kbase.auth2.service.common.Fields;

@Path(UIPaths.LOGOUT_ROOT)
public class Logout {
	
	//TODO JAVADOC or swagger

	@Inject
	private Authentication auth;
	
	@Inject
	private AuthAPIStaticConfig cfg;
	
	@GET
	@Template(name = "/logout")
	public Map<String, String> logout(
			@Context final HttpHeaders headers,
			@Context final UriInfo uriInfo)
			throws AuthStorageException, NoTokenProvidedException, InvalidTokenException {
		final StoredToken ht = auth.getToken(
				getTokenFromCookie(headers, cfg.getTokenCookieName()));
		return ImmutableMap.of(Fields.USER, ht.getUserName().getName(),
				Fields.URL_LOGOUT, relativize(uriInfo, UIPaths.LOGOUT_ROOT));
	}
	
	@POST
	@Produces(MediaType.TEXT_HTML)
	public Response logoutResult(@Context final HttpHeaders headers)
			throws AuthStorageException, NoTokenProvidedException {
		final IncomingToken token = getTokenFromCookie(headers, cfg.getTokenCookieName());
		return Response.ok(
				new Viewable("/logoutresult", logout(token)))
				.cookie(removeLoginCookie(cfg.getTokenCookieName()))
				.cookie(getLoginInProcessCookie(null))
				.cookie(getLinkInProcessCookie(null))
				.build();
	}
	
	@POST
	@Produces(MediaType.APPLICATION_JSON)
	public Response logoutResultJSON(@HeaderParam(UIConstants.HEADER_TOKEN) final String token)
			throws NoTokenProvidedException, AuthStorageException {
		return Response.ok()
				.entity(logout(getToken(token)))
				.cookie(getLoginInProcessCookie(null))
				.cookie(getLinkInProcessCookie(null))
				.build();
	}

	private Map<String, String> logout(final IncomingToken token) throws AuthStorageException {
		final Optional<StoredToken> ht = auth.logout(token);
		final Map<String, String> ret = new HashMap<>();
		ret.put(Fields.USER, ht.isPresent() ? ht.get().getUserName().getName() : null);
		return ret;
	}

}
