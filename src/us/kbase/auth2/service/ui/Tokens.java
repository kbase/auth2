package us.kbase.auth2.service.ui;

import static us.kbase.auth2.service.common.ServiceCommon.getToken;
import static us.kbase.auth2.service.ui.UIUtils.getLoginCookie;
import static us.kbase.auth2.service.ui.UIUtils.getTokenFromCookie;
import static us.kbase.auth2.service.ui.UIUtils.relativize;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.glassfish.jersey.server.mvc.Template;

import us.kbase.auth2.lib.AuthUser;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.TokenSet;
import us.kbase.auth2.service.AuthAPIStaticConfig;

@Path(UIPaths.TOKENS_ROOT)
public class Tokens {
	
	//TODO TEST
	//TODO JAVADOC

	@Inject
	private Authentication auth;
	
	@Inject
	private AuthAPIStaticConfig cfg;
	
	@GET
	@Produces(MediaType.TEXT_HTML)
	@Template(name = "/tokens")
	public Map<String, Object> getTokensHTML(
			@Context final HttpHeaders headers,
			@Context final UriInfo uriInfo)
			throws AuthStorageException, InvalidTokenException,
			NoTokenProvidedException, DisabledUserException {
		final Map<String, Object> t = getTokens(
				getTokenFromCookie(headers, cfg.getTokenCookieName()));
		t.put("user", ((UIToken) t.get("current")).getUser());
		t.put("createurl", relativize(uriInfo, UIPaths.TOKENS_ROOT_CREATE));
		t.put("revokeurl", relativize(uriInfo, UIPaths.TOKENS_ROOT_REVOKE +
				UIPaths.SEP));
		t.put("revokeallurl", relativize(uriInfo, UIPaths.TOKENS_ROOT_REVOKE_ALL));
		return t;
	}
	
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> getTokensJSON(
			@Context final HttpHeaders headers,
			@HeaderParam(UIConstants.HEADER_TOKEN) final String headerToken)
			throws AuthStorageException, InvalidTokenException,
			NoTokenProvidedException, DisabledUserException {
		final IncomingToken cookieToken = getTokenFromCookie(
				headers, cfg.getTokenCookieName(), false);
		return getTokens(cookieToken == null ? getToken(headerToken) : cookieToken);
	}
	
	@POST
	@Path(UIPaths.TOKENS_CREATE)
	@Produces(MediaType.TEXT_HTML)
	@Template(name = "/tokencreate")
	public UINewToken createTokenHTML(
			@Context final HttpHeaders headers,
			@FormParam("tokenname") final String tokenName,
			@FormParam("tokentype") final String tokenType)
			throws AuthStorageException, MissingParameterException,
			NoTokenProvidedException, InvalidTokenException,
			UnauthorizedException {
		return createtoken(tokenName, tokenType,
				getTokenFromCookie(headers, cfg.getTokenCookieName()));
	}
	
	@POST
	@Path(UIPaths.TOKENS_CREATE)
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public UINewToken createTokenJSON(
			@Context final HttpHeaders headers,
			@HeaderParam(UIConstants.HEADER_TOKEN) final String headerToken,
			final CreateTokenParams input)
			throws AuthStorageException, MissingParameterException,
			InvalidTokenException, NoTokenProvidedException,
			UnauthorizedException {
		final IncomingToken cookieToken = getTokenFromCookie(
				headers, cfg.getTokenCookieName(), false);
		return createtoken(input.getName(), input.getType(),
				cookieToken == null ? getToken(headerToken) : cookieToken);
	}
	
	@POST
	@Path(UIPaths.TOKENS_REVOKE_ID)
	public void revokeTokenPOST(
			@Context final HttpHeaders headers,
			@PathParam("tokenid") final UUID tokenId)
			throws AuthStorageException,
			NoSuchTokenException, NoTokenProvidedException,
			InvalidTokenException {
		auth.revokeToken(getTokenFromCookie(headers, cfg.getTokenCookieName()), tokenId);
	}
	
	@DELETE
	@Path(UIPaths.TOKENS_REVOKE_ID)
	public void revokeTokenDELETE(
			@PathParam("tokenid") final UUID tokenId,
			@Context final HttpHeaders headers,
			@HeaderParam(UIConstants.HEADER_TOKEN) final String headerToken)
			throws AuthStorageException,
			NoSuchTokenException, NoTokenProvidedException,
			InvalidTokenException {
		final IncomingToken cookieToken = getTokenFromCookie(
				headers, cfg.getTokenCookieName(), false);
		auth.revokeToken(cookieToken == null ? getToken(headerToken) : cookieToken, tokenId);
	}
	
	@POST
	@Path(UIPaths.TOKENS_REVOKE_ALL)
	public Response revokeAllAndLogout(@Context final HttpHeaders headers)
			throws AuthStorageException, NoTokenProvidedException,
			InvalidTokenException {
		auth.revokeTokens(getTokenFromCookie(headers, cfg.getTokenCookieName()));
		return Response.ok().cookie(getLoginCookie(cfg.getTokenCookieName(), null)).build();
	}
	
	@DELETE
	@Path(UIPaths.TOKENS_REVOKE_ALL)
	public void revokeAll(
			@Context final HttpHeaders headers,
			@HeaderParam(UIConstants.HEADER_TOKEN) final String headerToken)
			throws AuthStorageException, NoTokenProvidedException,
			InvalidTokenException {
		final IncomingToken cookieToken = getTokenFromCookie(
				headers, cfg.getTokenCookieName(), false);
		auth.revokeTokens(cookieToken == null ? getToken(headerToken) : cookieToken);
	}
			

	private UINewToken createtoken(
			final String tokenName,
			final String tokenType,
			final IncomingToken userToken)
			throws AuthStorageException, MissingParameterException,
			NoTokenProvidedException, InvalidTokenException,
			UnauthorizedException {
		return new UINewToken(auth.createToken(userToken, tokenName, "server".equals(tokenType)));
	}

	private Map<String, Object> getTokens(final IncomingToken token)
			throws AuthStorageException, NoTokenProvidedException,
			InvalidTokenException, DisabledUserException {
		final AuthUser au = auth.getUser(token);
		final TokenSet ts = auth.getTokens(token);
		final Map<String, Object> ret = new HashMap<>();
		ret.put("current", new UIToken(ts.getCurrentToken()));
		
		final List<UIToken> ats = ts.getTokens().stream()
				.map(t -> new UIToken(t)).collect(Collectors.toList());
		ret.put("tokens", ats);
		ret.put("dev", Role.DEV_TOKEN.isSatisfiedBy(au.getRoles()));
		ret.put("serv", Role.SERV_TOKEN.isSatisfiedBy(au.getRoles()));
		return ret;
	}
}
