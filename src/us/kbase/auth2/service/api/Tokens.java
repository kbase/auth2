package us.kbase.auth2.service.api;

import static us.kbase.auth2.service.api.APIUtils.getLoginCookie;
import static us.kbase.auth2.service.api.APIUtils.getToken;
import static us.kbase.auth2.service.api.APIUtils.getTokenFromCookie;
import static us.kbase.auth2.service.api.APIUtils.relativize;

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
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.TokenSet;
import us.kbase.auth2.service.AuthAPIStaticConfig;

@Path("/tokens")
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
			NoTokenProvidedException {
		final Map<String, Object> t = getTokens(
				getTokenFromCookie(headers, cfg.getTokenCookieName()));
		t.put("user", ((APIToken) t.get("current")).getUser());
		t.put("targeturl", relativize(uriInfo, "/tokens/create"));
		t.put("tokenurl", relativize(uriInfo, "/tokens/"));
		t.put("revokeallurl", relativize(uriInfo, "/tokens/revokeall"));
		return t;
	}
	
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> getTokensJSON(
			@Context final HttpHeaders headers,
			@HeaderParam("authentication") final String headerToken)
			throws AuthStorageException, InvalidTokenException,
			NoTokenProvidedException {
		final IncomingToken cookieToken = getTokenFromCookie(
				headers, cfg.getTokenCookieName(), false);
		return getTokens(cookieToken == null ? getToken(headerToken) : cookieToken);
	}
	
	@POST
	@Path("/create")
	@Produces(MediaType.TEXT_HTML)
	@Template(name = "/tokencreate")
	public APINewToken createTokenHTML(
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
	@Path("/create")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public APINewToken createTokenJSON(
			@Context final HttpHeaders headers,
			@HeaderParam("authentication") final String headerToken,
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
	@Path("/{tokenid}")
	public void revokeTokenPOST(
			@Context final HttpHeaders headers,
			@PathParam("tokenid") final UUID tokenId)
			throws AuthStorageException,
			NoSuchTokenException, NoTokenProvidedException,
			InvalidTokenException {
		auth.revokeToken(getTokenFromCookie(headers, cfg.getTokenCookieName()), tokenId);
	}
	
	@DELETE
	@Path("/{tokenid}")
	public void revokeTokenDELETE(
			@PathParam("tokenid") final UUID tokenId,
			@Context final HttpHeaders headers,
			@HeaderParam("authentication") final String headerToken)
			throws AuthStorageException,
			NoSuchTokenException, NoTokenProvidedException,
			InvalidTokenException {
		final IncomingToken cookieToken = getTokenFromCookie(
				headers, cfg.getTokenCookieName(), false);
		auth.revokeToken(cookieToken == null ? getToken(headerToken) : cookieToken, tokenId);
	}
	
	@POST
	@Path("/revokeall")
	public Response revokeAllAndLogout(@Context final HttpHeaders headers)
			throws AuthStorageException, NoTokenProvidedException,
			InvalidTokenException {
		auth.revokeTokens(getTokenFromCookie(headers, cfg.getTokenCookieName()));
		return Response.ok().cookie(getLoginCookie(cfg.getTokenCookieName(), null)).build();
	}
	
	@DELETE
	@Path("/revokeall")
	public void revokeAll(
			@Context final HttpHeaders headers,
			@HeaderParam("authentication") final String headerToken)
			throws AuthStorageException, NoTokenProvidedException,
			InvalidTokenException {
		final IncomingToken cookieToken = getTokenFromCookie(
				headers, cfg.getTokenCookieName(), false);
		auth.revokeTokens(cookieToken == null ? getToken(headerToken) : cookieToken);
	}
			

	private APINewToken createtoken(
			final String tokenName,
			final String tokenType,
			final IncomingToken userToken)
			throws AuthStorageException, MissingParameterException,
			NoTokenProvidedException, InvalidTokenException,
			UnauthorizedException {
		return new APINewToken(auth.createToken(userToken, tokenName, "server".equals(tokenType)));
	}

	private Map<String, Object> getTokens(final IncomingToken token)
			throws AuthStorageException, NoTokenProvidedException,
			InvalidTokenException {
		final AuthUser au = auth.getUser(token);
		final TokenSet ts = auth.getTokens(token);
		final Map<String, Object> ret = new HashMap<>();
		ret.put("current", new APIToken(ts.getCurrentToken()));
		
		final List<APIToken> ats = ts.getTokens().stream()
				.map(t -> new APIToken(t)).collect(Collectors.toList());
		ret.put("tokens", ats);
		ret.put("dev", Role.DEV_TOKEN.isSatisfiedBy(au.getRoles()));
		ret.put("serv", Role.SERV_TOKEN.isSatisfiedBy(au.getRoles()));
		return ret;
	}
}
