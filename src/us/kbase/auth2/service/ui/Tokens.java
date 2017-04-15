package us.kbase.auth2.service.ui;

import static us.kbase.auth2.service.common.ServiceCommon.getCustomContextFromString;
import static us.kbase.auth2.service.common.ServiceCommon.getToken;
import static us.kbase.auth2.service.common.ServiceCommon.getTokenContext;
import static us.kbase.auth2.service.common.ServiceCommon.isIgnoreIPsInHeaders;
import static us.kbase.auth2.service.ui.UIUtils.getLoginCookie;
import static us.kbase.auth2.service.ui.UIUtils.getTokenFromCookie;
import static us.kbase.auth2.service.ui.UIUtils.relativize;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.TokenName;
import us.kbase.auth2.lib.token.TokenSet;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.service.AuthAPIStaticConfig;
import us.kbase.auth2.service.UserAgentParser;
import us.kbase.auth2.service.common.Fields;
import us.kbase.auth2.service.common.IncomingJSON;

@Path(UIPaths.TOKENS_ROOT)
public class Tokens {
	
	//TODO TEST
	//TODO JAVADOC

	@Inject
	private Authentication auth;
	
	@Inject
	private AuthAPIStaticConfig cfg;
	
	@Inject
	private UserAgentParser userAgentParser;
	
	@GET
	@Produces(MediaType.TEXT_HTML)
	@Template(name = "/tokens")
	public Map<String, Object> getTokensHTML(
			@Context final HttpHeaders headers,
			@Context final UriInfo uriInfo)
			throws AuthStorageException, InvalidTokenException,
			NoTokenProvidedException, UnauthorizedException {
		final Map<String, Object> t = getTokens(
				getTokenFromCookie(headers, cfg.getTokenCookieName()), uriInfo);
		return t;
	}
	
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> getTokensJSON(
			@HeaderParam(UIConstants.HEADER_TOKEN) final String headerToken,
			@Context final UriInfo uriInfo)
			throws AuthStorageException, InvalidTokenException,
			NoTokenProvidedException, UnauthorizedException {
		return getTokens(getToken(headerToken), uriInfo);
	}
	
	@POST
	@Path(UIPaths.TOKENS_CREATE)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.TEXT_HTML)
	@Template(name = "/tokencreate")
	public NewUIToken createTokenHTML(
			@Context final HttpServletRequest req,
			@Context final HttpHeaders headers,
			@FormParam(Fields.TOKEN_NAME) final String tokenName,
			@FormParam(Fields.TOKEN_TYPE) final String tokenType,
			@FormParam(Fields.CUSTOM_CONTEXT) final String customContext)
			throws AuthStorageException, MissingParameterException,
			NoTokenProvidedException, InvalidTokenException,
			UnauthorizedException, IllegalParameterException {
		return createtoken(req, tokenName, tokenType,
				getTokenFromCookie(headers, cfg.getTokenCookieName()),
				getCustomContextFromString(customContext));
	}
	
	private static class CreateTokenParams extends IncomingJSON {

		public final String name;
		public final String type;
		private final Map<String, String> customContext;
		
		@JsonCreator
		private CreateTokenParams(
				@JsonProperty(Fields.TOKEN_NAME) final String name,
				@JsonProperty(Fields.TOKEN_TYPE) final String type,
				@JsonProperty(Fields.CUSTOM_CONTEXT) final Map<String, String> customContext)
				throws MissingParameterException {
			this.name = name;
			this.type = type;
			this.customContext = customContext;
		}
		
		public Map<String, String> getCustomContext() {
			if (customContext == null) {
				return Collections.emptyMap();
			}
			return customContext;
		}
	}
	
	@POST
	@Path(UIPaths.TOKENS_CREATE)
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public NewUIToken createTokenJSON(
			@Context final HttpServletRequest req,
			@HeaderParam(UIConstants.HEADER_TOKEN) final String headerToken,
			final CreateTokenParams input)
			throws AuthStorageException, MissingParameterException,
			InvalidTokenException, NoTokenProvidedException,
			UnauthorizedException, IllegalParameterException {
		input.exceptOnAdditionalProperties();
		return createtoken(req, input.name, input.type, getToken(headerToken),
				input.getCustomContext());
	}
	
	@POST
	@Path(UIPaths.TOKENS_REVOKE_ID)
	public void revokeTokenPOST(
			@Context final HttpHeaders headers,
			@PathParam(UIPaths.TOKEN_ID) final UUID tokenId)
			throws AuthStorageException,
			NoSuchTokenException, NoTokenProvidedException,
			InvalidTokenException, UnauthorizedException {
		auth.revokeToken(getTokenFromCookie(headers, cfg.getTokenCookieName()), tokenId);
	}
	
	@DELETE
	@Path(UIPaths.TOKENS_REVOKE_ID)
	public void revokeTokenDELETE(
			@PathParam(UIPaths.TOKEN_ID) final UUID tokenId,
			@HeaderParam(UIConstants.HEADER_TOKEN) final String headerToken)
			throws AuthStorageException,
			NoSuchTokenException, NoTokenProvidedException,
			InvalidTokenException, UnauthorizedException {
		auth.revokeToken(getToken(headerToken), tokenId);
	}
	
	@POST
	@Path(UIPaths.TOKENS_REVOKE_ALL)
	public Response revokeAllAndLogout(@Context final HttpHeaders headers)
			throws AuthStorageException, NoTokenProvidedException,
			InvalidTokenException, UnauthorizedException {
		auth.revokeTokens(getTokenFromCookie(headers, cfg.getTokenCookieName()));
		return Response.ok().cookie(getLoginCookie(cfg.getTokenCookieName(), null)).build();
	}
	
	@DELETE
	@Path(UIPaths.TOKENS_REVOKE_ALL)
	public void revokeAll(
			@HeaderParam(UIConstants.HEADER_TOKEN) final String headerToken)
			throws AuthStorageException, NoTokenProvidedException,
			InvalidTokenException, UnauthorizedException {
		auth.revokeTokens(getToken(headerToken));
	}

	private NewUIToken createtoken(
			final HttpServletRequest req,
			final String tokenName,
			final String tokenType,
			final IncomingToken userToken,
			final Map<String, String> customContext)
			throws AuthStorageException, MissingParameterException,
			NoTokenProvidedException, InvalidTokenException,
			UnauthorizedException, IllegalParameterException {
		final TokenCreationContext tcc = getTokenContext(
				userAgentParser, req, isIgnoreIPsInHeaders(auth), customContext);
		return new NewUIToken(auth.createToken(userToken, new TokenName(tokenName),
				Fields.TOKEN_SERVICE.equals(tokenType) ? TokenType.SERV : TokenType.DEV, tcc));
	}

	private Map<String, Object> getTokens(final IncomingToken token, final UriInfo uriInfo)
			throws AuthStorageException, NoTokenProvidedException,
			InvalidTokenException, UnauthorizedException {
		final AuthUser au = auth.getUser(token);
		final TokenSet ts = auth.getTokens(token);
		final Map<String, Object> ret = new HashMap<>();
		ret.put(Fields.CURRENT, new UIToken(ts.getCurrentToken()));
		
		final List<UIToken> ats = ts.getTokens().stream()
				.map(t -> new UIToken(t)).collect(Collectors.toList());
		ret.put(Fields.TOKENS, ats);
		ret.put(Fields.TOKEN_DEV, Role.DEV_TOKEN.isSatisfiedBy(au.getRoles()));
		ret.put(Fields.TOKEN_SERVICE, Role.SERV_TOKEN.isSatisfiedBy(au.getRoles()));
		ret.put(Fields.USER, au.getUserName().getName());
		ret.put(Fields.URL_CREATE, relativize(uriInfo, UIPaths.TOKENS_ROOT_CREATE));
		ret.put(Fields.URL_REVOKE, relativize(uriInfo, UIPaths.TOKENS_ROOT_REVOKE +
				UIPaths.SEP));
		ret.put(Fields.URL_REVOKE_ALL, relativize(uriInfo, UIPaths.TOKENS_ROOT_REVOKE_ALL));
		return ret;
	}
}
