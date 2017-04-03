package us.kbase.auth2.service.api;

import static us.kbase.auth2.service.common.ServiceCommon.getToken;
import static us.kbase.auth2.service.common.ServiceCommon.getTokenContext;
import static us.kbase.auth2.service.common.ServiceCommon.isIgnoreIPsInHeaders;

import java.util.Collections;
import java.util.Map;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenName;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.service.UserAgentParser;
import us.kbase.auth2.service.common.IncomingJSON;

@Path(APIPaths.API_V2_TOKEN)
public class Token {

	//TODO TEST
	//TODO JAVADOC
	
	@Inject
	private Authentication auth;
	
	@Inject
	private UserAgentParser userAgentParser;
	
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public APIToken viewToken(
			@HeaderParam(APIConstants.HEADER_TOKEN) final String token)
			throws NoTokenProvidedException, InvalidTokenException, AuthStorageException {
		final StoredToken ht = auth.getToken(getToken(token));
		return new APIToken(ht, auth.getSuggestedTokenCacheTime());
	}
	
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.APPLICATION_JSON)
	public NewAPIToken createAgentTokenForm(
			@Context final HttpServletRequest req,
			@HeaderParam(APIConstants.HEADER_TOKEN) final String token,
			@FormParam("tokenname") final String name)
			throws InvalidTokenException, MissingParameterException, UnauthorizedException,
			NoTokenProvidedException, IllegalParameterException, AuthStorageException {
		
		final TokenCreationContext tcc = getTokenContext(
				userAgentParser, req, isIgnoreIPsInHeaders(auth), Collections.emptyMap());
		return new NewAPIToken(auth.createToken(
				getToken(token), new TokenName(name), TokenType.AGENT, tcc),
				auth.getSuggestedTokenCacheTime());
	}
	
	private static class CreateToken extends IncomingJSON {
		
		public final String tokenname;

		@JsonCreator
		public CreateToken(@JsonProperty("tokenname") final String name) {
			this.tokenname = name;
		}
	}
	
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public NewAPIToken createAgentTokenJSON(
			@Context final HttpServletRequest req,
			@HeaderParam(APIConstants.HEADER_TOKEN) final String token,
			final CreateToken create)
			throws InvalidTokenException, UnauthorizedException, NoTokenProvidedException,
			MissingParameterException, IllegalParameterException, AuthStorageException {
		create.exceptOnAdditionalProperties();
		
		//TODO CTX add custom context to input
		final Map<String, String> customContext = Collections.emptyMap();
		final TokenCreationContext tcc = getTokenContext(
				userAgentParser, req, isIgnoreIPsInHeaders(auth), customContext);
		
		return new NewAPIToken(auth.createToken(
				getToken(token), new TokenName(create.tokenname), TokenType.AGENT, tcc),
				auth.getSuggestedTokenCacheTime());
	}
}
