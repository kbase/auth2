package us.kbase.auth2.service.api;

import static us.kbase.auth2.service.common.ServiceCommon.getToken;

import java.util.HashMap;
import java.util.Map;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.TokenName;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.service.common.IncomingJSON;
import us.kbase.auth2.service.common.NewExternalToken;

@Path(APIPaths.API_V2_TOKEN)
public class Token {

	//TODO TEST
	//TODO JAVADOC
	
	@Inject
	private Authentication auth;
	
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> viewToken(
			@HeaderParam(APIConstants.HEADER_TOKEN) final String token)
			throws NoTokenProvidedException, InvalidTokenException, AuthStorageException {
		final StoredToken ht = auth.getToken(getToken(token));
		final Map<String, Object> ret = new HashMap<>();
		ret.put("cachefor", auth.getSuggestedTokenCacheTime());
		ret.put("user", ht.getUserName().getName());
		ret.put("type", ht.getTokenType().getID());
		ret.put("created", ht.getCreationDate().toEpochMilli());
		ret.put("expires", ht.getExpirationDate().toEpochMilli());
		ret.put("name", ht.getTokenName().isPresent() ? ht.getTokenName().get().getName() : null);
		ret.put("id", ht.getId().toString());
		return ret;
	}
	
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.APPLICATION_JSON)
	public NewExternalToken createAgentTokenForm(
			@HeaderParam(APIConstants.HEADER_TOKEN) final String token,
			@FormParam("tokenname") final String name)
			throws InvalidTokenException, MissingParameterException, UnauthorizedException,
			NoTokenProvidedException, IllegalParameterException, AuthStorageException {
		
		return new NewExternalToken(auth.createToken(
				getToken(token), new TokenName(name), TokenType.AGENT));
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
	public NewExternalToken createAgentTokenJSON(
			@HeaderParam(APIConstants.HEADER_TOKEN) final String token,
			final CreateToken create)
			throws InvalidTokenException, UnauthorizedException, NoTokenProvidedException,
			MissingParameterException, IllegalParameterException, AuthStorageException {
		create.exceptOnAdditionalProperties();
		return new NewExternalToken(auth.createToken(
				getToken(token), new TokenName(create.tokenname), TokenType.AGENT));
	}
}
