package us.kbase.auth2.service.api;

import static us.kbase.auth2.service.common.ServiceCommon.getToken;

import java.util.Map;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.TestModeException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenName;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.service.common.Fields;
import us.kbase.auth2.service.common.IncomingJSON;

@Path(APIPaths.TESTMODE)
public class TestMode {
	
	// TODO JAVADOC or swagger
	
	private final Authentication auth;
	
	@Inject
	public TestMode(final Authentication auth) {
		this.auth = auth;
	}
	
	public static class CreateTestUser extends IncomingJSON {
		
		public final String userName;
		public final String displayName;

		@JsonCreator
		public CreateTestUser(
				@JsonProperty(Fields.USER) final String userName,
				@JsonProperty(Fields.DISPLAY) final String displayName) {
			this.userName = userName;
			this.displayName = displayName;
		}
	}

	@POST
	@Path(APIPaths.TESTMODE_USER)
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> createTestUser(final CreateTestUser create)
			throws MissingParameterException, IllegalParameterException, UserExistsException,
					UnauthorizedException, TestModeException, AuthStorageException {
		if (create == null) {
			throw new MissingParameterException("JSON body missing");
		}
		create.exceptOnAdditionalProperties();
		final UserName user = new UserName(create.userName);
		auth.testModeCreateUser(user, new DisplayName(create.displayName));
		try {
			return Me.toUserMap(auth.testModeGetUser(user));
		} catch (NoSuchUserException e) {
			throw new RuntimeException("Neat, user creation is totally busted: " +
					e.getMessage(), e);
		}
	}
	
	@GET
	@Path(APIPaths.TESTMODE_USER_GET)
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> getTestUser(@PathParam(APIPaths.USERNAME) final String userName)
			throws NoSuchUserException, TestModeException, MissingParameterException,
				IllegalParameterException, AuthStorageException {
		return Me.toUserMap(auth.testModeGetUser(new UserName(userName)));
	}
	
	public static class CreateTestToken extends IncomingJSON {
		public final String userName;
		public final String tokenName;
		public final String tokenType;

		@JsonCreator
		public CreateTestToken(
				@JsonProperty(Fields.USER) final String userName,
				@JsonProperty(Fields.TOKEN_NAME) final String tokenName,
				@JsonProperty(Fields.TOKEN_TYPE) final String tokenType) {
			this.userName = userName;
			this.tokenName = tokenName;
			this.tokenType = tokenType;
		}
	}
	
	@POST
	@Path(APIPaths.TESTMODE_TOKEN_CREATE)
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public NewAPIToken createTestToken(final CreateTestToken create)
			throws MissingParameterException, IllegalParameterException, NoSuchUserException,
				TestModeException, AuthStorageException {
		if (create == null) {
			throw new MissingParameterException("JSON body missing");
		}
		create.exceptOnAdditionalProperties();
		return new NewAPIToken(auth.testModeCreateToken(
				new UserName(create.userName),
				create.tokenName == null ? null : new TokenName(create.tokenName),
				getTokenType(create.tokenType)),
				auth.getSuggestedTokenCacheTime());
	}

	private TokenType getTokenType(final String tokenType) throws IllegalParameterException {
		try {
			return TokenType.getType(tokenType);
		} catch (IllegalArgumentException e) {
			throw new IllegalParameterException(e.getMessage(), e);
		}
	}
	
	@GET
	@Path(APIPaths.TESTMODE_TOKEN)
	@Produces(MediaType.APPLICATION_JSON)
	public APIToken getTestToken(@HeaderParam(APIConstants.HEADER_TOKEN) final String token)
			throws NoTokenProvidedException, InvalidTokenException, AuthStorageException,
				TestModeException {
		final StoredToken ht = auth.testModeGetToken(getToken(token));
		return new APIToken(ht, auth.getSuggestedTokenCacheTime());
	}
	
	@GET
	@Path(APIPaths.TESTMODE_ME)
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> getTestMe(
			@HeaderParam(APIConstants.HEADER_TOKEN) final String token)
			throws InvalidTokenException, NoSuchUserException, TestModeException,
				NoTokenProvidedException, AuthStorageException {
		return Me.toUserMap(auth.testModeGetUser(getToken(token)));
	}
	
}
