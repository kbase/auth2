package us.kbase.auth2.service.api;

import static us.kbase.auth2.service.common.ServiceCommon.getToken;
import static us.kbase.auth2.service.ui.UIUtils.customRolesToList;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.AuthException;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
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
	
	public static class CustomRoleCreate extends IncomingJSON {
		public final String id;
		public final String description;
		
		@JsonCreator
		public CustomRoleCreate(
				@JsonProperty(Fields.ID) final String id,
				@JsonProperty(Fields.DESCRIPTION) final String description) {
			this.id = id;
			this.description = description;
		}
	}
	
	@POST
	@Path(APIPaths.TESTMODE_CUSTOM_ROLES)
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public void createTestCustomRole(final CustomRoleCreate create)
			throws TestModeException, MissingParameterException, IllegalParameterException,
				AuthStorageException {
		if (create == null) {
			throw new MissingParameterException("JSON body missing");
		}
		create.exceptOnAdditionalProperties();
		auth.testModeSetCustomRole(new CustomRole(create.id, create.description));
	}
	
	@GET
	@Path(APIPaths.TESTMODE_CUSTOM_ROLES)
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> getTestCustomRoles()
			throws TestModeException, AuthStorageException {
		return ImmutableMap.of(Fields.CUSTOM_ROLES,
				customRolesToList(new TreeSet<>(auth.testModeGetCustomRoles())));
	}
	
	public static class UserRolesSet extends IncomingJSON {
		public String userName;
		public List<String> roles;
		public List<String> customRoles;
		
		@JsonCreator
		public UserRolesSet(
				@JsonProperty(Fields.USER) final String userName,
				@JsonProperty(Fields.ROLES) final List<String> roles,
				@JsonProperty(Fields.CUSTOM_ROLES) final List<String> customRoles) {
			this.userName = userName;
			this.roles = roles;
			this.customRoles = customRoles;
		}
	}
	
	@PUT
	@Path(APIPaths.TESTMODE_USER_ROLES)
	@Consumes(MediaType.APPLICATION_JSON)
	public void setTestModeUserRoles(final UserRolesSet set)
			throws MissingParameterException, IllegalParameterException, NoSuchUserException,
				NoSuchRoleException, TestModeException, AuthStorageException {
		if (set == null) {
			throw new MissingParameterException("JSON body missing");
		}
		set.exceptOnAdditionalProperties();
		final List<String> roles = set.roles == null ? Collections.emptyList() : set.roles;
		final List<String> customRoles = set.customRoles == null ? Collections.emptyList() :
			set.customRoles;
		noNulls(roles, "Null item in roles");
		noNulls(customRoles, "Null item in custom roles");
		auth.testModeSetRoles(
				new UserName(set.userName), toRoles(roles), new HashSet<>(customRoles));
	}
	
	private Set<Role> toRoles(final List<String> roles) throws IllegalParameterException {
		final Set<Role> ret = new HashSet<>();
		for (final String role: roles) {
			try {
				ret.add(Role.getRole(role));
			} catch (IllegalArgumentException e) {
				throw new IllegalParameterException(e.getMessage(), e);
			}
		}
		return ret;
	}

	private void noNulls(final List<String> l, final String message)
			throws IllegalParameterException {
		for (final String s: l) {
			if (s == null) {
				throw new IllegalParameterException(message);
			}
		}
	}
	
	@DELETE
	@Path(APIPaths.TESTMODE_CLEAR)
	public void clear() throws AuthStorageException {
		auth.testModeClear();
	}
	
	@GET
	@Path(APIPaths.TESTMODE_GLOBUS_TOKEN)
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> getGlobusToken(
			@HeaderParam("x-globus-goauthtoken") final String xtoken,
			@HeaderParam("globus-goauthtoken") final String token,
			@QueryParam("grant_type") final String grantType)
			throws AuthStorageException, AuthException {

		return LegacyGlobus.getToken(
				(a, t) -> a.testModeGetToken(t), auth, xtoken, token, grantType);
	}
	
	// note does not return identity_id
	// note error structure is completely different
	@GET
	@Path(APIPaths.TESTMODE_GLOBUS_USER)
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> getGlobusUser(
			@HeaderParam("x-globus-goauthtoken") final String xtoken,
			@HeaderParam("authorization") final String token,
			@PathParam("user") final String user)
			throws UnauthorizedException, AuthStorageException, NoSuchUserException,
				MissingParameterException, IllegalParameterException, TestModeException {
		
		return LegacyGlobus.getUser(
				(a, t, u) -> a.testModeGetUser(t, u), auth, xtoken, token, user);
	}
	
	@GET
	@Path(APIPaths.TESTMODE_KBASE_TOKEN)
	@Produces(MediaType.TEXT_HTML)
	public Response kbaseDummyGetMethod() {
		return new LegacyKBase(auth).dummyGetMethod();
	}
	
	@POST
	@Path(APIPaths.TESTMODE_KBASE_TOKEN)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> kbaseLogin(
			@Context final HttpHeaders headers,
			final MultivaluedMap<String, String> form)
			throws AuthStorageException, MissingParameterException, InvalidTokenException,
				DisabledUserException, TestModeException, NoSuchUserException {
		return LegacyKBase.kbaseLogin(
				auth,
				(a, t) -> a.testModeGetToken(t),
				(a, t) -> a.testModeGetUser(t),
				form,
				headers.getMediaType());
	}
}
