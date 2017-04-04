package us.kbase.auth2.service.ui;

import static us.kbase.auth2.service.common.ServiceCommon.getCustomContextFromString;
import static us.kbase.auth2.service.common.ServiceCommon.getTokenContext;
import static us.kbase.auth2.service.common.ServiceCommon.isIgnoreIPsInHeaders;
import static us.kbase.auth2.service.ui.UIUtils.getLoginCookie;
import static us.kbase.auth2.service.ui.UIUtils.getMaxCookieAge;
import static us.kbase.auth2.service.ui.UIUtils.relativize;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.CookieParam;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.UriInfo;

import org.glassfish.jersey.server.mvc.Template;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Optional;
import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.LoginState;
import us.kbase.auth2.lib.LoginToken;
import us.kbase.auth2.lib.PolicyID;
import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.config.ConfigAction.State;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.exceptions.AuthenticationException;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.IdentityLinkedException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.LinkFailedException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.service.AuthAPIStaticConfig;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.auth2.service.AuthExternalConfig.AuthExternalConfigMapper;
import us.kbase.auth2.service.UserAgentParser;
import us.kbase.auth2.service.common.IdentityProviderInput;
import us.kbase.auth2.service.common.IncomingJSON;

@Path(UIPaths.LOGIN_ROOT)
public class Login {

	//TODO TEST
	//TODO JAVADOC
	
	private static final String LOGIN_STATE_COOKIE = "loginstatevar";
	private static final String SESSION_CHOICE_COOKIE = "issessiontoken";
	private static final String REDIRECT_COOKIE = "loginredirect";
	private static final String IN_PROCESS_LOGIN_TOKEN = "in-process-login-token";
	
	private static final String REDIRECT_URL = "redirecturl";

	private static final String TRUE = "true";
	private static final String FALSE = "false";
	
	@Inject
	private Authentication auth;
	
	@Inject
	private AuthAPIStaticConfig cfg;
	
	@Inject
	private UserAgentParser userAgentParser;
	
	@GET
	@Template(name = "/loginstart")
	public Map<String, Object> loginStartDisplay(@Context final UriInfo uriInfo)
			throws NoSuchIdentityProviderException, AuthStorageException,
			IllegalParameterException {
		final Map<String, Object> ret = new HashMap<>();
		final List<Map<String, String>> provs = new LinkedList<>();
		ret.put("providers", provs);
		for (final String prov: auth.getIdentityProviders()) {
			final Map<String, String> rep = new HashMap<>();
			rep.put("name", prov);
			provs.add(rep);
		}
		ret.put("hasprov", !provs.isEmpty());
		ret.put("starturl", relativize(uriInfo, UIPaths.LOGIN_ROOT_START));
		return ret;
	}
	
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Path(UIPaths.LOGIN_START)
	public Response loginStart(
			@FormParam("provider") final String provider,
			@FormParam("redirect") final String redirect,
			@FormParam("stayLoggedIn") final String stayLoggedIn)
			throws IllegalParameterException, AuthStorageException,
			NoSuchIdentityProviderException, MissingParameterException {
		
		if (provider == null || provider.trim().isEmpty()) {
			throw new MissingParameterException("provider");
		}
		
		getRedirectURL(redirect); // check redirect url is ok
		final String state = auth.getBareToken();
		final URI target = toURI(auth.getIdentityProviderURL(provider, state, false));
		
		final ResponseBuilder r = Response.seeOther(target).cookie(getStateCookie(state))
				.cookie(getSessionChoiceCookie(stayLoggedIn == null));
		if (redirect != null && !redirect.trim().isEmpty()) {
			r.cookie(getRedirectCookie(redirect));
		}
		return r.build();
	}

	private URL getRedirectURL(final String redirect)
			throws AuthStorageException, IllegalParameterException {
		if (redirect != null && !redirect.trim().isEmpty()) {
			final AuthExternalConfig<State> ext;
			try {
				ext = auth.getExternalConfig(new AuthExternalConfigMapper());
			} catch (ExternalConfigMappingException e) {
				throw new RuntimeException("Dude, like, what just happened?", e);
			}
			final URL url;
			try {
				url = new URL(redirect);
			} catch (MalformedURLException e) {
				throw new IllegalParameterException("Illegal redirect URL: " + redirect);
			}
			if (ext.getAllowedLoginRedirectPrefix().hasItem()) {
				if (!redirect.startsWith(
						ext.getAllowedLoginRedirectPrefix().getItem().toString())) {
					throw new IllegalParameterException(
							"Illegal redirect url: " + redirect);
				}
			} else {
				throw new IllegalParameterException("Post-login redirects are not enabled");
			}
			return url;
		} else {
			return null;
		}
	}

	private NewCookie getRedirectCookie(final String redirect) {
		return new NewCookie(new Cookie(REDIRECT_COOKIE,
				redirect == null ? "no redirect" : redirect, UIPaths.LOGIN_ROOT, null),
				"redirect url", redirect == null ? 0 : 30 * 60, UIConstants.SECURE_COOKIES);
	}

	private NewCookie getStateCookie(final String state) {
		return new NewCookie(new Cookie(LOGIN_STATE_COOKIE,
				state == null ? "no state" : state, UIPaths.LOGIN_ROOT_COMPLETE, null),
				"loginstate", state == null ? 0 : 30 * 60, UIConstants.SECURE_COOKIES);
	}
	
	private NewCookie getSessionChoiceCookie(final Boolean session) {
		final String sessionValue = session == null ? "no session" : session ? TRUE : FALSE;
		return new NewCookie(new Cookie(SESSION_CHOICE_COOKIE,
				sessionValue, UIPaths.LOGIN_ROOT, null),
				"session choice", session == null ? 0 : 30 * 60, UIConstants.SECURE_COOKIES);
	}
	
	@GET
	@Path(UIPaths.LOGIN_COMPLETE_PROVIDER)
	public Response login(
			@Context final HttpServletRequest req,
			@PathParam("provider") final String provider,
			@CookieParam(LOGIN_STATE_COOKIE) final String state,
			@CookieParam(REDIRECT_COOKIE) final String redirect,
			@CookieParam(SESSION_CHOICE_COOKIE) final String session,
			@Context final UriInfo uriInfo)
			throws MissingParameterException, AuthStorageException,
			IllegalParameterException, AuthenticationException {
		//TODO INPUT handle error in params (provider, state)
		final MultivaluedMap<String, String> qps = uriInfo.getQueryParameters();
		//TODO ERRHANDLE handle returned OAuth error code in queryparams
		final String authcode = qps.getFirst("code"); //may need to be configurable
		final String retstate = qps.getFirst("state"); //may need to be configurable
		IdentityProviderInput.checkState(state, retstate);
		final TokenCreationContext tcc = getTokenContext(
				userAgentParser, req, isIgnoreIPsInHeaders(auth), Collections.emptyMap());
		final LoginToken lr = auth.login(provider, authcode, tcc);
		final Response r;
		// always redirect so the authcode doesn't remain in the title bar
		// note nginx will rewrite the redirect appropriately so absolute
		// redirects are ok
		if (lr.isLoggedIn()) {
			r = createLoginResponse(redirect, lr.getToken(), !FALSE.equals(session));
		} else {
			r = Response.seeOther(getCompleteLoginRedirectURI(UIPaths.LOGIN_ROOT_CHOICE))
					.cookie(getLoginInProcessCookie(lr.getTemporaryToken()))
					.cookie(getStateCookie(null))
					.build();
		}
		return r;
	}
	
	private static class IDProviderJSON extends IdentityProviderInput {

		private final Map<String, String> customContext;
		
		@JsonCreator
		public IDProviderJSON(
				@JsonProperty("authcode") final String authCode,
				@JsonProperty("state") final String state,
				@JsonProperty("customcontext") final Map<String, String> customContext) {
			super(authCode, state);
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
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	@Path(UIPaths.LOGIN_COMPLETE_PROVIDER)
	public Response login(
			@Context final HttpServletRequest req,
			@PathParam("provider") final String provider,
			@Context final UriInfo uriInfo,
			@CookieParam(LOGIN_STATE_COOKIE) final String state,
			@CookieParam(REDIRECT_COOKIE) final String redirect,
			@CookieParam(SESSION_CHOICE_COOKIE) final String session,
			final IDProviderJSON input)
			throws AuthenticationException, MissingParameterException, AuthStorageException,
			IllegalParameterException {
		if (input == null) {
			throw new MissingParameterException("JSON body missing");
		}
		//TODO INPUT handle error in provider
		input.exceptOnAdditionalProperties();
		input.checkState(state);
		
		final TokenCreationContext tcc = getTokenContext(
				userAgentParser, req, isIgnoreIPsInHeaders(auth), input.getCustomContext());
		
		final LoginToken lr = auth.login(provider, input.getAuthCode(), tcc);
		final Map<String, Object> choice = buildLoginChoice(uriInfo, lr.getLoginState(), redirect);
		if (lr.isLoggedIn()) {
			choice.put("token", new NewUIToken(lr.getToken()));
			choice.put("logged_in", true);
			final ResponseBuilder b = Response.ok(choice);
			setLoginCookies(b, lr.getToken(), TRUE.equals(session));
			return b.build();
		} else {
			choice.put("logged_in", false);
			return Response.ok(choice)
					.cookie(getLoginInProcessCookie(lr.getTemporaryToken()))
					.cookie(getStateCookie(null))
					.build();
		}
	}

	private Response createLoginResponse(
			final String redirect,
			final NewToken newtoken,
			final boolean session)
			throws IllegalParameterException, AuthStorageException {
		
		return setLoginCookies(Response.seeOther(
				getPostLoginRedirectURI(redirect, UIPaths.ME_ROOT)), newtoken, session).build();
	}
	
	private ResponseBuilder setLoginCookies(
			final ResponseBuilder resp,
			final NewToken newtoken,
			final boolean session) {
		return removeLoginProcessCookies(resp)
				.cookie(getLoginCookie(cfg.getTokenCookieName(), newtoken, session));
	}
	
	private ResponseBuilder removeLoginProcessCookies(final ResponseBuilder resp) {
		return resp.cookie(getSessionChoiceCookie(null))
				.cookie(getLoginInProcessCookie(null))
				.cookie(getStateCookie(null))
				.cookie(getRedirectCookie(null));
	}
	
	private Response createLoginResponseJSON(
			final Response.Status status,
			final String redirect,
			final NewToken newtoken)
			throws IllegalParameterException, AuthStorageException {
		
		final Map<String, Object> ret = new HashMap<>();
		ret.put(REDIRECT_URL, getRedirectURL(redirect));
		ret.put("token", new NewUIToken(newtoken));
		return removeLoginProcessCookies(Response.status(status)).entity(ret).build();
	}
	
	private URI getCompleteLoginRedirectURI(final String deflt) throws AuthStorageException {
		final ConfigItem<URL, State> url;
		try {
			url = auth.getExternalConfig(new AuthExternalConfigMapper())
					.getCompleteLoginRedirect();
		} catch (ExternalConfigMappingException e) {
			throw new RuntimeException("Dude, like, what just happened?", e);
		}
		if (!url.hasItem()) {
			return toURI(deflt);
		}
		try {
			return url.getItem().toURI();
		} catch (URISyntaxException e) {
			throw new RuntimeException("this should be impossible" , e);
		}
	}

	private URI getPostLoginRedirectURI(final String redirect, final String deflt)
			throws IllegalParameterException, AuthStorageException {
		final URL redirURL = getRedirectURL(redirect);
		if (redirURL != null) {
			return toURI(redirURL);
		}
		return toURI(deflt);
	}

	private NewCookie getLoginInProcessCookie(final TemporaryToken token) {
		return new NewCookie(new Cookie(IN_PROCESS_LOGIN_TOKEN,
				token == null ? "no token" : token.getToken(), UIPaths.LOGIN_ROOT, null),
				"logintoken",
				token == null ? 0 : getMaxCookieAge(token, false), UIConstants.SECURE_COOKIES);
	}

	@GET
	@Path(UIPaths.LOGIN_CHOICE)
	@Template(name = "/loginchoice")
	@Produces(MediaType.TEXT_HTML)
	public Map<String, Object> loginChoiceHTML(
			@CookieParam(IN_PROCESS_LOGIN_TOKEN) final String token,
			@CookieParam(REDIRECT_COOKIE) final String redirect,
			@Context final UriInfo uriInfo)
			throws NoTokenProvidedException, AuthStorageException, InvalidTokenException,
			IllegalParameterException {
		return loginChoice(token, uriInfo, redirect);
	}

	// trying to combine JSON and HTML doesn't work - @Template = always HTML regardless of Accept:
	@GET
	@Path(UIPaths.LOGIN_CHOICE)
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> loginChoiceJSON(
			@CookieParam(IN_PROCESS_LOGIN_TOKEN) final String token,
			@CookieParam(REDIRECT_COOKIE) final String redirect,
			@Context final UriInfo uriInfo)
			throws NoTokenProvidedException, AuthStorageException, InvalidTokenException,
			IllegalParameterException {
		return loginChoice(token, uriInfo, redirect);
	}
	
	private Map<String, Object> loginChoice(
			final String token,
			final UriInfo uriInfo,
			final String redirect)
			throws NoTokenProvidedException, AuthStorageException, InvalidTokenException,
			IllegalParameterException {
		final LoginState loginState = auth.getLoginState(getLoginInProcessToken(token));
		
		return buildLoginChoice(uriInfo, loginState, redirect);
	}

	private Map<String, Object> buildLoginChoice(
			final UriInfo uriInfo,
			final LoginState loginState,
			final String redirect)
			throws AuthStorageException, IllegalParameterException {
		final Map<String, Object> ret = new HashMap<>();
		ret.put("createurl", relativize(uriInfo, UIPaths.LOGIN_ROOT_CREATE));
		ret.put("pickurl", relativize(uriInfo, UIPaths.LOGIN_ROOT_PICK));
		ret.put("provider", loginState.getProvider());
		ret.put(REDIRECT_URL, getRedirectURL(redirect));
		ret.put("creationallowed", loginState.isNonAdminLoginAllowed());
		
		final List<Map<String, String>> create = new LinkedList<>();
		final List<Map<String, Object>> login = new LinkedList<>();
		ret.put("create", create);
		ret.put("login", login);
		
		for (final RemoteIdentity id: loginState.getIdentities()) {
			final Map<String, String> c = new HashMap<>();
			c.put("id", id.getRemoteID().getID());
			final String suggestedUserName = id.getDetails().getUsername().split("@")[0];
			final Optional<UserName> availName = auth.getAvailableUserName(suggestedUserName);
			c.put("usernamesugg", availName.isPresent() ? availName.get().getName() : null);
			//TODO UI return null for full name & email if they're not valid by our rules
			c.put("prov_username", id.getDetails().getUsername());
			c.put("prov_fullname", id.getDetails().getFullname());
			c.put("prov_email", id.getDetails().getEmail());
			create.add(c);
		}
		final boolean adminOnly = !loginState.isNonAdminLoginAllowed();
		for (final UserName userName: loginState.getUsers()) {
			final AuthUser user = loginState.getUser(userName);
			final boolean loginRestricted = adminOnly && !loginState.isAdmin(userName);
			final Map<String, Object> l = new HashMap<>();
			l.put("username", userName.getName());
			l.put("loginallowed", !(user.isDisabled() || loginRestricted));
			l.put("disabled", user.isDisabled());
			l.put("adminonly", loginRestricted);
			l.put("id", loginState.getIdentities(userName).iterator().next()
					.getRemoteID().getID());
			l.put("policy_ids", user.getPolicyIDs().keySet().stream().map(id -> ImmutableMap.of(
					"id", id.getName(),
					"agreed_on", user.getPolicyIDs().get(id).toEpochMilli()))
					.collect(Collectors.toSet()));
			final List<String> remoteIDs = new LinkedList<>();
			for (final RemoteIdentity id: loginState.getIdentities(userName)) {
				remoteIDs.add(id.getDetails().getUsername());
			}
			l.put("prov_usernames", remoteIDs);
			login.add(l);
		}
		return ret;
	}

	private IncomingToken getLoginInProcessToken(final String token)
			throws NoTokenProvidedException {
		final IncomingToken incToken;
		try {
			incToken = new IncomingToken(token);
		} catch (MissingParameterException e) {
			throw new NoTokenProvidedException("Missing " + IN_PROCESS_LOGIN_TOKEN); 
		}
		return incToken;
	}
	
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Path(UIPaths.LOGIN_PICK)
	public Response pickAccount(
			@Context final HttpServletRequest req,
			@CookieParam(IN_PROCESS_LOGIN_TOKEN) final String token,
			@CookieParam(REDIRECT_COOKIE) final String redirect,
			@CookieParam(SESSION_CHOICE_COOKIE) final String session,
			@FormParam("id") final String identityID,
			@FormParam("policy_ids") final String policyIDs,
			@FormParam("customcontext") final String customContext,
			@FormParam("linkall") final String linkAll)
			throws NoTokenProvidedException, AuthenticationException,
			AuthStorageException, UnauthorizedException, IllegalParameterException,
			LinkFailedException, MissingParameterException {
		
		final TokenCreationContext tcc = getTokenContext(userAgentParser, req,
				isIgnoreIPsInHeaders(auth), getCustomContextFromString(customContext));
		final NewToken newtoken = auth.login(getLoginInProcessToken(token),
				PickChoice.getString(identityID, "id"),
				PickChoice.getPolicyIDs(policyIDs), tcc, linkAll != null);
		return createLoginResponse(redirect, newtoken, !FALSE.equals(session));
	}

	private static class PickChoice extends IncomingJSON {
		
		private final String id;
		private final List<String> policyIDs;
		private final Object linkAll;
		private final Map<String, String> customContext;
		
		// don't throw error from constructor, doesn't get picked up by the custom error handler 
		@JsonCreator
		public PickChoice(
				@JsonProperty("id") final String id,
				@JsonProperty("policy_ids") final List<String> policyIDs,
				@JsonProperty("customcontext") final Map<String, String> customContext,
				@JsonProperty("linkall") final Object linkAll) {
			this.id = id;
			this.policyIDs = policyIDs;
			this.customContext = customContext;
			this.linkAll = linkAll;
		}
		
		public String getIdentityID() throws MissingParameterException {
			return getString(id, "id");
		}
		
		public Set<PolicyID> getPolicyIDs()
				throws MissingParameterException, IllegalParameterException {
			return getPolicyIDs(policyIDs);
		}
		
		public static Set<PolicyID> getPolicyIDs(final String policyIDlist)
				throws MissingParameterException, IllegalParameterException {
			final Set<PolicyID> ids = new HashSet<>();
			if (policyIDlist == null || policyIDlist.trim().isEmpty()) {
				return ids;
			}
			return getPolicyIDs(Arrays.asList(policyIDlist.split(",")));
			
		}
		
		private static Set<PolicyID> getPolicyIDs(final List<String> policyIDs)
				throws MissingParameterException, IllegalParameterException {
			final Set<PolicyID> ret = new HashSet<>(); 
			if (policyIDs == null) {
				return ret;
			}
			for (final String id: policyIDs) {
				ret.add(new PolicyID(id));
			}
			return ret;
		}
		
		public boolean isLinkAll() throws IllegalParameterException {
			return getBoolean(linkAll, "linkall");
		}
		
		public Map<String, String> getCustomContext() {
			if (customContext == null) {
				return Collections.emptyMap();
			}
			return customContext;
		}
	}
	
	@POST // non-idempotent
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	@Path(UIPaths.LOGIN_PICK)
	public Response pickAccount(
			@Context final HttpServletRequest req,
			@CookieParam(IN_PROCESS_LOGIN_TOKEN) final String token,
			@CookieParam(REDIRECT_COOKIE) final String redirect,
			final PickChoice pick)
			throws AuthenticationException, UnauthorizedException, NoTokenProvidedException,
			AuthStorageException, IllegalParameterException, MissingParameterException,
			LinkFailedException {
		if (pick == null) {
			throw new MissingParameterException("JSON body missing");
		}
		
		pick.exceptOnAdditionalProperties();
		final TokenCreationContext tcc = getTokenContext(
				userAgentParser, req, isIgnoreIPsInHeaders(auth), pick.getCustomContext());
		final NewToken newtoken = auth.login(getLoginInProcessToken(token),
				pick.getIdentityID(), pick.getPolicyIDs(), tcc, pick.isLinkAll());
		return createLoginResponseJSON(Response.Status.OK, redirect, newtoken);
	}

	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Path(UIPaths.LOGIN_CREATE)
	public Response createUser(
			@Context final HttpServletRequest req,
			@CookieParam(IN_PROCESS_LOGIN_TOKEN) final String token,
			@CookieParam(REDIRECT_COOKIE) final String redirect,
			@CookieParam(SESSION_CHOICE_COOKIE) final String session,
			@FormParam("id") final String identityID,
			@FormParam("user") final String userName,
			@FormParam("display") final String displayName,
			@FormParam("email") final String email,
			@FormParam("policy_ids") final String policyIDs,
			@FormParam("customcontext") final String customContext,
			@FormParam("linkall") final String linkAll)
			throws AuthenticationException, AuthStorageException,
				UserExistsException, NoTokenProvidedException,
				MissingParameterException, IllegalParameterException,
				UnauthorizedException, IdentityLinkedException, LinkFailedException {
	
		if (identityID == null) {
			throw new MissingParameterException("identityID");
		}
		final TokenCreationContext tcc = getTokenContext(userAgentParser, req,
				isIgnoreIPsInHeaders(auth), getCustomContextFromString(customContext));

		final NewToken newtoken = auth.createUser(
				getLoginInProcessToken(token),
				CreateChoice.getString(identityID, "id"),
				new UserName(userName),
				new DisplayName(displayName),
				new EmailAddress(email),
				CreateChoice.getPolicyIDs(policyIDs),
				tcc,
				linkAll != null);
		return createLoginResponse(redirect, newtoken, !FALSE.equals(session));
	}
	
	private static class CreateChoice extends PickChoice {
		
		public final String user;
		public final String displayName;
		public final String email;

		// don't throw error from constructor, doesn't get picked up by the custom error handler 
		@JsonCreator
		public CreateChoice(
				@JsonProperty("id") final String id,
				@JsonProperty("user") final String userName,
				@JsonProperty("display") final String displayName,
				@JsonProperty("email") final String email,
				@JsonProperty("policy_ids") final List<String> policyIDs,
				@JsonProperty("customcontext") final Map<String, String> customContext,
				@JsonProperty("linkall") final Object linkAll) {
			super(id, policyIDs, customContext, linkAll);
			this.user = userName;
			this.displayName = displayName;
			this.email = email;
		}
	}
	
	@POST //non-idempotent
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	@Path(UIPaths.LOGIN_CREATE)
	public Response createUser(
			@Context final HttpServletRequest req,
			@CookieParam(IN_PROCESS_LOGIN_TOKEN) final String token,
			@CookieParam(REDIRECT_COOKIE) final String redirect,
			final CreateChoice create)
			throws AuthenticationException, AuthStorageException,
				UserExistsException, NoTokenProvidedException,
				MissingParameterException, IllegalParameterException,
				UnauthorizedException, IdentityLinkedException, LinkFailedException {
		if (create == null) {
			throw new MissingParameterException("JSON body missing");
		}
		
		create.exceptOnAdditionalProperties();
		
		final TokenCreationContext tcc = getTokenContext(
				userAgentParser, req, isIgnoreIPsInHeaders(auth), create.getCustomContext());
		
		final NewToken newtoken = auth.createUser(
				getLoginInProcessToken(token),
				create.getIdentityID(),
				new UserName(create.user),
				new DisplayName(create.displayName),
				new EmailAddress(create.email),
				create.getPolicyIDs(),
				tcc,
				create.isLinkAll());
		return createLoginResponseJSON(Response.Status.CREATED, redirect, newtoken);
	}
	
	//Assumes valid URI in URL form
	private URI toURI(final URL loginURL) {
		try {
			return loginURL.toURI();
		} catch (URISyntaxException e) {
			throw new RuntimeException("This should be impossible", e);
		}
	}
	
	//Assumes valid URI in String form
	private URI toURI(final String uri) {
		try {
			return new URI(uri);
		} catch (URISyntaxException e) {
			throw new RuntimeException("This should be impossible", e);
		}
	}
}
