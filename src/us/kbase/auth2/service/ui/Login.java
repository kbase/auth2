package us.kbase.auth2.service.ui;

import static us.kbase.auth2.service.ui.UIUtils.getLoginCookie;
import static us.kbase.auth2.service.ui.UIUtils.getMaxCookieAge;
import static us.kbase.auth2.service.ui.UIUtils.relativize;
import static us.kbase.auth2.service.ui.UIUtils.upperCase;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.CookieParam;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
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

import us.kbase.auth2.lib.AuthUser;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.LoginState;
import us.kbase.auth2.lib.LoginToken;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.AuthenticationException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.IdentityLinkedException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.service.AuthAPIStaticConfig;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.auth2.service.AuthExternalConfig.AuthExternalConfigMapper;

@Path(UIPaths.LOGIN_ROOT)
public class Login {

	//TODO TEST
	//TODO JAVADOC
	
	private static final String LOGIN_STATE_COOKIE = "loginstatevar";
	private static final String SESSION_CHOICE_COOKIE = "issessiontoken";
	private static final String REDIRECT_COOKIE = "loginredirect";
	private static final String IN_PROCESS_LOGIN_TOKEN = "in-process-login-token";

	private static final String TRUE = "true";
	private static final String FALSE = "false";
	
	@Inject
	private Authentication auth;
	
	@Inject
	private AuthAPIStaticConfig cfg;
	
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
	@Path(UIPaths.LOGIN_START)
	public Response loginStart(
			@FormParam("provider") final String provider,
			@FormParam("redirect") final String redirect,
			@FormParam("stayLoggedIn") final String stayLoggedIn)
			throws IllegalParameterException, AuthStorageException,
			NoSuchIdentityProviderException {
		
		getRedirectURL(redirect);
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
			final AuthExternalConfig ext;
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
			if (ext.getAllowedLoginRedirectPrefix() != null) {
				if (!redirect.startsWith(ext.getAllowedLoginRedirectPrefix().toString())) {
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
			@PathParam("provider") String provider,
			@CookieParam(LOGIN_STATE_COOKIE) final String state,
			@CookieParam(REDIRECT_COOKIE) final String redirect,
			@CookieParam(SESSION_CHOICE_COOKIE) final String session,
			@Context final UriInfo uriInfo)
			throws MissingParameterException, AuthStorageException,
			IllegalParameterException, AuthenticationException {
		//TODO INPUT handle error in params (provider, state)
		provider = upperCase(provider);
		final MultivaluedMap<String, String> qps = uriInfo.getQueryParameters();
		//TODO ERRHANDLE handle returned OAuth error code in queryparams
		final String authcode = qps.getFirst("code"); //may need to be configurable
		final String retstate = qps.getFirst("state"); //may need to be configurable
		if (state == null || state.trim().isEmpty()) {
			throw new MissingParameterException("Couldn't retrieve state value from cookie");
		}
		if (!state.equals(retstate)) {
			throw new AuthenticationException(ErrorType.AUTHENTICATION_FAILED,
					"State values do not match, this may be a CXRF attack");
		}
		final LoginToken lr = auth.login(provider, authcode);
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
		return resp.cookie(getLoginCookie(cfg.getTokenCookieName(), newtoken, session))
				.cookie(getSessionChoiceCookie(null))
				.cookie(getLoginInProcessCookie(null))
				.cookie(getStateCookie(null))
				.cookie(getRedirectCookie(null));
	}
	
	private Response createLoginResponseJSON(
			final String redirect,
			final NewToken newtoken,
			final boolean session)
			throws IllegalParameterException, AuthStorageException {
		
		return setLoginCookies(Response.ok().entity(ImmutableMap.of(
				"redirect_url", getPostLoginRedirectURI(redirect, UIPaths.ME_ROOT))),
				newtoken, session).build();
	}
	
	private URI getCompleteLoginRedirectURI(final String deflt) throws AuthStorageException {
		final URL url;
		try {
			url = auth.getExternalConfig(new AuthExternalConfigMapper())
					.getCompleteLoginRedirect();
		} catch (ExternalConfigMappingException e) {
			throw new RuntimeException("Dude, like, what just happened?", e);
		}
		if (url == null) {
			return toURI(deflt);
		}
		try {
			return url.toURI();
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
			@Context final UriInfo uriInfo)
			throws NoTokenProvidedException, AuthStorageException, InvalidTokenException {
		return loginChoice(token, uriInfo);
	}

	// trying to combine JSON and HTML doesn't work - @Template = always HTML regardless of Accept:
	@GET
	@Path(UIPaths.LOGIN_CHOICE)
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> loginChoiceJSON(
			@CookieParam(IN_PROCESS_LOGIN_TOKEN) final String token,
			@Context final UriInfo uriInfo)
			throws NoTokenProvidedException, AuthStorageException, InvalidTokenException {
		return loginChoice(token, uriInfo);
	}
	
	private Map<String, Object> loginChoice(final String token, final UriInfo uriInfo)
			throws NoTokenProvidedException, AuthStorageException, InvalidTokenException {
		final LoginState loginState = auth.getLoginState(getLoginInProcessToken(token));
		
		final Map<String, Object> ret = new HashMap<>();
		ret.put("createurl", relativize(uriInfo, UIPaths.LOGIN_ROOT_CREATE));
		ret.put("pickurl", relativize(uriInfo, UIPaths.LOGIN_ROOT_PICK));
		ret.put("provider", loginState.getProvider());
		ret.put("creationallowed", loginState.isNonAdminLoginAllowed());
		
		final List<Map<String, String>> create = new LinkedList<>();
		final List<Map<String, Object>> login = new LinkedList<>();
		ret.put("create", create);
		ret.put("login", login);
		
		for (final RemoteIdentityWithLocalID id: loginState.getIdentities()) {
			final Map<String, String> c = new HashMap<>();
			c.put("id", id.getID().toString());
			final String suggestedUserName = id.getDetails().getUsername().split("@")[0];
			final Optional<UserName> availName = auth.getAvailableUserName(suggestedUserName);
			c.put("usernamesugg", availName.isPresent() ? availName.get().getName() : null);
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
			l.put("id", loginState.getIdentities(userName).iterator().next().getID());
			final List<String> remoteIDs = new LinkedList<>();
			for (final RemoteIdentityWithLocalID id: loginState.getIdentities(userName)) {
				remoteIDs.add(id.getDetails().getUsername());
			}
			l.put("prov_usernames", remoteIDs);
			login.add(l);
		}
		return ret;
	}

	private IncomingToken getLoginInProcessToken(final String token) throws NoTokenProvidedException {
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
			@CookieParam(IN_PROCESS_LOGIN_TOKEN) final String token,
			@CookieParam(REDIRECT_COOKIE) final String redirect,
			@CookieParam(SESSION_CHOICE_COOKIE) final String session,
			@FormParam("id") final UUID identityID)
			throws NoTokenProvidedException, AuthenticationException,
			AuthStorageException, UnauthorizedException, IllegalParameterException {
		
		final NewToken newtoken = auth.login(getLoginInProcessToken(token), identityID);
		return createLoginResponse(redirect, newtoken, !FALSE.equals(session));
	}
	
	private static class PickChoice {
		
		public final UUID id;

		@JsonCreator
		public PickChoice(@JsonProperty("id") final String id) throws IllegalParameterException {
			super();
			try {
				this.id = UUID.fromString(id);
			} catch (IllegalArgumentException e) {
				throw new IllegalParameterException("id is not a valid UUID: " + id);
			}
		}
	}
	
	@PUT
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	@Path(UIPaths.LOGIN_PICK)
	public Response pickAccountJSON(
			@CookieParam(IN_PROCESS_LOGIN_TOKEN) final String token,
			@CookieParam(REDIRECT_COOKIE) final String redirect,
			@CookieParam(SESSION_CHOICE_COOKIE) final String session,
			final PickChoice pick)
			throws AuthenticationException, UnauthorizedException, NoTokenProvidedException,
			AuthStorageException, IllegalParameterException {
		final NewToken newtoken = auth.login(getLoginInProcessToken(token), pick.id);
		return createLoginResponseJSON(redirect, newtoken, !FALSE.equals(session));
	}

	// may need another POST endpoint for AJAX with query params and no redirect
	@POST
	@Path(UIPaths.LOGIN_CREATE)
	public Response createUser(
			@CookieParam(IN_PROCESS_LOGIN_TOKEN) final String token,
			@CookieParam(REDIRECT_COOKIE) final String redirect,
			@CookieParam(SESSION_CHOICE_COOKIE) final String session,
			@FormParam("id") final UUID identityID,
			@FormParam("user") final String userName,
			@FormParam("display") final String displayName,
			@FormParam("email") final String email)
			throws AuthenticationException, AuthStorageException,
				UserExistsException, NoTokenProvidedException,
				MissingParameterException, IllegalParameterException,
				UnauthorizedException, IdentityLinkedException {
		//TODO INPUT sanity check inputs
		
		// might want to enapsulate the user data in a NewUser class
		final NewToken newtoken = auth.createUser(getLoginInProcessToken(token), identityID,
				new UserName(userName), new DisplayName(displayName), new EmailAddress(email));
		return createLoginResponse(redirect, newtoken, !FALSE.equals(session));
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
