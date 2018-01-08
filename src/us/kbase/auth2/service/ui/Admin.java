package us.kbase.auth2.service.ui;

import static us.kbase.auth2.service.common.ServiceCommon.getToken;
import static us.kbase.auth2.service.common.ServiceCommon.nullOrEmpty;
import static us.kbase.auth2.service.ui.UIUtils.getRolesFromForm;
import static us.kbase.auth2.service.ui.UIUtils.getTokenFromCookie;
import static us.kbase.auth2.service.ui.UIUtils.relativize;
import static us.kbase.auth2.service.ui.UIUtils.removeLoginCookie;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import java.util.Set;
import java.util.UUID;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
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
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.glassfish.jersey.server.mvc.Template;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Optional;
import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.Password;
import us.kbase.auth2.lib.PolicyID;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.UserSearchSpec;
import us.kbase.auth2.lib.config.AuthConfigSetWithUpdateTime;
import us.kbase.auth2.lib.config.AuthConfigUpdate;
import us.kbase.auth2.lib.config.AuthConfigUpdate.ProviderUpdate;
import us.kbase.auth2.lib.config.ConfigAction.Action;
import us.kbase.auth2.lib.config.ConfigAction.State;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.config.ExternalConfig;
import us.kbase.auth2.lib.config.AuthConfig.ProviderConfig;
import us.kbase.auth2.lib.config.AuthConfig.TokenLifetimeType;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.service.AuthAPIStaticConfig;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.auth2.service.AuthExternalConfig.AuthExternalConfigMapper;
import us.kbase.auth2.service.common.Fields;
import us.kbase.auth2.service.common.IncomingJSON;

@Path(UIPaths.ADMIN_ROOT)
public class Admin {

	//TODO TEST
	//TODO JAVADOC or swagger
	
	private static final String SEP = UIPaths.SEP;
	
	private static final int MIN_IN_MS = 60 * 1000;

	private static final int DAY_IN_MS = 24 * 60 * MIN_IN_MS;
	
	@Inject
	private Authentication auth;
	
	@Inject
	private AuthAPIStaticConfig cfg;
	
	@GET
	@Template(name = "/admingeneral")
	public Map<String, Object> admin(
			@Context final UriInfo uriInfo,
			@Context final HttpHeaders headers)
			throws InvalidTokenException, UnauthorizedException, NoTokenProvidedException,
			AuthStorageException {
		final Map<String, Object> ret = new HashMap<>();
		ret.put(Fields.URL_RESET, relativize(uriInfo, UIPaths.ADMIN_ROOT_FORCE_RESET_PWD));
		ret.put(Fields.URL_REVOKE_ALL, relativize(uriInfo, UIPaths.ADMIN_ROOT_REVOKE_ALL));
		ret.put(Fields.URL_TOKEN, relativize(uriInfo, UIPaths.ADMIN_ROOT_TOKEN));
		ret.put(Fields.URL_POLICY, relativize(uriInfo, UIPaths.ADMIN_ROOT_POLICY_ID));
		ret.put(Fields.URL_SEARCH, relativize(uriInfo, UIPaths.ADMIN_ROOT_SEARCH));
		ret.put(Fields.CUSTOM_ROLES, UIUtils.customRolesToList(
				auth.getCustomRoles(getTokenFromCookie(headers, cfg.getTokenCookieName()), true)));
		return ret;
	}
	
	@POST
	@Path(UIPaths.ADMIN_FORCE_RESET_PWD)
	public void forceResetAllPasswords(@Context final HttpHeaders headers)
			throws NoTokenProvidedException, InvalidTokenException, UnauthorizedException,
			AuthStorageException {
		auth.forceResetAllPasswords(getTokenFromCookie(headers, cfg.getTokenCookieName()));
	}
	
	@POST
	@Path(UIPaths.ADMIN_REVOKE_ALL)
	public Response revokeAllTokens(@Context final HttpHeaders headers)
			throws NoTokenProvidedException, InvalidTokenException, UnauthorizedException,
			AuthStorageException {
		auth.revokeAllTokens(getTokenFromCookie(headers, cfg.getTokenCookieName()));
		return Response.ok().cookie(removeLoginCookie(cfg.getTokenCookieName())).build();
	}
	
	@POST
	@Path(UIPaths.ADMIN_TOKEN)
	@Template(name = "/admintoken")
	public Map<String, Object> getUserToken(
			@Context final UriInfo uriInfo,
			@FormParam(Fields.TOKEN) final String token)
			throws MissingParameterException, InvalidTokenException, AuthStorageException {
		final IncomingToken t;
		try {
			t = getToken(token);
		} catch (NoTokenProvidedException e) {
			throw new MissingParameterException(Fields.TOKEN);
		}
		final StoredToken ht = auth.getToken(t);
		final Map<String, Object> ret = new HashMap<>();
		ret.put(Fields.TOKEN, new UIToken(ht));
		ret.put(Fields.URL_REVOKE, relativize(uriInfo, UIPaths.ADMIN_ROOT_USER + SEP +
				ht.getUserName().getName() + SEP + UIPaths.ADMIN_TOKENS + SEP +
				UIPaths.ADMIN_USER_TOKENS_REVOKE + SEP + ht.getId().toString()));
		return ret;
	}
	
	@POST
	@Path(UIPaths.ADMIN_POLICY_ID)
	public void removePolicyID(
			@Context final HttpHeaders headers,
			@FormParam(Fields.POLICY_ID) final String policyID)
			throws InvalidTokenException, UnauthorizedException, NoTokenProvidedException,
				MissingParameterException, IllegalParameterException, AuthStorageException {
		auth.removePolicyID(getTokenFromCookie(headers, cfg.getTokenCookieName()),
				new PolicyID(policyID));
	}
	
	@POST
	@Path(UIPaths.ADMIN_SEARCH) 
	@Template(name = "/adminsearch")
	public Map<String, Object> searchForUsers(
			@Context final HttpHeaders headers,
			@Context final UriInfo uriInfo,
			final MultivaluedMap<String, String> form)
			throws InvalidTokenException, IllegalParameterException, NoTokenProvidedException,
			AuthStorageException, UnauthorizedException {
		final String prefix = form.getFirst(Fields.SEARCH_PREFIX);
		final UserSearchSpec.Builder build = UserSearchSpec.getBuilder().withIncludeDisabled(true)
				.withIncludeRoot(true); // may want to include option to exclude disabled
		final boolean hasPrefix;
		if (prefix != null && !prefix.trim().isEmpty()) {
			build.withSearchPrefix(prefix);
			hasPrefix = true;
		} else {
			hasPrefix = false;
		}
		
		if (hasPrefix && !nullOrEmpty(form.getFirst(Fields.SEARCH_USER))) {
			build.withSearchOnUserName(true);
		}
		if (hasPrefix && !nullOrEmpty(form.getFirst(Fields.SEARCH_DISPLAY))) {
			build.withSearchOnDisplayName(true);
		}
		for (final Role r: getRolesFromForm(form)) {
			build.withSearchOnRole(r);
		}
		for (final String key: form.keySet()) {
			if (key.startsWith(Fields.CUSTOM_ROLE_FORM_PREFIX)) {
				if (!nullOrEmpty(form.getFirst(key))) {
					build.withSearchOnCustomRole(key.replace(Fields.CUSTOM_ROLE_FORM_PREFIX, ""));
				}
			}
		}
		final Map<UserName, DisplayName> users = auth.getUserDisplayNames(
				getTokenFromCookie(headers, cfg.getTokenCookieName()), build.build());
		final List<Map<String, String>> uiusers = new LinkedList<>();
		for (final UserName user: users.keySet()) {
			final Map<String, String> u = new HashMap<>();
			u.put(Fields.USER, user.getName());
			u.put(Fields.DISPLAY, users.get(user).getName());
			u.put(Fields.URL_USER, relativize(uriInfo,
					UIPaths.ADMIN_ROOT_USER + SEP + user.getName()));
			uiusers.add(u);
		}
		return ImmutableMap.of(Fields.USERS, uiusers, Fields.HAS_USERS, !uiusers.isEmpty());
	}
	
	@GET
	@Path(UIPaths.ADMIN_LOCALACCOUNT)
	@Template(name = "/adminlocalaccount")
	@Produces(MediaType.TEXT_HTML)
	public Map<String, String> createLocalAccountStart(@Context final UriInfo uriInfo) {
		return ImmutableMap.of(Fields.URL_CREATE,
				relativize(uriInfo, UIPaths.ADMIN_ROOT_LOCAL_CREATE));
	}
	
	@POST
	@Path(UIPaths.ADMIN_LOCAL_CREATE)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.TEXT_HTML)
	@Template(name = "/adminlocalaccountcreated")
	public Map<String, String> createLocalAccountComplete(
			@Context final HttpHeaders headers,
			@FormParam(Fields.USER) final String userName,
			@FormParam(Fields.DISPLAY) final String displayName,
			@FormParam(Fields.EMAIL) final String email)
			throws AuthStorageException, UserExistsException,
			MissingParameterException, IllegalParameterException,
			UnauthorizedException, InvalidTokenException,
			NoTokenProvidedException {
		final Password pwd = auth.createLocalUser(
				getTokenFromCookie(headers, cfg.getTokenCookieName()),
				new UserName(userName), new DisplayName(displayName), new EmailAddress(email));
		final Map<String, String> ret = ImmutableMap.of(
				Fields.USER, userName,
				Fields.DISPLAY, displayName,
				Fields.EMAIL, email,
				Fields.PASSWORD, new String(pwd.getPassword())); // char[] won't work
		pwd.clear(); // not that this helps much...
		return ret;
	}
	
	@GET
	@Path(UIPaths.ADMIN_USER_PARAM)
	@Template(name = "/adminuser")
	@Produces(MediaType.TEXT_HTML)
	public Map<String, Object> userDisplay(
			@Context final HttpHeaders headers,
			@PathParam(UIPaths.USER) final String user,
			@Context final UriInfo uriInfo)
			throws AuthStorageException, NoSuchUserException,
			MissingParameterException, IllegalParameterException,
			InvalidTokenException, UnauthorizedException,
			NoTokenProvidedException {
		final IncomingToken adminToken = getTokenFromCookie(headers, cfg.getTokenCookieName());
		final AuthUser au = auth.getUserAsAdmin(adminToken, new UserName(user));
		final Set<CustomRole> roles = auth.getCustomRoles(adminToken, true);
		final String userPrefix = UIPaths.ADMIN_ROOT_USER + SEP + user + SEP;
		final Map<String, Object> ret = new HashMap<>();
		ret.put(Fields.CUSTOM_ROLES, customRolesToList(roles, au.getCustomRoles()));
		ret.put(Fields.HAS_CUSTOM_ROLES, !roles.isEmpty());
		ret.put(Fields.URL_ROLE, relativize(uriInfo, userPrefix + UIPaths.ADMIN_ROLES));
		ret.put(Fields.URL_CUSTOM_ROLE,
				relativize(uriInfo, userPrefix + UIPaths.ADMIN_CUSTOM_ROLES));
		ret.put(Fields.URL_DISABLE, relativize(uriInfo, userPrefix + UIPaths.ADMIN_DISABLE));
		ret.put(Fields.URL_RESET, relativize(uriInfo, userPrefix + UIPaths.ADMIN_RESET_PWD));
		ret.put(Fields.URL_FORCE_RESET,
				relativize(uriInfo, userPrefix + UIPaths.ADMIN_FORCE_RESET_PWD));
		ret.put(Fields.URL_TOKEN, relativize(uriInfo, userPrefix + UIPaths.ADMIN_TOKENS));
		ret.put(Fields.USER, au.getUserName().getName());
		ret.put(Fields.DISPLAY, au.getDisplayName().getName());
		ret.put(Fields.EMAIL, au.getEmail().getAddress());
		ret.put(Fields.LOCAL, au.isLocal());
		ret.put(Fields.CREATED, au.getCreated().toEpochMilli());
		final Optional<Instant> lastLogin = au.getLastLogin();
		ret.put(Fields.LAST_LOGIN, lastLogin.isPresent() ? lastLogin.get().toEpochMilli() : null);
		ret.put(Fields.DISABLED, au.isDisabled());
		final Optional<String> dis = au.getReasonForDisabled();
		ret.put(Fields.DISABLED_REASON, dis.isPresent() ? au.getReasonForDisabled().get() : null);
		final Optional<Instant> disabled = au.getEnableToggleDate();
		ret.put(Fields.ENABLE_TOGGLE_DATE, disabled.isPresent() ?
				disabled.get().toEpochMilli() : null);
		final Optional<UserName> admin = au.getAdminThatToggledEnabledState();
		ret.put(Fields.ENABLE_TOGGLED_BY, admin.isPresent() ? admin.get().getName() : null);
		ret.put(Role.ADMIN.getID(), au.hasRole(Role.ADMIN));
		ret.put(Role.SERV_TOKEN.getID(), au.hasRole(Role.SERV_TOKEN));
		ret.put(Role.DEV_TOKEN.getID(), au.hasRole(Role.DEV_TOKEN));
		ret.put(Role.CREATE_ADMIN.getID(), au.hasRole(Role.CREATE_ADMIN));
		return ret;
	}
	
	private List<Map<String, Object>> customRolesToList(
			final Set<CustomRole> roles,
			final Set<String> userHas) {
		final List<Map<String, Object>> ret = new LinkedList<>();
		for (final CustomRole r: roles) {
			ret.add(ImmutableMap.of(
					Fields.DESCRIPTION, r.getDesc(),
					Fields.ID, r.getID(),
					Fields.HAS, userHas.contains(r.getID())));
		}
		return ret;
	}

	@GET
	@Path(UIPaths.ADMIN_USER_TOKENS)
	@Template(name = "/adminusertokens")
	public Map<String, Object> getUserTokens(
			@Context final HttpHeaders headers,
			@Context final UriInfo uriInfo,
			@PathParam(UIPaths.USER) final String user)
			throws InvalidTokenException, UnauthorizedException, NoTokenProvidedException,
			MissingParameterException, IllegalParameterException, AuthStorageException {
		
		final Set<StoredToken> tokens = auth.getTokens(
				getTokenFromCookie(headers, cfg.getTokenCookieName()), new UserName(user));
		final List<UIToken> uitokens = tokens.stream()
				.map(t -> new UIToken(t)).collect(Collectors.toList());
		final String urlPrefix = UIPaths.ADMIN_ROOT_USER + SEP + user + SEP +
				UIPaths.ADMIN_TOKENS + SEP;
		final Map<String, Object> ret = new HashMap<>();
		ret.put(Fields.USER, user);
		ret.put(Fields.TOKENS, uitokens);
		ret.put(Fields.URL_REVOKE, relativize(uriInfo, urlPrefix +
				UIPaths.ADMIN_USER_TOKENS_REVOKE + SEP));
		ret.put(Fields.URL_REVOKE_ALL, relativize(uriInfo, urlPrefix + UIPaths.ADMIN_REVOKE_ALL));
		return ret;
	}
	
	@POST
	@Path(UIPaths.ADMIN_USER_TOKENS_REVOKE_ID)
	public void revokeUserToken(
			@Context final HttpHeaders headers,
			@PathParam(UIPaths.USER) final String user,
			@PathParam(UIPaths.TOKEN_ID) final UUID tokenID)
			throws InvalidTokenException, NoSuchTokenException, UnauthorizedException,
			NoTokenProvidedException, MissingParameterException, IllegalParameterException,
			AuthStorageException {
		auth.revokeToken(getTokenFromCookie(headers, cfg.getTokenCookieName()),
				new UserName(user), tokenID);
	}
	
	@POST
	@Path(UIPaths.ADMIN_USER_TOKENS_REVOKE_ALL)
	public void revokeUserToken(
			@Context final HttpHeaders headers,
			@PathParam(UIPaths.USER) final String user)
			throws InvalidTokenException, UnauthorizedException, NoTokenProvidedException,
			MissingParameterException, IllegalParameterException, AuthStorageException {
		auth.revokeAllTokens(getTokenFromCookie(headers, cfg.getTokenCookieName()),
				new UserName(user));
	}
			
	
	@POST
	@Path(UIPaths.ADMIN_USER_DISABLE)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public void disableUser(
			@Context final HttpHeaders headers,
			@PathParam(UIPaths.USER) final String user,
			@FormParam(Fields.DISABLED) final String disableStr,
			@FormParam(Fields.DISABLED_REASON) final String reason)
			throws MissingParameterException, IllegalParameterException, NoTokenProvidedException,
			InvalidTokenException, UnauthorizedException, AuthStorageException,
			NoSuchUserException {
		final IncomingToken token = getTokenFromCookie(headers, cfg.getTokenCookieName());
		if (disableStr == null) {
			auth.enableAccount(token, new UserName(user));
		} else {
			auth.disableAccount(token, new UserName(user), reason);
		}
	}
	
	@POST
	@Path(UIPaths.ADMIN_USER_FORCE_RESET_PWD)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public void forcePasswordReset(
			@Context final HttpHeaders headers,
			@PathParam(UIPaths.USER) final String user)
			throws MissingParameterException, IllegalParameterException, NoTokenProvidedException,
			InvalidTokenException, UnauthorizedException, AuthStorageException,
			NoSuchUserException {
		final IncomingToken token = getTokenFromCookie(headers, cfg.getTokenCookieName());
		auth.forceResetPassword(token, new UserName(user));
	}
	
	@POST
	@Path(UIPaths.ADMIN_USER_RESET_PWD)
	@Template(name = "/adminpwdreset")
	public Map<String, Object> resetUserPassword(
			@Context final HttpHeaders headers,
			@PathParam(UIPaths.USER) final String user)
			throws NoTokenProvidedException, InvalidTokenException, NoSuchUserException,
			UnauthorizedException, MissingParameterException, IllegalParameterException,
			AuthStorageException{
		final IncomingToken token = getTokenFromCookie(headers, cfg.getTokenCookieName());
		final Password pwd = auth.resetPassword(token, new UserName(user));
		final Map<String, Object> ret = new HashMap<>();
		ret.put(Fields.USER, user);
		ret.put(Fields.PASSWORD, new String(pwd.getPassword()));
		pwd.clear();
		return ret;
	}
	
	@POST
	@Path(UIPaths.ADMIN_USER_ROLES)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public void changeRoles(
			@Context final HttpHeaders headers,
			@PathParam(UIPaths.USER) final String user,
			final MultivaluedMap<String, String> form)
			throws NoSuchUserException, AuthStorageException, NoSuchRoleException,
				MissingParameterException, IllegalParameterException, UnauthorizedException,
				InvalidTokenException, NoTokenProvidedException {
		final IncomingToken token = getTokenFromCookie(headers, cfg.getTokenCookieName());
		final UserName userName = new UserName(user);
		final AuthUser au = auth.getUserAsAdmin(token, userName);
		final Set<Role> addRoles = new HashSet<>();
		final Set<Role> removeRoles = new HashSet<>();
		addRoleFromForm(au, form, addRoles, removeRoles, Role.CREATE_ADMIN);
		addRoleFromForm(au, form, addRoles, removeRoles, Role.ADMIN);
		addRoleFromForm(au, form, addRoles, removeRoles, Role.DEV_TOKEN);
		addRoleFromForm(au, form, addRoles, removeRoles, Role.SERV_TOKEN);
		auth.updateRoles(token, userName, addRoles, removeRoles);
	}

	private void addRoleFromForm(
			final AuthUser user,
			final MultivaluedMap<String, String> form,
			final Set<Role> addRoles,
			final Set<Role> removeRoles,
			final Role role) {
		if (form.get(role.getID()) != null) {
			if (!user.hasRole(role)) {
				addRoles.add(role);
			}
		} else {
			if (user.hasRole(role)) {
				removeRoles.add(role);
			}
		}
	}
	
	@POST
	@Path(UIPaths.ADMIN_USER_CUSTOM_ROLES)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public void changeCustomRoles(
			@Context final HttpHeaders headers,
			@PathParam(UIPaths.USER) final String user,
			final MultivaluedMap<String, String> form)
			throws NoSuchUserException, AuthStorageException,
			NoSuchRoleException, MissingParameterException,
			IllegalParameterException, UnauthorizedException,
			InvalidTokenException, NoTokenProvidedException {
		final UserName userName = new UserName(user);
		final Set<String> addRoles = new HashSet<>();
		final Set<String> removeRoles = new HashSet<>();
		final IncomingToken token = getTokenFromCookie(headers, cfg.getTokenCookieName());
		processRolesFromForm(token, form, addRoles, removeRoles);
		auth.updateCustomRoles(token, userName, addRoles, removeRoles);
	}

	private void processRolesFromForm(
			final IncomingToken token,
			final MultivaluedMap<String, String> form,
			final Set<String> addRoles,
			final Set<String> removeRoles)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException {
		final Set<String> croles = auth.getCustomRoles(token, true).stream().map(r -> r.getID())
				.collect(Collectors.toSet());
		for (final String s: croles) {
			if (form.get(s) != null) {
				addRoles.add(s);
			} else {
				removeRoles.add(s);
			}
		}
	}

	@GET
	@Path(UIPaths.ADMIN_CUSTOM_ROLES)
	@Template(name = "/admincustomroles")
	public Map<String, Object> customRoles(
			@Context final HttpHeaders headers,
			@Context final UriInfo uriInfo)
			throws AuthStorageException, InvalidTokenException,
			UnauthorizedException, NoTokenProvidedException {
		final IncomingToken token = getTokenFromCookie(headers, cfg.getTokenCookieName());
		final List<Map<String, String>> roles = UIUtils.customRolesToList(
				auth.getCustomRoles(token, true));
		return ImmutableMap.of(
				Fields.URL_CUSTOM_ROLE, relativize(uriInfo, UIPaths.ADMIN_ROOT_CUSTOM_ROLES_SET),
				Fields.URL_DELETE_CUSTOM_ROLE,
					relativize(uriInfo, UIPaths.ADMIN_ROOT_CUSTOM_ROLES_DELETE),
				Fields.ROLES, roles);
	}
	
	// might make more sense to have separate create and edit methods for roles
	@POST // should take PUT as well
	@Path(UIPaths.ADMIN_CUSTOM_ROLES_SET)
	public void createCustomRole(
			@Context final HttpHeaders headers,
			@FormParam(Fields.ID) final String roleId,
			@FormParam(Fields.DESCRIPTION) final String description)
			throws MissingParameterException, AuthStorageException, InvalidTokenException,
				UnauthorizedException, NoTokenProvidedException, IllegalParameterException {
		auth.setCustomRole(getTokenFromCookie(headers, cfg.getTokenCookieName()),
				new CustomRole(roleId, description));
	}
	
	@POST // should take DELETE as well
	@Path(UIPaths.ADMIN_CUSTOM_ROLES_DELETE)
	public void deleteCustomRole(
			@Context final HttpHeaders headers,
			@FormParam(Fields.ID) final String roleId)
			throws MissingParameterException, AuthStorageException,
			InvalidTokenException, UnauthorizedException,
			NoTokenProvidedException, NoSuchRoleException, IllegalParameterException {
		auth.deleteCustomRole(getTokenFromCookie(headers, cfg.getTokenCookieName()), roleId);
	}
	
	@POST
	@Path(UIPaths.ADMIN_CONFIG_RESET)
	public void resetConfig(
			@Context final HttpHeaders headers)
			throws InvalidTokenException, UnauthorizedException, NoTokenProvidedException,
			AuthStorageException {
		auth.resetConfigToDefault(getTokenFromCookie(headers, cfg.getTokenCookieName()));
	}
	
	@GET
	@Path(UIPaths.ADMIN_CONFIG)
	@Template(name = "/adminconfig")
	@Produces(MediaType.TEXT_HTML)
	public Map<String, Object> getConfig(
			@Context final HttpHeaders headers,
			@Context final UriInfo uriInfo)
			throws InvalidTokenException, UnauthorizedException,
			NoTokenProvidedException, AuthStorageException {
		final AuthConfigSetWithUpdateTime<AuthExternalConfig<State>> cfgset;
		try {
			cfgset = auth.getConfig(getTokenFromCookie(headers, cfg.getTokenCookieName()),
					new AuthExternalConfigMapper());
		} catch (ExternalConfigMappingException e) {
			throw new RuntimeException(
					"There's something very wrong in the database config", e);
		}
		
		final Map<String, Object> ret = new HashMap<>();
		final List<Map<String, Object>> prov = new ArrayList<>();
		ret.put(Fields.PROVIDERS, prov);
		for (final Entry<String, ProviderConfig> e:
				cfgset.getCfg().getProviders().entrySet()) {
			final Map<String, Object> p = new HashMap<>();
			p.put(Fields.PROVIDER, e.getKey());
			p.put(Fields.CFG_PROV_ENABLED, e.getValue().isEnabled());
			p.put(Fields.CFG_PROV_FORCE_LINK_CHOICE, e.getValue().isForceLinkChoice());
			p.put(Fields.CFG_PROV_FORCE_LOGIN_CHOICE, e.getValue().isForceLoginChoice());
			prov.add(p);
		}
		ret.put(Fields.CFG_SHOW_STACK_TRACE,
				cfgset.getExtcfg().isIncludeStackTraceInResponseOrDefault());
		ret.put(Fields.CFG_IGNORE_IP_HEADERS, cfgset.getExtcfg().isIgnoreIPHeadersOrDefault());
		final ConfigItem<URL, State> loginallowed =
				cfgset.getExtcfg().getAllowedLoginRedirectPrefix();
		ret.put(Fields.CFG_ALLOWED_LOGIN_REDIRECT,
				loginallowed.hasItem() ? loginallowed.getItem() : null);
		final ConfigItem<URL, State> logincomplete =
				cfgset.getExtcfg().getCompleteLoginRedirect();
		ret.put(Fields.CFG_COMPLETE_LOGIN_REDIRECT,
				logincomplete.hasItem() ? logincomplete.getItem() : null);
		final ConfigItem<URL, State> postlink = cfgset.getExtcfg().getPostLinkRedirect();
		ret.put(Fields.CFG_POST_LINK_REDIRECT, postlink.hasItem() ? postlink.getItem() : null);
		final ConfigItem<URL, State> completelink =
				cfgset.getExtcfg().getCompleteLinkRedirect();
		ret.put(Fields.CFG_COMPLETE_LINK_REDIRECT,
				completelink.hasItem() ? completelink.getItem() : null);
		
		ret.put(Fields.CFG_ALLOW_LOGIN, cfgset.getCfg().isLoginAllowed());
		ret.put(Fields.CFG_TOKEN_CACHE_TIME, cfgset.getCfg().getTokenLifetimeMS(
				TokenLifetimeType.EXT_CACHE) / MIN_IN_MS);
		ret.put(Fields.CFG_TOKEN_LOGIN, cfgset.getCfg().getTokenLifetimeMS(
				TokenLifetimeType.LOGIN) / DAY_IN_MS);
		ret.put(Fields.CFG_TOKEN_AGENT, cfgset.getCfg().getTokenLifetimeMS(
				TokenLifetimeType.AGENT) / DAY_IN_MS);
		ret.put(Fields.CFG_TOKEN_DEV, cfgset.getCfg().getTokenLifetimeMS(
				TokenLifetimeType.DEV) / DAY_IN_MS);
		ret.put(Fields.CFG_TOKEN_SERV, cfgset.getCfg().getTokenLifetimeMS(
				TokenLifetimeType.SERV) / DAY_IN_MS);

		ret.put(Fields.CFG_UPDATE_TIME_SEC, cfgset.getUpdateTimeInMillis() / 1000);
		
		ret.put(Fields.URL_CFG_BASIC, relativize(uriInfo, UIPaths.ADMIN_ROOT_CONFIG_BASIC));
		ret.put(Fields.URL_TOKEN, relativize(uriInfo, UIPaths.ADMIN_ROOT_CONFIG_TOKEN));
		ret.put(Fields.URL_PROVIDER, relativize(uriInfo, UIPaths.ADMIN_ROOT_CONFIG_PROVIDER));
		ret.put(Fields.URL_RESET, relativize(uriInfo, UIPaths.ADMIN_ROOT_CONFIG_RESET));
		return ret;
	}
	
	@POST
	@Path(UIPaths.ADMIN_CONFIG_BASIC)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public void updateBasic(
			@Context final HttpHeaders headers,
			@FormParam(Fields.CFG_ALLOW_LOGIN) final String allowLogin,
			@FormParam(Fields.CFG_SHOW_STACK_TRACE) final String showstack,
			@FormParam(Fields.CFG_IGNORE_IP_HEADERS) final String ignoreip,
			@FormParam(Fields.CFG_ALLOWED_LOGIN_REDIRECT) final String allowedloginredirect,
			@FormParam(Fields.CFG_COMPLETE_LOGIN_REDIRECT) final String completeloginredirect,
			@FormParam(Fields.CFG_POST_LINK_REDIRECT) final String postlinkredirect,
			@FormParam(Fields.CFG_COMPLETE_LINK_REDIRECT) final String completelinkredirect)
			throws IllegalParameterException, InvalidTokenException,
				UnauthorizedException, NoTokenProvidedException, AuthStorageException {
		final ConfigItem<URL, Action> postlogin = getURL(allowedloginredirect);
		final ConfigItem<URL, Action> completelogin = getURL(completeloginredirect);
		final ConfigItem<URL, Action> postlink = getURL(postlinkredirect);
		final ConfigItem<URL, Action> completelink = getURL(completelinkredirect);
		final ConfigItem<Boolean, Action> ignore = ConfigItem.set(!nullOrEmpty(ignoreip));
		final ConfigItem<Boolean, Action> stack = ConfigItem.set(!nullOrEmpty(showstack));
		
		final AuthExternalConfig<Action> ext = new AuthExternalConfig<>(
				postlogin, completelogin, postlink, completelink, ignore, stack);
		try {
			auth.updateConfig(getTokenFromCookie(headers, cfg.getTokenCookieName()),
					AuthConfigUpdate.getBuilder().withLoginAllowed(!nullOrEmpty(allowLogin))
							.withExternalConfig(ext).build());
		} catch (NoSuchIdentityProviderException e) {
			throw new RuntimeException("OK, that's not supposed to happen", e);
		}
	}
	
	private static class SetConfig extends IncomingJSON {
		
		//TODO UI CODE include all the config parameters
		
		private final Boolean allowLogin;
		private final Boolean showStack;
		private final Boolean ignoreIP;
		
		private final String allowedLoginURL;
		private final String completeLoginURL;
		private final String postLinkURL;
		private final String completeLinkURL;
		
		public final List<String> remove;
		
		@JsonCreator
		public SetConfig(
				@JsonProperty(Fields.CFG_ALLOW_LOGIN) final Boolean allowLogin,
				@JsonProperty(Fields.CFG_SHOW_STACK_TRACE) final Boolean showStack,
				@JsonProperty(Fields.CFG_IGNORE_IP_HEADERS) final Boolean ignoreIP,
				@JsonProperty(Fields.CFG_ALLOWED_LOGIN_REDIRECT) final String allowedLoginURL,
				@JsonProperty(Fields.CFG_COMPLETE_LOGIN_REDIRECT) final String completeLoginURL,
				@JsonProperty(Fields.CFG_POST_LINK_REDIRECT) final String postLinkURL,
				@JsonProperty(Fields.CFG_COMPLETE_LINK_REDIRECT) final String completeLinkURL,
				@JsonProperty(Fields.CFG_REMOVE) final List<String> remove) {
			this.allowLogin = allowLogin;
			this.showStack = showStack;
			this.ignoreIP = ignoreIP;
			this.allowedLoginURL = allowedLoginURL;
			this.completeLoginURL = completeLoginURL;
			this.postLinkURL = postLinkURL;
			this.completeLinkURL = completeLinkURL;
			this.remove = remove == null ? Collections.emptyList() : remove;
		}
		
		public Boolean getAllowLogin() {
			return allowLogin;
		}
		
		public ConfigItem<Boolean, Action> getShowStack() {
			return getBoolean(showStack, Fields.CFG_SHOW_STACK_TRACE);
		}
		
		public ConfigItem<Boolean, Action> getIgnoreIP() {
			return getBoolean(ignoreIP, Fields.CFG_IGNORE_IP_HEADERS);
		}
		
		public ConfigItem<URL, Action> getAllowedLoginURLPrefix()
				throws IllegalParameterException {
			return getURL(allowedLoginURL, Fields.CFG_ALLOWED_LOGIN_REDIRECT);
		}

		public ConfigItem<URL, Action> getCompleteLoginURL()
				throws IllegalParameterException {
			return getURL(completeLoginURL, Fields.CFG_COMPLETE_LOGIN_REDIRECT);
		}
		
		public ConfigItem<URL, Action> getPostLinkURL()
				throws IllegalParameterException {
			return getURL(postLinkURL, Fields.CFG_POST_LINK_REDIRECT);
		}
		
		public ConfigItem<URL, Action> getCompleteLinkURL()
				throws IllegalParameterException {
			return getURL(completeLinkURL, Fields.CFG_COMPLETE_LINK_REDIRECT);
		}
		
		private ConfigItem<URL, Action> getURL(final String s, final String field)
				throws IllegalParameterException {
			final ConfigItem<URL, Action> act = getRemove(field);
			// may want to throw an error if both remove and set are true in input
			if (act != null) {
				return act;
			}
			if (nullOrEmpty(s)) {
				return ConfigItem.noAction();
			}
			try {
				final ConfigItem<URL, Action> item = ConfigItem.set(new URL(s));
				item.getItem().toURI(); // check for legal URIs
				return item;
			} catch (MalformedURLException | URISyntaxException e) {
				throw new IllegalParameterException("Illegal URL: " + s, e);
			}
		}

		private <T> ConfigItem<T, Action> getRemove(final String field) {
			if (remove.contains(field)) {
				return ConfigItem.remove();
			}
			return null;
		}

		private ConfigItem<Boolean, Action> getBoolean(final Boolean b, final String field) {
			final ConfigItem<Boolean, Action> act = getRemove(field);
			if (act != null) {
				return act;
			}
			if (b == null) {
				return ConfigItem.noAction();
			}
			return ConfigItem.set(b);
		}
	}
	
	@POST
	@Path(UIPaths.ADMIN_CONFIG)
	@Consumes(MediaType.APPLICATION_JSON)
	public void updateConfig(
			@HeaderParam(UIConstants.HEADER_TOKEN) final String token,
			final SetConfig config)
			throws MissingParameterException, IllegalParameterException, InvalidTokenException,
				UnauthorizedException, NoTokenProvidedException, AuthStorageException {
		if (config == null) {
			throw new MissingParameterException("JSON body missing");
		}
		config.exceptOnAdditionalProperties();
		final AuthExternalConfig<Action> ext = new AuthExternalConfig<>(
				config.getAllowedLoginURLPrefix(),
				config.getCompleteLoginURL(),
				config.getPostLinkURL(),
				config.getCompleteLinkURL(),
				config.getIgnoreIP(),
				config.getShowStack());
		try {
			auth.updateConfig(getToken(token),
					AuthConfigUpdate.getBuilder().withNullableLoginAllowed(config.getAllowLogin())
							.withExternalConfig(ext).build());
		} catch (NoSuchIdentityProviderException e) {
			throw new RuntimeException("OK, that's not supposed to happen", e);
		}
	}

	private ConfigItem<URL, Action> getURL(final String putativeURL)
			throws IllegalParameterException {
		final ConfigItem<URL, Action> redirect;
		if (nullOrEmpty(putativeURL)) {
			redirect = ConfigItem.remove();
		} else {
			try {
				redirect = ConfigItem.set(new URL(putativeURL));
				redirect.getItem().toURI(); // check for bad URIs
			} catch (MalformedURLException | URISyntaxException e) {
				throw new IllegalParameterException("Illegal URL: " + putativeURL, e);
			}
		}
		return redirect;
	}
	
	@POST
	@Path(UIPaths.ADMIN_CONFIG_PROVIDER)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public void configProvider(
			@Context final HttpHeaders headers,
			@FormParam(Fields.PROVIDER) final String provname,
			@FormParam(Fields.CFG_PROV_ENABLED) final String enabled,
			@FormParam(Fields.CFG_PROV_FORCE_LOGIN_CHOICE) final String forceLogin,
			@FormParam(Fields.CFG_PROV_FORCE_LINK_CHOICE) final String forcelink)
			throws MissingParameterException, InvalidTokenException,
			UnauthorizedException, NoTokenProvidedException,
			AuthStorageException, NoSuchIdentityProviderException {
		if (provname == null || provname.trim().isEmpty()) {
			throw new MissingParameterException(Fields.PROVIDER);
		}
		auth.updateConfig(getTokenFromCookie(headers, cfg.getTokenCookieName()),
				AuthConfigUpdate.getBuilder().withProviderUpdate(provname, new ProviderUpdate(
						!nullOrEmpty(enabled), !nullOrEmpty(forceLogin), !nullOrEmpty(forcelink)))
				.build());
	}
	
	@POST
	@Path(UIPaths.ADMIN_CONFIG_TOKEN)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public void configTokens(
			@Context final HttpHeaders headers,
			@FormParam(Fields.CFG_TOKEN_CACHE_TIME) final int sugcache,
			@FormParam(Fields.CFG_TOKEN_LOGIN) final int login,
			@FormParam(Fields.CFG_TOKEN_AGENT) final int agent,
			@FormParam(Fields.CFG_TOKEN_DEV) final int dev,
			@FormParam(Fields.CFG_TOKEN_SERV) final long serv)
			throws IllegalParameterException, InvalidTokenException,
			UnauthorizedException, NoTokenProvidedException,
			AuthStorageException {
		if (sugcache < 1) {
			throw new IllegalParameterException(
					"Suggested token cache time must be at least 1");
		}
		if (login < 1) {
			throw new IllegalParameterException(
					"Login token expiration time must be at least 1");
		}
		if (agent < 1) {
			throw new IllegalParameterException(
					"Agent token expiration time must be at least 1");
		}
		if (dev < 1) {
			throw new IllegalParameterException(
					"Developer token expiration time must be at least 1");
		}
		if (serv < 1) {
			throw new IllegalParameterException(
					"Server token expiration time must be at least 1");
		}
		final AuthConfigUpdate<ExternalConfig> acu = AuthConfigUpdate.getBuilder()
				.withTokenLifeTime(TokenLifetimeType.EXT_CACHE, safeMult(sugcache, MIN_IN_MS))
				.withTokenLifeTime(TokenLifetimeType.LOGIN, safeMult(login, DAY_IN_MS))
				.withTokenLifeTime(TokenLifetimeType.AGENT, safeMult(agent, DAY_IN_MS))
				.withTokenLifeTime(TokenLifetimeType.DEV, safeMult(dev, DAY_IN_MS))
				.withTokenLifeTime(TokenLifetimeType.SERV, safeMult(serv, DAY_IN_MS))
				.build();
		try {
			auth.updateConfig(getTokenFromCookie(headers, cfg.getTokenCookieName()), acu);
		} catch (NoSuchIdentityProviderException e) {
			throw new RuntimeException("OK, that's not supposed to happen", e);
		}
	}
	
	private Long safeMult(final long l1, final long l2) {
		
		if (Long.MAX_VALUE / l2 < l1) {
			return Long.MAX_VALUE;
		}
		return l1 * l2;
	}
}
