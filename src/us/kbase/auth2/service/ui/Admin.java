package us.kbase.auth2.service.ui;

import static us.kbase.auth2.service.ui.UIUtils.getTokenFromCookie;
import static us.kbase.auth2.service.ui.UIUtils.relativize;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriInfo;

import org.glassfish.jersey.server.mvc.Template;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.AuthConfig;
import us.kbase.auth2.lib.AuthConfig.ProviderConfig;
import us.kbase.auth2.lib.AuthConfig.TokenLifetimeType;
import us.kbase.auth2.lib.AuthConfigSet;
import us.kbase.auth2.lib.AuthUser;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.Password;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.service.AuthAPIStaticConfig;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.auth2.service.AuthExternalConfig.AuthExternalConfigMapper;

@Path(UIPaths.ADMIN_ROOT)
public class Admin {

	//TODO TEST
	//TODO JAVADOC

	//TODO ADMIN find user
	
	private static final String SEP = UIPaths.SEP;
	
	private static final int MIN_IN_MS = 60 * 1000;

	private static final int DAY_IN_MS = 24 * 60 * MIN_IN_MS;

	@Inject
	private Authentication auth;
	
	@Inject
	private AuthAPIStaticConfig cfg;
	
	@GET
	@Template(name = "/admingeneral")
	public Map<String, String> admin(@Context final UriInfo uriInfo) {
		return ImmutableMap.of("reseturl", relativize(uriInfo, UIPaths.ADMIN_ROOT_RESET_PWD));
	}
	
	@POST
	@Path(UIPaths.ADMIN_RESET_PWD)
	public void forceResetAllPasswords(@Context final HttpHeaders headers)
			throws NoTokenProvidedException, InvalidTokenException, UnauthorizedException,
			AuthStorageException {
		auth.forceResetAllPasswords(getTokenFromCookie(headers, cfg.getTokenCookieName()));
	}
	
	@GET
	@Path(UIPaths.ADMIN_LOCALACCOUNT)
	@Template(name = "/adminlocalaccount")
	@Produces(MediaType.TEXT_HTML)
	public Map<String, String> createLocalAccountStart(@Context final UriInfo uriInfo) {
		return ImmutableMap.of("targeturl", relativize(uriInfo, UIPaths.ADMIN_ROOT_LOCAL_CREATE));
	}
	
	@POST
	@Path(UIPaths.ADMIN_LOCAL_CREATE)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.TEXT_HTML)
	@Template(name = "/adminlocalaccountcreated")
	public Map<String, String> createLocalAccountComplete(
			@Context final HttpHeaders headers,
			@FormParam("user") final String userName,
			@FormParam("display") final String displayName,
			@FormParam("email") final String email)
			throws AuthStorageException, UserExistsException,
			MissingParameterException, IllegalParameterException,
			UnauthorizedException, InvalidTokenException,
			NoTokenProvidedException {
		//TODO LOG log
		final Password pwd = auth.createLocalUser(
				getTokenFromCookie(headers, cfg.getTokenCookieName()),
				new UserName(userName), new DisplayName(displayName), new EmailAddress(email));
		final Map<String, String> ret = ImmutableMap.of(
				"user", userName,
				"display", displayName,
				"email", email,
				"password", new String(pwd.getPassword())); // char[] won't work
		pwd.clear(); // not that this helps much...
		return ret;
	}
	
	@GET
	@Path(UIPaths.ADMIN_USER_PARAM)
	@Template(name = "/adminuser")
	@Produces(MediaType.TEXT_HTML)
	public Map<String, Object> userDisplay(
			@Context final HttpHeaders headers,
			@PathParam("user") final String user,
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
		ret.put("custom", setUpCustomRoles(roles, au.getCustomRoles()));
		ret.put("hascustom", !roles.isEmpty());
		ret.put("roleurl", relativize(uriInfo, userPrefix + UIPaths.ADMIN_ROLES));
		ret.put("customroleurl", relativize(uriInfo, userPrefix + UIPaths.ADMIN_CUSTOM_ROLES));
		ret.put("disableurl", relativize(uriInfo, userPrefix + UIPaths.ADMIN_DISABLE));
		ret.put("reseturl", relativize(uriInfo, userPrefix + UIPaths.ADMIN_RESET_PWD));
		ret.put("user", au.getUserName().getName());
		ret.put("display", au.getDisplayName().getName());
		ret.put("email", au.getEmail().getAddress());
		ret.put("local", au.isLocal());
		ret.put("created", au.getCreated().getTime());
		final Date lastLogin = au.getLastLogin();
		ret.put("lastlogin", lastLogin == null ? null : lastLogin.getTime());
		ret.put("disabled", au.isDisabled());
		ret.put("disabledreason", au.getReasonForDisabled());
		final Date disabled = au.getEnableToggleDate();
		ret.put("enabletoggledate", disabled == null ? null : disabled.getTime());
		final UserName admin = au.getAdminThatToggledEnabledState();
		ret.put("enabledtoggledby", admin == null ? null : admin.getName());
		final Set<Role> r = au.getRoles();
		ret.put("admin", Role.ADMIN.isSatisfiedBy(r));
		ret.put("serv", Role.SERV_TOKEN.isSatisfiedBy(r));
		ret.put("dev", Role.DEV_TOKEN.isSatisfiedBy(r));
		ret.put("createadmin", Role.CREATE_ADMIN.isSatisfiedBy(r));
		return ret;
	}
	
	// might make more sense to have separate create and edit methods for roles

	private List<Map<String, Object>> setUpCustomRoles(
			final Set<CustomRole> roles, final Set<String> set) {
		final List<Map<String, Object>> ret = new LinkedList<>();
		for (final CustomRole r: roles) {
			ret.add(ImmutableMap.of(
					"desc", r.getDesc(),
					"id", r.getID(),
					"has", set.contains(r.getID())));
		}
		return ret;
	}

	@POST
	@Path(UIPaths.ADMIN_USER_DISABLE)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public void disableUser(
			@Context final HttpHeaders headers,
			@PathParam("user") final String user,
			@FormParam("disable") final String disableStr,
			@FormParam("reason") final String reason)
			throws MissingParameterException, IllegalParameterException, NoTokenProvidedException,
			InvalidTokenException, UnauthorizedException, AuthStorageException,
			NoSuchUserException {
		final boolean disable = disableStr != null;
		final IncomingToken token = getTokenFromCookie(headers, cfg.getTokenCookieName());
		auth.disableAccount(token, new UserName(user), disable, reason);
	}
	
	@POST
	@Path(UIPaths.ADMIN_USER_RESET_PWD)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public void forcePasswordReset(
			@Context final HttpHeaders headers,
			@PathParam("user") final String user)
			throws MissingParameterException, IllegalParameterException, NoTokenProvidedException,
			InvalidTokenException, UnauthorizedException, AuthStorageException,
			NoSuchUserException {
		final IncomingToken token = getTokenFromCookie(headers, cfg.getTokenCookieName());
		auth.forceResetPassword(token, new UserName(user));
	}
	
	@POST
	@Path(UIPaths.ADMIN_USER_ROLES)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public void changeRoles(
			@Context final HttpHeaders headers,
			@PathParam("user") final String user,
			final MultivaluedMap<String, String> form)
			throws NoSuchUserException, AuthStorageException,
			NoSuchRoleException, MissingParameterException,
			IllegalParameterException, UnauthorizedException,
			InvalidTokenException, NoTokenProvidedException {
		final Set<Role> roles = new HashSet<>();
		addRoleFromForm(form, roles, "createadmin", Role.CREATE_ADMIN);
		addRoleFromForm(form, roles, "admin", Role.ADMIN);
		addRoleFromForm(form, roles, "dev", Role.DEV_TOKEN);
		addRoleFromForm(form, roles, "serv", Role.SERV_TOKEN);
		auth.updateRoles(getTokenFromCookie(headers, cfg.getTokenCookieName()),
				new UserName(user), roles);
	}
	
	@POST
	@Path(UIPaths.ADMIN_USER_CUSTOM_ROLES)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public void changeCustomRoles(
			@Context final HttpHeaders headers,
			@PathParam("user") final String user,
			final MultivaluedMap<String, String> form)
			throws NoSuchUserException, AuthStorageException,
			NoSuchRoleException, MissingParameterException,
			IllegalParameterException, UnauthorizedException,
			InvalidTokenException, NoTokenProvidedException {
		final UserName userName = new UserName(user);
		auth.updateCustomRoles(getTokenFromCookie(headers, cfg.getTokenCookieName()),
				userName, getRoleIds(form));
	}

	private Set<String> getRoleIds(final MultivaluedMap<String, String> form) {
		final Set<String> ret = new HashSet<>();
		for (final String s: form.keySet()) {
			if (form.get(s) != null) {
					ret.add(s);
			}
		}
		return ret;
	}

	private void addRoleFromForm(
			final MultivaluedMap<String, String> form,
			final Set<Role> roles,
			final String rstr,
			final Role role) {
		if (form.get(rstr) != null) {
			roles.add(role);
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
		final Set<CustomRole> roles = auth.getCustomRoles(token, true);
		return ImmutableMap.of(
				"custroleurl", relativize(uriInfo, UIPaths.ADMIN_ROOT_CUSTOM_ROLES_SET),
				"delroleurl", relativize(uriInfo, UIPaths.ADMIN_ROOT_CUSTOM_ROLES_DELETE),
				"roles", roles);
	}
	
	@POST // should take PUT as well
	@Path(UIPaths.ADMIN_CUSTOM_ROLES_SET)
	public void createCustomRole(
			@Context final HttpHeaders headers,
			@FormParam("id") final String roleId,
			@FormParam("desc") final String description)
			throws MissingParameterException, AuthStorageException,
			InvalidTokenException, UnauthorizedException,
			NoTokenProvidedException {
		auth.setCustomRole(getTokenFromCookie(headers, cfg.getTokenCookieName()),
				roleId, description);
	}
	
	@POST // should take DELETE as well
	@Path(UIPaths.ADMIN_CUSTOM_ROLES_DELETE)
	public void deleteCustomRole(
			@Context final HttpHeaders headers,
			@FormParam("id") final String roleId)
			throws MissingParameterException, AuthStorageException,
			InvalidTokenException, UnauthorizedException,
			NoTokenProvidedException, NoSuchRoleException {
		auth.deleteCustomRole(getTokenFromCookie(headers, cfg.getTokenCookieName()), roleId);
	}
	
	//TODO CONFIG reset to defaults
	@GET
	@Path(UIPaths.ADMIN_CONFIG)
	@Template(name = "/adminconfig")
	@Produces(MediaType.TEXT_HTML)
	public Map<String, Object> getConfig(
			@Context final HttpHeaders headers,
			@Context final UriInfo uriInfo)
			throws InvalidTokenException, UnauthorizedException,
			NoTokenProvidedException, AuthStorageException {
		final AuthConfigSet<AuthExternalConfig> cfgset;
		try {
			cfgset = auth.getConfig(getTokenFromCookie(headers, cfg.getTokenCookieName()),
					new AuthExternalConfigMapper());
		} catch (ExternalConfigMappingException e) {
			throw new RuntimeException(
					"There's something very wrong in the database config", e);
		}
		
		final Map<String, Object> ret = new HashMap<>();
		final List<Map<String, Object>> prov = new ArrayList<>();
		ret.put("providers", prov);
		for (final Entry<String, ProviderConfig> e:
				cfgset.getCfg().getProviders().entrySet()) {
			final Map<String, Object> p = new HashMap<>();
			p.put("name", e.getKey());
			p.put("enabled", e.getValue().isEnabled());
			p.put("forcelinkchoice", e.getValue().isForceLinkChoice());
			prov.add(p);
		}
		ret.put("showstack", cfgset.getExtcfg().isIncludeStackTraceInResponse());
		ret.put("ignoreip", cfgset.getExtcfg().isIgnoreIPHeaders());
		ret.put("allowedloginredirect", cfgset.getExtcfg().getAllowedLoginRedirectPrefix());
		ret.put("completeloginredirect", cfgset.getExtcfg().getCompleteLoginRedirect());
		ret.put("postlinkredirect", cfgset.getExtcfg().getPostLinkRedirect());
		ret.put("completelinkredirect", cfgset.getExtcfg().getCompleteLinkRedirect());
		
		ret.put("allowlogin", cfgset.getCfg().isLoginAllowed());
		ret.put("tokensugcache", cfgset.getCfg().getTokenLifetimeMS(
				TokenLifetimeType.EXT_CACHE) / MIN_IN_MS);
		ret.put("tokenlogin", cfgset.getCfg().getTokenLifetimeMS(
				TokenLifetimeType.LOGIN) / DAY_IN_MS);
		ret.put("tokendev", cfgset.getCfg().getTokenLifetimeMS(
				TokenLifetimeType.DEV) / DAY_IN_MS);
		ret.put("tokenserv", cfgset.getCfg().getTokenLifetimeMS(
				TokenLifetimeType.SERV) / DAY_IN_MS);

		ret.put("basicurl", relativize(uriInfo, UIPaths.ADMIN_ROOT_CONFIG_BASIC));
		ret.put("tokenurl", relativize(uriInfo, UIPaths.ADMIN_ROOT_CONFIG_TOKEN));
		ret.put("providerurl", relativize(uriInfo, UIPaths.ADMIN_ROOT_CONFIG_PROVIDER));
		return ret;
	}
	
	@POST
	@Path(UIPaths.ADMIN_CONFIG_BASIC)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public void updateBasic(
			@Context final HttpHeaders headers,
			@FormParam("allowlogin") final String allowLogin,
			@FormParam("showstack") final String showstack,
			@FormParam("ignoreip") final String ignoreip,
			@FormParam("allowedloginredirect") final String allowedloginredirect,
			@FormParam("completeloginredirect") final String completeloginredirect,
			@FormParam("postlinkredirect") final String postlinkredirect,
			@FormParam("completelinkredirect") final String completelinkredirect)
			throws IllegalParameterException, InvalidTokenException,
			UnauthorizedException, NoTokenProvidedException,
			AuthStorageException {
		final URL postlogin = getURL(allowedloginredirect);
		final URL completelogin = getURL(completeloginredirect);
		final URL postlink = getURL(postlinkredirect);
		final URL completelink = getURL(completelinkredirect);
		
		final AuthExternalConfig ext = new AuthExternalConfig(
				postlogin, completelogin, postlink, completelink,
				!nullOrEmpty(ignoreip), !nullOrEmpty(showstack));
		try {
			auth.updateConfig(getTokenFromCookie(headers, cfg.getTokenCookieName()),
					new AuthConfigSet<>(new AuthConfig(!nullOrEmpty(allowLogin), null, null),
							ext));
		} catch (NoSuchIdentityProviderException e) {
			throw new RuntimeException("OK, that's not supposed to happen", e);
		}
	}

	private URL getURL(final String putativeURL) throws IllegalParameterException {
		final URL redirect;
		if (putativeURL == null || putativeURL.isEmpty()) {
			redirect = null;
		} else {
			try {
				redirect = new URL(putativeURL);
			} catch (MalformedURLException e) {
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
			@FormParam("provname") final String provname,
			@FormParam("enabled") final String enabled,
			@FormParam("forcelinkchoice") final String forcelink)
			throws MissingParameterException, InvalidTokenException,
			UnauthorizedException, NoTokenProvidedException,
			AuthStorageException, NoSuchIdentityProviderException {
		final ProviderConfig pc = new ProviderConfig(
				!nullOrEmpty(enabled), !nullOrEmpty(forcelink));
		if (provname == null || provname.isEmpty()) {
			throw new MissingParameterException("provname");
		}
		final Map<String, ProviderConfig> provs = new HashMap<>();
		provs.put(provname, pc);
		auth.updateConfig(getTokenFromCookie(headers, cfg.getTokenCookieName()),
				new AuthConfigSet<>(new AuthConfig(null, provs, null),
						AuthExternalConfig.NO_CHANGE));
	}
	
	@POST
	@Path(UIPaths.ADMIN_CONFIG_TOKEN)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public void configTokens(
			@Context final HttpHeaders headers,
			@FormParam("tokensugcache") final int sugcache,
			@FormParam("tokenlogin") final int login,
			@FormParam("tokendev") final int dev,
			@FormParam("tokenserv") final long serv)
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
		if (dev < 1) {
			throw new IllegalParameterException(
					"Developer token expiration time must be at least 1");
		}
		if (serv < 1) {
			throw new IllegalParameterException(
					"Server token expiration time must be at least 1");
		}
		final Map<TokenLifetimeType, Long> t = new HashMap<>();
		t.put(TokenLifetimeType.EXT_CACHE, safeMult(sugcache, MIN_IN_MS));
		t.put(TokenLifetimeType.LOGIN, safeMult(login, DAY_IN_MS));
		t.put(TokenLifetimeType.DEV, safeMult(dev, DAY_IN_MS));
		t.put(TokenLifetimeType.SERV, safeMult(serv, DAY_IN_MS));
		try {
			auth.updateConfig(getTokenFromCookie(headers, cfg.getTokenCookieName()),
					new AuthConfigSet<>(new AuthConfig(null, null, t),
							AuthExternalConfig.NO_CHANGE));
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

	private boolean nullOrEmpty(final String s) {
		return s == null || s.isEmpty();
	}

}
