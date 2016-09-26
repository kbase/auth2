package us.kbase.auth2.service.api;

import static us.kbase.auth2.service.api.APIUtils.getToken;
import static us.kbase.auth2.service.api.APIUtils.relativize;

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
import javax.ws.rs.CookieParam;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriInfo;

import org.glassfish.jersey.server.mvc.Template;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.AuthConfig.ProviderConfig;
import us.kbase.auth2.lib.AuthConfig.TokenLifetimeType;
import us.kbase.auth2.lib.AuthConfigSet;
import us.kbase.auth2.lib.AuthUser;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.Password;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.auth2.service.AuthExternalConfig.AuthExternalConfigMapper;

@Path("/admin")
public class Admin {

	//TODO TEST
	//TODO JAVADOC

	//TODO ADMIN reset user pwd
	//TODO ADMIN find user
	
	@Inject
	private Authentication auth;
	
	@GET
	public String admin() {
		return "foo";
	}
	
	@GET
	@Path("/localaccount")
	@Template(name = "/adminlocalaccount")
	@Produces(MediaType.TEXT_HTML)
	public Map<String, String> createLocalAccountStart(
			@Context final UriInfo uriInfo) {
		return ImmutableMap.of("targeturl",
					relativize(uriInfo, "/admin/localaccount/create"));
	}
	
	@POST
	@Path("/localaccount/create")
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.TEXT_HTML)
	@Template(name = "/adminlocalaccountcreated")
	public Map<String, String> createLocalAccountComplete(
			@CookieParam("token") final String adminToken,
			@FormParam("user") final String userName,
			@FormParam("full") final String fullName,
			@FormParam("email") final String email)
			throws AuthStorageException, UserExistsException,
			MissingParameterException, IllegalParameterException,
			UnauthorizedException, InvalidTokenException,
			NoTokenProvidedException {
		//TODO LOG log
		//TODO INPUT email class with proper checking (probably not validation)
		if (userName == null) {
			throw new MissingParameterException("userName");
		}
		final Password pwd = auth.createLocalUser(getToken(adminToken),
				new UserName(userName), fullName, email);
		final Map<String, String> ret = ImmutableMap.of(
				"user", userName,
				"full", fullName,
				"email", email,
				"password", new String(pwd.getPassword())); // char[] won't work
		pwd.clear(); // not that this helps much...
		return ret;
	}
	
	@GET
	@Path("/user/{user}")
	@Template(name = "/adminuser")
	@Produces(MediaType.TEXT_HTML)
	public Map<String, Object> userDisplay(
			@CookieParam("token") final String incToken,
			@PathParam("user") final String user,
			@Context final UriInfo uriInfo)
			throws AuthStorageException, NoSuchUserException,
			MissingParameterException, IllegalParameterException,
			InvalidTokenException, UnauthorizedException,
			NoTokenProvidedException {
		final IncomingToken adminToken = getToken(incToken);
		final AuthUser au = auth.getUserAsAdmin(
				adminToken, new UserName(user));
		final Set<CustomRole> roles = auth.getCustomRoles(adminToken);
		final Map<String, Object> ret = new HashMap<>();
		ret.put("custom", setUpCustomRoles(roles, au.getCustomRoles()));
		ret.put("hascustom", !roles.isEmpty());
		ret.put("roleurl", relativize(uriInfo,
				"/admin/user/" + user + "/roles"));
		ret.put("customroleurl", relativize(uriInfo,
				"/admin/user/" + user + "/customroles"));
		ret.put("user", au.getUserName().getName());
		ret.put("full", au.getFullName());
		ret.put("email", au.getEmail());
		ret.put("local", au.isLocal());
		ret.put("created", au.getCreated().getTime());
		final Date lastLogin = au.getLastLogin();
		ret.put("lastlogin", lastLogin == null ? null : lastLogin.getTime());
		final Set<Role> r = au.getRoles();
		//TODO ADMIN only show create-admin & admin buttons when appropriate
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
	@Path("/user/{user}/roles")
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public void changeRoles(
			@CookieParam("token") final String incToken,
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
		auth.updateRoles(getToken(incToken), new UserName(user), roles);
	}
	
	@POST
	@Path("/user/{user}/customroles")
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public void changeCustomRoles(
			@CookieParam("token") final String incToken,
			@PathParam("user") final String user,
			final MultivaluedMap<String, String> form)
			throws NoSuchUserException, AuthStorageException,
			NoSuchRoleException, MissingParameterException,
			IllegalParameterException, UnauthorizedException,
			InvalidTokenException, NoTokenProvidedException {
		final UserName userName = new UserName(user);
		auth.updateCustomRoles(getToken(incToken), userName, getRoleIds(form));
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
	@Path("/customroles")
	@Template(name = "/admincustomroles")
	public Map<String, Object> customRoles(
			@CookieParam("token") final String incToken,
			@Context final UriInfo uriInfo)
			throws AuthStorageException, InvalidTokenException,
			UnauthorizedException, NoTokenProvidedException {
		final Set<CustomRole> roles = auth.getCustomRoles(getToken(incToken));
		return ImmutableMap.of(
				"custroleurl", relativize(uriInfo, "/admin/customroles/set"),
				"roles", roles);
	}
	
	@POST // should take PUT as well
	@Path("/customroles/set")
	public void createCustomRole(
			@CookieParam("token") final String incToken,
			@FormParam("id") final String roleId,
			@FormParam("desc") final String description)
			throws MissingParameterException, AuthStorageException,
			InvalidTokenException, UnauthorizedException,
			NoTokenProvidedException {
		auth.setCustomRole(getToken(incToken), roleId, description);
	}
	
	@GET
	@Path("/config")
	@Template(name = "/config")
	@Produces(MediaType.TEXT_HTML)
	public Map<String, Object> getConfig(
			@CookieParam("token") final String token,
			@Context final UriInfo uriInfo)
			throws InvalidTokenException, UnauthorizedException,
			NoTokenProvidedException, AuthStorageException {
		final AuthConfigSet<AuthExternalConfig> cfg;
		try {
			cfg = auth.getConfig(getToken(token),
					new AuthExternalConfigMapper());
		} catch (ExternalConfigMappingException e) {
			throw new RuntimeException(
					"There's something very wrong in the database config", e);
		}
		
		final Map<String, Object> ret = new HashMap<>();
		final List<Map<String, Object>> prov = new ArrayList<>();
		ret.put("providers", prov);
		for (final Entry<String, ProviderConfig> e:
				cfg.getCfg().getProviders().entrySet()) {
			final Map<String, Object> p = new HashMap<>();
			p.put("name", e.getKey());
			p.put("enabled", e.getValue().isEnabled());
			p.put("forcelinkchoice", e.getValue().isForceLinkChoice());
			prov.add(p);
		}
		ret.put("showtrace", cfg.getExtcfg().isIncludeStackTraceInResponse());
		ret.put("ignoreip", cfg.getExtcfg().isIgnoreIPHeaders());
		ret.put("allowedredirect", cfg.getExtcfg().getAllowedRedirectPrefix());
		
		ret.put("allowlogin", cfg.getCfg().isLoginAllowed());
		ret.put("tokensugcache", cfg.getCfg().getTokenLifetimeMS(
				TokenLifetimeType.EXT_CACHE) / (60 * 1000));
		ret.put("tokenlogin", cfg.getCfg().getTokenLifetimeMS(
				TokenLifetimeType.LOGIN) / (24 * 60 * 60 * 1000));
		ret.put("tokendev", cfg.getCfg().getTokenLifetimeMS(
				TokenLifetimeType.DEV) / (24 * 60 * 60 * 1000));
		ret.put("tokenserv", cfg.getCfg().getTokenLifetimeMS(
				TokenLifetimeType.SERV) / (24 * 60 * 60 * 1000));

		ret.put("basicurl", relativize(uriInfo, "/admin/config/basic"));
		ret.put("tokenurl", relativize(uriInfo, "/admin/config/token"));
		ret.put("providerurl", relativize(uriInfo, "/admin/config/provider"));
		return ret;
	}

}
