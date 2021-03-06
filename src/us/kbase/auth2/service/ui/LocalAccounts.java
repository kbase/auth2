package us.kbase.auth2.service.ui;

import static us.kbase.auth2.service.common.ServiceCommon.getCustomContextFromString;
import static us.kbase.auth2.service.common.ServiceCommon.getTokenContext;
import static us.kbase.auth2.service.common.ServiceCommon.isIgnoreIPsInHeaders;
import static us.kbase.auth2.service.ui.UIUtils.getLoginCookie;
import static us.kbase.auth2.service.ui.UIUtils.relativize;
import static us.kbase.auth2.service.ui.UIUtils.removeLoginCookie;
import static us.kbase.auth2.service.ui.UIUtils.toURI;

import java.util.Map;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.glassfish.jersey.server.mvc.Template;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.LocalLoginResult;
import us.kbase.auth2.lib.Password;
import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.AuthenticationException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.IllegalPasswordException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.service.AuthAPIStaticConfig;
import us.kbase.auth2.service.UserAgentParser;
import us.kbase.auth2.service.common.Fields;

@Path(UIPaths.LOCAL_ROOT)
public class LocalAccounts {
	
	//TODO JAVADOC or swagger

	@Inject
	private Authentication auth;
	
	@Inject
	private AuthAPIStaticConfig cfg;
	
	@Inject
	private UserAgentParser userAgentParser;
	
	@GET
	@Path(UIPaths.LOCAL_LOGIN)
	@Template(name = "/locallogin")
	@Produces(MediaType.TEXT_HTML)
	public Map<String, String> login(@Context final UriInfo uriInfo) {
		return ImmutableMap.of(Fields.URL_LOGIN,
				relativize(uriInfo, UIPaths.LOCAL_ROOT_LOGIN));
	}
	
	//TODO UI will need ajax version or at least something in the body that says a reset is required
	@POST
	@Path(UIPaths.LOCAL_LOGIN)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response loginResult(
			@Context final HttpServletRequest req,
			@FormParam(Fields.USER) final String userName,
			@FormParam(Fields.PASSWORD) String pwd, //char makes Jersey puke
			//checkbox, so "on" = checked, null = not checked
			@FormParam(Fields.STAY_LOGGED_IN) final String stayLoggedIn,
			@FormParam(Fields.CUSTOM_CONTEXT) final String customContext)
			throws AuthStorageException, MissingParameterException,
			AuthenticationException, IllegalParameterException,
			UnauthorizedException {
		if (userName == null || userName.trim().isEmpty()) {
			throw new MissingParameterException(Fields.USER);
		}
		if (pwd == null || pwd.trim().isEmpty()) {
			throw new MissingParameterException(Fields.PASSWORD);
		}
		final Password cpwd = new Password(pwd.toCharArray());
		pwd = null; // try to get pwd GC'd as quickly as possible
		final TokenCreationContext tcc = getTokenContext(userAgentParser, req,
				isIgnoreIPsInHeaders(auth), getCustomContextFromString(customContext));
		
		final LocalLoginResult llr = auth.localLogin(new UserName(userName), cpwd, tcc);
		if (llr.isPwdResetRequired()) {
			return Response.seeOther(toURI(UIPaths.LOCAL_ROOT_RESET + "?" + Fields.USER + "=" +
					llr.getUserName().get().getName())).build();
		}
		return Response.seeOther(toURI(UIPaths.ME_ROOT))
				.cookie(getLoginCookie(cfg.getTokenCookieName(), llr.getToken().get(),
						stayLoggedIn == null))
				.build();
	}
	
	@GET
	@Path(UIPaths.LOCAL_RESET)
	@Template(name = "/localreset")
	public Map<String, Object> resetPasswordStart(
			@QueryParam(Fields.USER) final String user,
			@Context final UriInfo uriInfo) {
		return ImmutableMap.of(Fields.URL_RESET,
					relativize(uriInfo, UIPaths.LOCAL_ROOT_RESET),
				Fields.USER, user == null ? "" : user);
	}
	
	//TODO UI will need an ajax version
	@POST
	@Path(UIPaths.LOCAL_RESET)
	public Response resetPassword(
			@FormParam(Fields.USER) final String userName,
			@FormParam(Fields.PASSWORD_OLD) String pwdold,
			@FormParam(Fields.PASSWORD_NEW) String pwdnew)
			throws MissingParameterException, IllegalParameterException,
				AuthenticationException, UnauthorizedException, AuthStorageException,
				IllegalPasswordException {
		if (userName == null || userName.trim().isEmpty()) {
			throw new MissingParameterException(Fields.USER);
		}
		if (pwdold == null || pwdold.trim().isEmpty()) {
			throw new MissingParameterException(Fields.PASSWORD_OLD);
		}
		if (pwdnew == null || pwdnew.trim().isEmpty()) {
			throw new MissingParameterException(Fields.PASSWORD_NEW);
		}
		final Password cpwdold = new Password(pwdold.toCharArray());
		final Password cpwdnew = new Password(pwdnew.toCharArray());
		pwdold = null;
		pwdnew = null;
		auth.localPasswordChange(new UserName(userName), cpwdold, cpwdnew);
		return Response.seeOther(toURI(UIPaths.LOCAL_ROOT_LOGIN))
				.cookie(removeLoginCookie(cfg.getTokenCookieName()))
				.build();
	}
}
