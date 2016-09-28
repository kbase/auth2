package us.kbase.auth2.service.api;

import static us.kbase.auth2.service.api.APIUtils.getLoginCookie;
import static us.kbase.auth2.service.api.APIUtils.relativize;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.glassfish.jersey.server.mvc.Template;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.Password;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.AuthenticationException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.NewToken;

@Path("/localaccount")
public class LocalAccounts {
	
	//TODO TEST
	//TODO JAVADOC

	//TODO PWD reset pwd

	@Inject
	private Authentication auth;
	
	@GET
	@Path("/login")
	@Template(name = "/locallogin")
	@Produces(MediaType.TEXT_HTML)
	public Map<String, String> login(@Context final UriInfo uriInfo) {
		return ImmutableMap.of("targeturl",
				relativize(uriInfo, "/localaccount/login/result"));
	}
	
	@POST
	@Path("/login/result")
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response loginResult(
			@FormParam("user") final String userName,
			@FormParam("pwd") String pwd, //char makes Jersey puke
			//checkbox, so "on" = checked, null = not checked
			@FormParam("stayLoggedIn") final String stayLoggedIn)
			throws AuthStorageException, MissingParameterException,
			AuthenticationException, IllegalParameterException,
			UnauthorizedException {
		if (userName == null || userName.isEmpty()) {
			throw new MissingParameterException("user");
		}
		if (pwd == null || pwd.isEmpty()) {
			throw new MissingParameterException("pwd");
		}
		final NewToken t = auth.localLogin(new UserName(userName),
				new Password(pwd.toCharArray()));
		//TODO LOG log
		pwd = null; // try to get pwd GC'd as quickly as possible
		//TODO PWD if reset required, do reset
		return Response.seeOther(toURI("/me"))
				.cookie(getLoginCookie(t, stayLoggedIn == null))
				.build();
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
