package us.kbase.auth2.service.ui;

import static us.kbase.auth2.service.ui.UIUtils.customRolesToList;
import static us.kbase.auth2.service.ui.UIUtils.getTokenFromCookie;

import java.util.Map;
import java.util.TreeSet;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;

import org.glassfish.jersey.server.mvc.Template;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.service.AuthAPIStaticConfig;
import us.kbase.auth2.service.common.Fields;

@Path(UIPaths.CUSTOM_ROLES_ROOT)
public class CustomRoles {

	//TODO JAVADOC or swagger
	
	/* May need to make a ViewRoles role in the future so that viewing roles can be restricted to
	 * a subset of users, but a larger subset than just Admins.
	 */
	
	@Inject
	private Authentication auth;
	
	@Inject
	private AuthAPIStaticConfig cfg;
	
	@GET
	@Template(name = "/customroles")
	public Map<String, Object> customRoles(
			@Context final HttpHeaders headers)
			throws AuthStorageException, NoTokenProvidedException, InvalidTokenException,
				UnauthorizedException { // can't actually be thrown
		final IncomingToken token = getTokenFromCookie(headers, cfg.getTokenCookieName());
		return ImmutableMap.of(Fields.CUSTOM_ROLES,
				customRolesToList(new TreeSet<>(auth.getCustomRoles(token, false))));
	}
	


}
