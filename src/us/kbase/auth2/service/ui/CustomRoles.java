package us.kbase.auth2.service.ui;

import java.util.Map;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;

import org.glassfish.jersey.server.mvc.Template;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;

@Path(UIPaths.CUSTOM_ROLES_ROOT)
public class CustomRoles {

	//TODO TEST
	//TODO JAVADOC
	
	/* May need to make a ViewRoles role in the future so that viewing roles can be restricted to
	 * a subset of users, but a larger subset than just Admins.
	 */
	
	@Inject
	private Authentication auth;
	
	@GET
	@Template(name = "/customroles")
	public Map<String, Object> customRoles() throws AuthStorageException {
		return ImmutableMap.of("roles", auth.getCustomRoles());
	}

}
