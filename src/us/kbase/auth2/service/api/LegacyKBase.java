package us.kbase.auth2.service.api;

import java.util.HashMap;
import java.util.Map;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.exceptions.AuthenticationException;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.user.AuthUser;

@Path(APIPaths.LEGACY_KBASE)
public class LegacyKBase {
	

	//TODO TEST
	//TODO JAVADOC
	
	@Inject
	private Authentication auth;
	
	@GET
	@Produces(MediaType.TEXT_HTML)
	public Response dummyGetMethod() throws AuthenticationException {
		return Response.status(401).entity("This GET method is just here for compatibility with " +
				"the old java client and does nothing useful. Here's the compatibility part: " +
				"\"user_id\": null").build();
	}
	
	// this just exists to capture requests when the content-type header isn't
	// set. It seems to be chosen first repeatably. The method below will throw
	// an ugly error about the @FormParam otherwise.
	@POST
	@Consumes(MediaType.TEXT_PLAIN)
	@Produces(MediaType.APPLICATION_JSON)
	public void dummyErrorMethod() throws MissingParameterException {
		throw new MissingParameterException("token");
	}

	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> kbaseLogin(
			@FormParam("token") final String token,
			@FormParam("fields") String fields)
			throws AuthStorageException,
			MissingParameterException, InvalidTokenException, DisabledUserException {
		if (token == null || token.trim().isEmpty()) {
			throw new MissingParameterException("token");
		}
		if (fields == null) {
			fields = "";
		}
		//this is totally stupid.
		final String[] f = fields.split(",");
		final Map<String, Object> ret = new HashMap<>();
		boolean name = false;
		boolean email = false;
		for (int i = 0; i < f.length; i++) {
			final String field = f[i].trim();
			if ("name".equals(field)) {
				name = true;
			} else if ("email".equals(field)) {
				email = true;
			} else if ("token".equals(field)) {
				ret.put("token", token);
			}
		}

		final IncomingToken in = new IncomingToken(token.trim());
		if (name || email) {
			final AuthUser u = auth.getUser(in);
			if (name) {
				ret.put("name", u.getDisplayName().getName());
			}
			if (email) {
				ret.put("email", u.getEmail().getAddress());
			}
			ret.put("user_id", u.getUserName().getName());
		} else {
			final StoredToken ht = auth.getToken(in);
			ret.put("user_id", ht.getUserName().getName());
		}
		return ret;
	}
}
