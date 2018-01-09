package us.kbase.auth2.service.api;

import java.util.HashMap;
import java.util.Map;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.TestModeException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.user.AuthUser;

@Path(APIPaths.LEGACY_KBASE)
public class LegacyKBase {
	

	//TODO JAVADOC or swagger
	
	private Authentication auth;
	
	@Inject
	public LegacyKBase(final Authentication auth) {
		this.auth = auth;
	}
	
	@GET
	@Produces(MediaType.TEXT_HTML)
	public Response dummyGetMethod() {
		return Response.status(401).entity("This GET method is just here for compatibility with " +
				"the old java client and does nothing useful. Here's the compatibility part: " +
				"\"user_id\": null").build();
	}
	
	interface TokenProvider {
		StoredToken getToken(final Authentication auth, final IncomingToken token)
				throws InvalidTokenException, AuthStorageException, TestModeException;
	}
	
	interface UserProvider {
		AuthUser getUser(Authentication auth, IncomingToken token)
				throws AuthStorageException, DisabledUserException, InvalidTokenException,
				TestModeException;
	}
	
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> kbaseLogin(
			@Context final HttpHeaders headers,
			final MultivaluedMap<String, String> form)
			throws AuthStorageException, MissingParameterException, InvalidTokenException,
				DisabledUserException, TestModeException {
		final MediaType mediaType = headers.getMediaType();
		return kbaseLogin(auth, (a, t) -> a.getToken(t), (a, t) -> a.getUser(t), form, mediaType);
	}

	static Map<String, Object> kbaseLogin(
			final Authentication auth,
			final TokenProvider tokenProvider,
			final UserProvider userProvider,
			final MultivaluedMap<String, String> form,
			final MediaType mediaType)
			throws MissingParameterException, InvalidTokenException, AuthStorageException,
				DisabledUserException, TestModeException {
		if (!MediaType.APPLICATION_FORM_URLENCODED_TYPE.equals(mediaType)) {
			// goofy, but matches the behavior of the previous service
			throw new MissingParameterException("token");
		}
		
		final IncomingToken in = new IncomingToken(form.getFirst("token"));
		String fields = form.getFirst("fields");
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
				ret.put("token", in.getToken());
			}
		}

		if (name || email) {
			final AuthUser u = userProvider.getUser(auth, in);
			if (name) {
				ret.put("name", u.getDisplayName().getName());
			}
			if (email) {
				ret.put("email", u.getEmail().getAddress());
			}
			ret.put("user_id", u.getUserName().getName());
		} else {
			final StoredToken ht = tokenProvider.getToken(auth, in);
			ret.put("user_id", ht.getUserName().getName());
		}
		return ret;
	}
}
