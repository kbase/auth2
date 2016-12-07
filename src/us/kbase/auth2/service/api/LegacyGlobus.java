package us.kbase.auth2.service.api;

import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.ViewableUser;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.AuthException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.HashedToken;
import us.kbase.auth2.lib.token.IncomingToken;

@Path(APIPaths.LEGACY_GLOBUS)
public class LegacyGlobus {

	//TODO TEST
	//TODO JAVADOC
	
	@Inject
	private Authentication auth;
	
	// note that access_token_hash is not returned in the structure
	// also note that unlike the globus api, this does not refresh the token
	// also note that the error structure is completely different. 
	@GET
	@Path(APIPaths.LEGACY_GLOBUS_TOKEN)
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> introspectToken(
			@HeaderParam("x-globus-goauthtoken") final String xtoken,
			@HeaderParam("globus-goauthtoken") String token,
			@QueryParam("grant_type") final String grantType)
			throws AuthStorageException, AuthException {

		if (!"client_credentials".equals(grantType)) {
			throw new AuthException(ErrorType.UNSUPPORTED_OP,
					"Only client_credentials grant_type supported. Got " +
					grantType);
		}
		token = getGlobusToken(xtoken, token);
		final HashedToken ht;
		try {
			ht = auth.getToken(new IncomingToken(token));
		} catch (InvalidTokenException e) {
			// globus throws a 403 instead of a 401
			throw new UnauthorizedException(
					e.getErr(), "Authentication failed.");
		}
		final long created = dateToSec(ht.getCreationDate());
		final long expires = dateToSec(ht.getExpirationDate());
		final Map<String, Object> ret = new HashMap<>();
		ret.put("access_token", token);
		ret.put("client_id", ht.getUserName().getName());
		ret.put("expires_in", expires - dateToSec(new Date()));
		ret.put("expiry", expires);
		ret.put("issued_on", created);
		ret.put("lifetime", expires - created);
		ret.put("refresh_token", "");
		ret.put("scopes", new LinkedList<String>());
		ret.put("token_id", ht.getId().toString());
		ret.put("token_type", "Bearer");
		ret.put("user_name", ht.getUserName().getName());
		return ret;
	}

	private String getGlobusToken(final String xtoken, String token)
			throws UnauthorizedException {
		if (token == null || token.trim().isEmpty()) {
			token = xtoken;
			if (token == null || token.trim().isEmpty()) {
				// globus throws a 403 instead of a 401
				throw new UnauthorizedException(ErrorType.NO_TOKEN);
			}
		}
		return token.trim();
	}
	
	
	private long dateToSec(final Date date) {
		return (long) Math.floor(date.getTime() / 1000.0);
	}
	
	// note does not return identity_id
	// note error structure is completely different
	@GET
	@Path(APIPaths.LEGACY_GLOBUS_USERS)
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> getUser(
			@HeaderParam("x-globus-goauthtoken") final String xtoken,
			@HeaderParam("authorization") String token,
			@PathParam("user") final String user)
			throws UnauthorizedException, AuthStorageException,
			NoSuchUserException, MissingParameterException,
			IllegalParameterException {
		if (token != null) {
			final String[] bits = token.trim().split("\\s+");
			if (bits.length != 2) {
				throw new UnauthorizedException(
						ErrorType.NO_TOKEN, "Invalid authorization header");
			}
			token = bits[1];
		}
		token = getGlobusToken(xtoken, token);
		final ViewableUser u;
		try {
			u = auth.getUser(new IncomingToken(token), new UserName(user));
		} catch (InvalidTokenException e) {
			// globus throws a 403 instead of a 401
			throw new UnauthorizedException(
					e.getErr(), "Authentication failed.");
		}
		final String email = u.getEmail() == null ? null : u.getEmail().getAddress(); 
		final Map<String, Object> ret = new HashMap<>();
		ret.put("username", u.getUserName().getName());
		ret.put("email_validated", false);
		ret.put("ssh_pubkeys", new LinkedList<String>());
		ret.put("resource_type", "users");
		ret.put("full_name", u.getDisplayName().getName());
		ret.put("organization", null);
		ret.put("fullname", u.getDisplayName().getName());
		ret.put("user_name", u.getUserName().getName());
		ret.put("email", email);
		ret.put("custom_fields", new HashMap<String,String>());
		return ret;
	}
}
