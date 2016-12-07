package us.kbase.auth2.service.api;

import java.util.HashMap;
import java.util.Map;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.HashedToken;
import us.kbase.auth2.lib.token.IncomingToken;

@Path(APIPaths.API_V2_TOKEN)
public class Token {

	//TODO TEST
	//TODO JAVADOC
	
	@Inject
	private Authentication auth;
	
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> getToken(@HeaderParam(APIConstants.HEADER_TOKEN) final String token)
			throws NoTokenProvidedException, InvalidTokenException, AuthStorageException {
		if (token == null || token.trim().isEmpty()) {
			throw new NoTokenProvidedException();
		}
		final HashedToken ht = auth.getToken(new IncomingToken(token));
		final Map<String, Object> ret = new HashMap<>();
		ret.put("cachefor", auth.getSuggestedTokenCacheTime());
		ret.put("user", ht.getUserName().getName());
		ret.put("type", ht.getTokenType().getID());
		ret.put("created", ht.getCreationDate().getTime());
		ret.put("expires", ht.getExpirationDate().getTime());
		ret.put("name", ht.getTokenName());
		ret.put("id", ht.getId().toString());
		return ret;
	}
			
}
