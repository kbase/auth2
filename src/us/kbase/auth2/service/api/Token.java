package us.kbase.auth2.service.api;

import static us.kbase.auth2.service.common.ServiceCommon.getToken;

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

@Path(APIPaths.API_V2_TOKEN)
public class Token {

	//TODO TEST
	//TODO JAVADOC
	
	@Inject
	private Authentication auth;
	
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> viewToken(
			@HeaderParam(APIConstants.HEADER_TOKEN) final String token)
			throws NoTokenProvidedException, InvalidTokenException, AuthStorageException {
		final HashedToken ht = auth.getToken(getToken(token));
		final Map<String, Object> ret = new HashMap<>();
		ret.put("cachefor", auth.getSuggestedTokenCacheTime());
		ret.put("user", ht.getUserName().getName());
		ret.put("type", ht.getTokenType().getID());
		ret.put("created", ht.getCreationDate().toEpochMilli());
		ret.put("expires", ht.getExpirationDate().toEpochMilli());
		ret.put("name", ht.getTokenName().isPresent() ? ht.getTokenName().get().getName() : null);
		ret.put("id", ht.getId().toString());
		return ret;
	}
}
