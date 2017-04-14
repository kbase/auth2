package us.kbase.auth2.service.ui;

import static us.kbase.auth2.service.common.ServiceCommon.getToken;
import static us.kbase.auth2.service.ui.UIConstants.PROVIDER_RETURN_EXPIRATION_SEC;
import static us.kbase.auth2.service.ui.UIUtils.checkState;
import static us.kbase.auth2.service.ui.UIUtils.getMaxCookieAge;
import static us.kbase.auth2.service.ui.UIUtils.getTokenFromCookie;
import static us.kbase.auth2.service.ui.UIUtils.relativize;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.NoSuchProviderException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.CookieParam;
import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.glassfish.jersey.server.mvc.Template;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Optional;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.LinkIdentities;
import us.kbase.auth2.lib.LinkToken;
import us.kbase.auth2.lib.config.ConfigAction.State;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.exceptions.AuthenticationException;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.IdentityLinkedException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.LinkFailedException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.service.AuthAPIStaticConfig;
import us.kbase.auth2.service.AuthExternalConfig.AuthExternalConfigMapper;
import us.kbase.auth2.service.common.Fields;
import us.kbase.auth2.service.common.IncomingJSON;

@Path(UIPaths.LINK_ROOT)
public class Link {

	//TODO JAVADOC
	//TODO TEST
	//TODO CODE can probably share some code with /login
	
	private static final String LINK_STATE_COOKIE = "linkstatevar";
	private static final String IN_PROCESS_LINK_COOKIE = "in-process-link-token";

	@Inject
	private Authentication auth;
	
	@Inject
	private AuthAPIStaticConfig cfg;
	
	@GET
	@Template(name = "/linkstart")
	public Map<String, Object> linkStartDisplay(
			@Context final HttpHeaders headers,
			@Context final UriInfo uriInfo)
			throws NoSuchIdentityProviderException, NoTokenProvidedException,
			InvalidTokenException, AuthStorageException, DisabledUserException {

		final IncomingToken incToken = getTokenFromCookie(headers, cfg.getTokenCookieName());
		final AuthUser u = auth.getUser(incToken);
		final Map<String, Object> ret = new HashMap<>();
		ret.put(Fields.USER, u.getUserName().getName());
		ret.put("local", u.isLocal());
		final List<Map<String, String>> provs = new LinkedList<>();
		ret.put(Fields.PROVIDERS, provs);
		for (final String prov: auth.getIdentityProviders()) {
			final Map<String, String> rep = new HashMap<>();
			rep.put(Fields.PROVIDER, prov);
			provs.add(rep);
		}
		ret.put("starturl", relativize(uriInfo, UIPaths.LINK_ROOT_START));
		ret.put(Fields.HAS_PROVIDERS, !provs.isEmpty());
		return ret;
	}
	
	/* this method intentionally does not check the user identity because UIs must use a browser
	 * form submit rather than AJAX for the redirect to work correctly. Since it's a form submit
	 * the UI cannot trap any errors, and an invalid token error would default to the built in
	 * HTML UI. Hence, this method should only throw errors when the request absolutely cannot
	 * continue.
	 */
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Path(UIPaths.LINK_START)
	public Response linkStart(
			@FormParam(Fields.PROVIDER) final String provider)
			throws NoSuchIdentityProviderException, AuthStorageException {
		
		final String state = auth.getBareToken();
		final URI target = toURI(auth.getIdentityProviderURL(provider, state, true));
		return Response.seeOther(target).cookie(getStateCookie(state)).build();
	}

	private NewCookie getStateCookie(final String state) {
		return new NewCookie(new Cookie(LINK_STATE_COOKIE,
				state == null ? "no state" : state, UIPaths.LINK_ROOT_COMPLETE, null),
				"linkstate",
				state == null ? 0 : PROVIDER_RETURN_EXPIRATION_SEC,
				UIConstants.SECURE_COOKIES);
	}
	
	@GET
	@Path(UIPaths.LINK_COMPLETE_PROVIDER)
	public Response link(
			@Context final HttpHeaders headers,
			@PathParam(Fields.PROVIDER) final String provider,
			@CookieParam(LINK_STATE_COOKIE) final String state,
			@Context final UriInfo uriInfo)
			throws MissingParameterException, AuthenticationException,
			NoSuchProviderException, AuthStorageException,
			NoTokenProvidedException, LinkFailedException, UnauthorizedException {
		//TODO INPUT handle error in params (provider, state)
		final MultivaluedMap<String, String> qps = uriInfo.getQueryParameters();
		//TODO ERRHANDLE handle returned OAuth error code in queryparams
		final String authcode = qps.getFirst("code"); //may need to be configurable
		final String retstate = qps.getFirst("state"); //may need to be configurable
		checkState(state, retstate);
		final Optional<IncomingToken> token =
				getTokenFromCookie(headers, cfg.getTokenCookieName(), false);
		final Optional<TemporaryToken> tt;
		if (token.isPresent()) {
			final LinkToken lt = auth.link(token.get(), provider, authcode);
			if (lt.isLinked()) {
				tt = Optional.absent();
			} else {
				tt = Optional.of(lt.getTemporaryToken().get());
			}
		} else {
			tt = Optional.of(auth.link(provider, authcode));
		}
		final Response r;
		// always redirect so the authcode doesn't remain in the title bar
		// note nginx will rewrite the redirect appropriately so absolute
		// redirects are ok
		if (tt.isPresent()) {
			r = Response.seeOther(getCompleteLinkRedirectURI(UIPaths.LINK_ROOT_CHOICE)).cookie(
					getLinkInProcessCookie(tt.get()))
					.cookie(getStateCookie(null))
					.build();
		} else {
			r = Response.seeOther(getPostLinkRedirectURI(UIPaths.ME_ROOT))
					.cookie(getStateCookie(null)).build();
		}
		return r;
	}
	
	// the two methods below are very similar and there's another similar method in Login
	private URI getCompleteLinkRedirectURI(final String deflt) throws AuthStorageException {
		final ConfigItem<URL, State> url;
		try {
			url = auth.getExternalConfig(new AuthExternalConfigMapper())
					.getCompleteLinkRedirect();
		} catch (ExternalConfigMappingException e) {
			throw new RuntimeException("Dude, like, what just happened?", e);
		}
		if (!url.hasItem()) {
			return toURI(deflt);
		}
		try {
			return url.getItem().toURI();
		} catch (URISyntaxException e) {
			throw new RuntimeException("this should be impossible" , e);
		}
	}
	
	private URI getPostLinkRedirectURI(final String deflt) throws AuthStorageException {
		final ConfigItem<URL, State> url;
		try {
			url = auth.getExternalConfig(new AuthExternalConfigMapper())
					.getPostLinkRedirect();
		} catch (ExternalConfigMappingException e) {
			throw new RuntimeException("Dude, like, what just happened?", e);
		}
		if (!url.hasItem()) {
			return toURI(deflt);
		}
		try {
			return url.getItem().toURI();
		} catch (URISyntaxException e) {
			throw new RuntimeException("this should be impossible" , e);
		}
	}
	
	private NewCookie getLinkInProcessCookie(final TemporaryToken token) {
		return new NewCookie(new Cookie(IN_PROCESS_LINK_COOKIE,
				token == null ? "no token" : token.getToken(), UIPaths.LINK_ROOT, null),
				"linktoken", token == null ? 0 : getMaxCookieAge(token),
				UIConstants.SECURE_COOKIES);
	}
	
	@GET
	@Path(UIPaths.LINK_CHOICE)
	@Template(name = "/linkchoice")
	@Produces(MediaType.TEXT_HTML)
	public Map<String, Object> linkChoice(
			@Context final HttpHeaders headers,
			@CookieParam(IN_PROCESS_LINK_COOKIE) final String linktoken,
			@Context final UriInfo uriInfo)
			throws NoTokenProvidedException, AuthStorageException,
			InvalidTokenException, LinkFailedException, UnauthorizedException {
		return linkChoice(getTokenFromCookie(headers, cfg.getTokenCookieName()),
				linktoken, uriInfo);
	}
	
	@GET
	@Path(UIPaths.LINK_CHOICE)
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> linkChoice(
			@HeaderParam(UIConstants.HEADER_TOKEN) final String token,
			@CookieParam(IN_PROCESS_LINK_COOKIE) final String linktoken,
			@Context final UriInfo uriInfo)
			throws NoTokenProvidedException, AuthStorageException,
			InvalidTokenException, LinkFailedException, UnauthorizedException {
		return linkChoice(getToken(token), linktoken, uriInfo);
	}

	private Map<String, Object> linkChoice(
			final IncomingToken incomingToken,
			final String linktoken,
			final UriInfo uriInfo)
			throws NoTokenProvidedException, InvalidTokenException, AuthStorageException,
			LinkFailedException, UnauthorizedException {
		final LinkIdentities ids = auth.getLinkState(incomingToken,
				getLinkInProcessToken(linktoken));
		/* there's a possibility here that between the redirects the number
		 * of identities that aren't already linked was reduced to 1. The
		 * probability is so low that it's not worth special casing it,
		 * especially since the effect is simply that the user only has one
		 * choice for link targets.
		 */ 
		final Map<String, Object> ret = new HashMap<>();
		ret.put(Fields.USER, ids.getUser().getUserName().getName());
		ret.put(Fields.PROVIDER, ids.getProvider());
		final List<Map<String, String>> ris = new LinkedList<>();
		ret.put(Fields.IDENTITIES, ris);
		for (final RemoteIdentity ri: ids.getIdentities()) {
			final Map<String, String> s = new HashMap<>();
			s.put(Fields.ID, ri.getRemoteID().getID());
			s.put(Fields.PROV_USER, ri.getDetails().getUsername());
			ris.add(s);
		}
		ret.put("cancelurl", relativize(uriInfo, UIPaths.LINK_ROOT_CANCEL));
		ret.put("pickurl", relativize(uriInfo, UIPaths.LINK_ROOT_PICK));
		ret.put("expires", ids.getExpires().toEpochMilli());
		return ret;
	}

	private IncomingToken getLinkInProcessToken(final String linktoken)
			throws NoTokenProvidedException {
		final IncomingToken incToken;
		try {
			incToken = new IncomingToken(linktoken);
		} catch (MissingParameterException e) {
			throw new NoTokenProvidedException("Missing " + IN_PROCESS_LINK_COOKIE); 
		}
		return incToken;
	}
	
	@POST
	@Path(UIPaths.LINK_CANCEL)
	public Response cancelLinkPOST(@CookieParam(IN_PROCESS_LINK_COOKIE) final String token)
			throws NoTokenProvidedException, AuthStorageException {
		return cancelLink(token);
	}
	
	@DELETE
	@Path(UIPaths.LINK_CANCEL)
	public Response cancelLinkDELETE(@CookieParam(IN_PROCESS_LINK_COOKIE) final String token)
			throws NoTokenProvidedException, AuthStorageException {
		return cancelLink(token);
	}

	private Response cancelLink(final String token)
			throws NoTokenProvidedException, AuthStorageException {
		auth.deleteLinkOrLoginState(getLinkInProcessToken(token));
		return Response.noContent().cookie(getLinkInProcessCookie(null)).build();
	}
	
	// for dumb HTML pages that use forms
	// if identityID is not provided, links all
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Path(UIPaths.LINK_PICK)
	public Response pickAccount(
			@Context final HttpHeaders headers,
			@CookieParam(IN_PROCESS_LINK_COOKIE) final String linktoken,
			@FormParam(Fields.ID) String identityID)
			throws NoTokenProvidedException, AuthStorageException, LinkFailedException,
				IdentityLinkedException, UnauthorizedException, InvalidTokenException,
				MissingParameterException {
		if (identityID == null || identityID.trim().isEmpty()) {
			identityID = null;
		}
		final IncomingToken token = getTokenFromCookie(headers, cfg.getTokenCookieName());
		pickAccount(token, linktoken, Optional.fromNullable(identityID));
		return Response.seeOther(getPostLinkRedirectURI(UIPaths.ME_ROOT))
				.cookie(getLinkInProcessCookie(null)).build();
	}
	
	private static class LinkPick extends IncomingJSON {
		
		private final String id;
		
		// don't throw exception in constructor. Bypasses custom error handler.
		@JsonCreator
		public LinkPick(@JsonProperty(Fields.ID) final String id) {
			this.id = id;
		}
		
		public Optional<String> getID() {
			return getOptionalString(id);
		}
	}
	
	// for AJAX pages that can decide for themselves where to go next
	// if identityID is not provided, links all
	@POST // non-idempotent, so has to be post
	@Consumes(MediaType.APPLICATION_JSON)
	@Path(UIPaths.LINK_PICK)
	public Response pickAccount(
			@HeaderParam(UIConstants.HEADER_TOKEN) final String token,
			@CookieParam(IN_PROCESS_LINK_COOKIE) final String linktoken,
			final LinkPick linkpick)
			throws NoTokenProvidedException, AuthStorageException,
				LinkFailedException, IllegalParameterException, MissingParameterException,
				IdentityLinkedException, UnauthorizedException, InvalidTokenException {
		if (linkpick == null) {
			throw new MissingParameterException("JSON body missing");
		}
		linkpick.exceptOnAdditionalProperties();
		pickAccount(getToken(token), linktoken, linkpick.getID());
		return Response.noContent().cookie(getLinkInProcessCookie(null)).build();
	}

	private void pickAccount(
			final IncomingToken token,
			final String linktoken,
			final Optional<String> id)
			throws NoTokenProvidedException, AuthStorageException, LinkFailedException,
				IdentityLinkedException, UnauthorizedException, InvalidTokenException,
				MissingParameterException {
		final IncomingToken linkInProcessToken = getLinkInProcessToken(linktoken);
		if (id.isPresent()) {
			auth.link(token, linkInProcessToken, id.get());
		} else {
			auth.linkAll(token, linkInProcessToken);
		}
	}
	
	//Assumes valid URI in URL form
	private URI toURI(final URL loginURL) {
		try {
			return loginURL.toURI();
		} catch (URISyntaxException e) {
			throw new RuntimeException("This should be impossible", e);
		}
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
