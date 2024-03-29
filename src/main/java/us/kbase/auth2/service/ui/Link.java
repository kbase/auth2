package us.kbase.auth2.service.ui;

import static us.kbase.auth2.service.common.ServiceCommon.getToken;
import static us.kbase.auth2.service.common.ServiceCommon.nullOrEmpty;
import static us.kbase.auth2.service.ui.UIConstants.PROVIDER_RETURN_EXPIRATION_SEC;
import static us.kbase.auth2.service.ui.UIConstants.IN_PROCESS_LINK_COOKIE;
import static us.kbase.auth2.service.ui.UIUtils.ENVIRONMENT_COOKIE;
import static us.kbase.auth2.service.ui.UIUtils.getEnvironmentCookie;
import static us.kbase.auth2.service.ui.UIUtils.getExternalConfigURI;
import static us.kbase.auth2.service.ui.UIUtils.getLinkInProcessCookie;
import static us.kbase.auth2.service.ui.UIUtils.getMaxCookieAge;
import static us.kbase.auth2.service.ui.UIUtils.getTokenFromCookie;
import static us.kbase.auth2.service.ui.UIUtils.getValueFromHeaderOrString;
import static us.kbase.auth2.service.ui.UIUtils.relativize;

import java.net.URI;
import java.security.NoSuchProviderException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

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
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.glassfish.jersey.server.mvc.Template;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.LinkIdentities;
import us.kbase.auth2.lib.LinkToken;
import us.kbase.auth2.lib.OAuth2StartData;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.Utils;
import us.kbase.auth2.lib.exceptions.AuthenticationException;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.IdentityLinkedException;
import us.kbase.auth2.lib.exceptions.IdentityProviderErrorException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.LinkFailedException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchEnvironmentException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.service.AuthAPIStaticConfig;
import us.kbase.auth2.service.common.Fields;
import us.kbase.auth2.service.common.IncomingJSON;

@Path(UIPaths.LINK_ROOT)
public class Link {

	//TODO JAVADOC or swagger
	
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
		ret.put(Fields.LOCAL, u.isLocal());
		final List<Map<String, String>> provs = new LinkedList<>();
		ret.put(Fields.PROVIDERS, provs);
		for (final String prov: auth.getIdentityProviders()) {
			final Map<String, String> rep = new HashMap<>();
			rep.put(Fields.PROVIDER, prov);
			provs.add(rep);
		}
		ret.put(Fields.URL_START, relativize(uriInfo, UIPaths.LINK_ROOT_START));
		ret.put(Fields.HAS_PROVIDERS, !provs.isEmpty());
		return ret;
	}
	
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Path(UIPaths.LINK_START)
	public Response linkStart(
			@Context final HttpHeaders headers,
			@FormParam(Fields.PROVIDER) final String provider,
			@FormParam(Fields.TOKEN) final String formToken,
			@FormParam(Fields.ENVIRONMENT) final String environForm)
			throws NoSuchIdentityProviderException, AuthStorageException,
				MissingParameterException, NoTokenProvidedException, InvalidTokenException,
				UnauthorizedException, LinkFailedException, NoSuchEnvironmentException {
		
		final Optional<String> environment = getValueFromHeaderOrString(
				headers, cfg.getEnvironmentHeaderName(), environForm);
		Utils.checkString(provider, Fields.PROVIDER);
		
		final IncomingToken token;
		if (!nullOrEmpty(formToken)) {
			token = getToken(formToken);
		} else {
			token = getTokenFromCookie(headers, cfg.getTokenCookieName());
		}
		final OAuth2StartData oa2sd = auth.linkStart(
				token, PROVIDER_RETURN_EXPIRATION_SEC, provider, environment.orElse(null));
		return Response.seeOther(oa2sd.getRedirectURI())
				.cookie(getEnvironmentCookie(environment.orElse(null), UIPaths.LINK_ROOT,
						PROVIDER_RETURN_EXPIRATION_SEC))
				/* the link in process token must be a session token so that if a user closes the
				 * browser and thus logs themselves out, the link session token disappears.
				 * Otherwise another user could access the link in process token that identifies
				 * them as the first user and proceed with the linking process, thus linking their
				 * remote account to the first user's account.
				 */
				.cookie(getLinkInProcessCookie(oa2sd.getTemporaryToken()))
				.build();
	}

	/* We don't necessarily have access to the user's token here since it's a redirect from the
	 * 3rd party identity provider. If the UI is setting its own cookies for tokens (which is
	 * what the current KBase UI does) then the server won't know about it.
	 * Hence we trust the link in process cookie that we set at link start and which is
	 * associated with the user name, which was extracted from their token at link start.
	 * 
	 * IOW, the link in process cookie is a proxy for the user's token.
	 */
	@GET
	@Path(UIPaths.LINK_COMPLETE_PROVIDER)
	public Response link(
			@PathParam(Fields.PROVIDER) final String provider,
			@CookieParam(IN_PROCESS_LINK_COOKIE) final String userCookie,
			@CookieParam(ENVIRONMENT_COOKIE) final String environment,
			@Context final UriInfo uriInfo)
			throws MissingParameterException, AuthenticationException, NoSuchProviderException,
				AuthStorageException, LinkFailedException, UnauthorizedException,
				NoTokenProvidedException, NoSuchEnvironmentException {
		
		//provider cannot be null or empty here since it's a path param
		final MultivaluedMap<String, String> qps = uriInfo.getQueryParameters();
		final String authcode = qps.getFirst(Fields.PROVIDER_CODE); //may need to be configurable
		final String retstate = qps.getFirst(Fields.PROVIDER_STATE); //may need to be configurable
		final String error = qps.getFirst(Fields.ERROR); //may need to be configurable
		final Optional<TemporaryToken> tt;
		if (!nullOrEmpty(error)) {
			tt = Optional.of(auth.linkProviderError(error));
		} else {
			final IncomingToken token = getLinkInProcessToken(userCookie);
			final LinkToken lt = auth.link(token, provider, authcode, environment, retstate);
			if (lt.isLinked()) {
				tt = Optional.empty();
			} else {
				tt = Optional.of(lt.getTemporaryToken().get());
			}
		}
		final Response r;
		// always redirect so the authcode doesn't remain in the title bar
		// note nginx will rewrite the redirect appropriately so absolute
		// redirects are ok
		if (tt.isPresent()) {
			final URI completeURI = getExternalConfigURI(
					auth,
					cfg -> cfg.getURLSetOrDefault(environment).getCompleteLinkRedirect(),
					UIPaths.LINK_ROOT_CHOICE);
			final int age = getMaxCookieAge(tt.get());
			r = Response.seeOther(completeURI)
					.cookie(getLinkInProcessCookie(tt.get()))
					.cookie(getEnvironmentCookie(environment, UIPaths.LINK_ROOT, age))
					.build();
		} else {
			final URI postLinkURI = getExternalConfigURI(
					auth,
					cfg-> cfg.getURLSetOrDefault(environment).getPostLinkRedirect(),
					UIPaths.ME_ROOT);
			r = Response.seeOther(postLinkURI)
					.cookie(getLinkInProcessCookie(null))
					.cookie(getEnvironmentCookie(null, UIPaths.LINK_ROOT, 0))
					.build();
		}
		return r;
	}
	
	@GET
	@Path(UIPaths.LINK_CHOICE)
	@Template(name = "/linkchoice")
	@Produces(MediaType.TEXT_HTML)
	public Map<String, Object> linkChoice(
			@Context final HttpHeaders headers,
			@CookieParam(IN_PROCESS_LINK_COOKIE) final String linktoken,
			@Context final UriInfo uriInfo)
			throws NoTokenProvidedException, AuthStorageException, InvalidTokenException,
				LinkFailedException, UnauthorizedException, IdentityProviderErrorException {
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
			throws NoTokenProvidedException, AuthStorageException, InvalidTokenException,
				LinkFailedException, UnauthorizedException, IdentityProviderErrorException {
		return linkChoice(getToken(token), linktoken, uriInfo);
	}

	private Map<String, Object> linkChoice(
			final IncomingToken incomingToken,
			final String linktoken,
			final UriInfo uriInfo)
			throws NoTokenProvidedException, InvalidTokenException, AuthStorageException,
			LinkFailedException, UnauthorizedException, IdentityProviderErrorException {
		final LinkIdentities ids = auth.getLinkState(incomingToken,
				getLinkInProcessToken(linktoken));
		/* there's a possibility here that between the redirects the number
		 * of identities that aren't already linked was reduced to 1. The
		 * probability is so low that it's not worth special casing it,
		 * especially since the effect is simply that the user only has one
		 * choice for link targets.
		 */ 
		final Map<String, Object> ret = new HashMap<>();
		ret.put(Fields.USER, ids.getUser().getName());
		ret.put(Fields.PROVIDER, ids.getProvider());
		ret.put(Fields.HAS_LINKS, !ids.getIdentities().isEmpty());
		final List<Map<String, String>> ris = new LinkedList<>();
		ret.put(Fields.IDENTITIES, ris);
		for (final RemoteIdentity ri: ids.getIdentities()) {
			final Map<String, String> s = new HashMap<>();
			s.put(Fields.ID, ri.getRemoteID().getID());
			s.put(Fields.PROV_USER, ri.getDetails().getUsername());
			ris.add(s);
		}
		final List<Map<String, String>> linked = new LinkedList<>();
		ret.put(Fields.LINKED, linked);
		for (final UserName u: ids.getLinkedUsers()) {
			for (final RemoteIdentity ri: ids.getLinkedIdentities(u)) {
				linked.add(ImmutableMap.of(
						Fields.USER, u.getName(),
						Fields.ID, ri.getRemoteID().getID(),
						Fields.PROV_USER, ri.getDetails().getUsername()));
			}
		}
		ret.put(Fields.URL_CANCEL, relativize(uriInfo, UIPaths.LINK_ROOT_CANCEL));
		ret.put(Fields.URL_PICK, relativize(uriInfo, UIPaths.LINK_ROOT_PICK));
		ret.put(Fields.CHOICE_EXPIRES, ids.getExpires().toEpochMilli());
		return ret;
	}

	private IncomingToken getLinkInProcessToken(final String linktoken)
			throws NoTokenProvidedException {
		try {
			return new IncomingToken(linktoken);
		} catch (MissingParameterException e) {
			throw new NoTokenProvidedException("Missing " + IN_PROCESS_LINK_COOKIE); 
		}
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
		return Response.noContent()
				.cookie(getLinkInProcessCookie(null))
				.cookie(getEnvironmentCookie(null, UIPaths.LINK_ROOT, 0))
				.build();
	}
	
	// for dumb HTML pages that use forms
	// if identityID is not provided, links all
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Path(UIPaths.LINK_PICK)
	public Response pickAccount(
			@Context final HttpHeaders headers,
			@CookieParam(IN_PROCESS_LINK_COOKIE) final String linktoken,
			@CookieParam(ENVIRONMENT_COOKIE) final String environment,
			@FormParam(Fields.ID) String identityID)
			throws NoTokenProvidedException, AuthStorageException, LinkFailedException,
				IdentityLinkedException, UnauthorizedException, InvalidTokenException,
				MissingParameterException, IdentityProviderErrorException,
				NoSuchEnvironmentException {
		if (nullOrEmpty(identityID)) {
			identityID = null;
		}
		final IncomingToken token = getTokenFromCookie(headers, cfg.getTokenCookieName());
		pickAccount(token, linktoken, Optional.ofNullable(identityID));
		final URI postLinkURI = getExternalConfigURI(
				auth,
				cfg-> cfg.getURLSetOrDefault(environment).getPostLinkRedirect(),
				UIPaths.ME_ROOT);
		return Response.seeOther(postLinkURI)
				.cookie(getLinkInProcessCookie(null))
				.cookie(getEnvironmentCookie(null, UIPaths.LINK_ROOT, 0))
				.build();
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
				IdentityLinkedException, UnauthorizedException, InvalidTokenException,
				IdentityProviderErrorException {
		if (linkpick == null) {
			throw new MissingParameterException("JSON body missing");
		}
		linkpick.exceptOnAdditionalProperties();
		pickAccount(getToken(token), linktoken, linkpick.getID());
		return Response.noContent()
				.cookie(getLinkInProcessCookie(null))
				.cookie(getEnvironmentCookie(null, UIPaths.LINK_ROOT, 0))
				.build();
	}

	private void pickAccount(
			final IncomingToken token,
			final String linktoken,
			final Optional<String> id)
			throws NoTokenProvidedException, AuthStorageException, LinkFailedException,
				IdentityLinkedException, UnauthorizedException, InvalidTokenException,
				MissingParameterException, IdentityProviderErrorException {
		final IncomingToken linkInProcessToken = getLinkInProcessToken(linktoken);
		if (id.isPresent()) {
			auth.link(token, linkInProcessToken, id.get());
		} else {
			auth.linkAll(token, linkInProcessToken);
		}
	}
}
