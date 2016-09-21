package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.checkString;
import static us.kbase.auth2.lib.Utils.clear;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import us.kbase.auth2.cryptutils.PasswordCrypt;
import us.kbase.auth2.cryptutils.TokenGenerator;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;
import us.kbase.auth2.lib.exceptions.AuthenticationException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.LinkFailedException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UnLinkFailedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.IdentityProviderFactory;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityWithID;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.lib.token.TokenSet;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.token.HashedToken;
import us.kbase.auth2.lib.token.IncomingToken;

public class Authentication {

	//TODO TEST unit tests
	//TODO TEST test logging on startup
	//TODO TEST test logging on calls
	//TODO JAVADOC 
	//TODO AUTH schema version
	//TODO AUTH handle root user somehow (spec chars unallowed in usernames?)
	//TODO AUTH server root should return server version (and urls for endpoints?)
	//TODO AUTH check workspace for other useful things like the schema manager
	//TODO LOG logging everywhere - on login, on logout, on create / delete / expire token
	//TODO SCOPES configure scopes via ui
	//TODO SCOPES configure scope on login via ui
	//TODO SCOPES restricted scopes - allow for specific roles or users (or for specific clients via oauth2)
	//TODO ADMIN revoke user token, revoke all tokens for a user, revoke all tokens
	//TODO ADMIN deactivate account
	//TODO ADMIN force user pwd reset
	//TODO TOKEN tokens - redirect to standard login if not logged in (other pages as well)
	//TODO USERPROFILE email & username change propagation
	//TODO USERCONFIG set email & username privacy & respect (in both legacy apis)
	//TODO USERCONFIG set email & username
	//TODO DEPLOY jetty should start app immediately & fail if app fails
	//TODO CONFIG set token cache time to be sent to client via api
	//TODO UI set keep me logged in on login page
	//TODO PWD last pwd reset field for local users
	//TODO CONFIG service 1st start should start with id providers disabled (thus no logins possible except for root)
	
	/* TODO ROLES feature: delete custom roles (see below)
	 * Delete role from all users
	 * Delete role from system:
	 * 1) Remove role from all users
	 * 2) delete role from system
	 * 3) Remove role from all users again
	 * 4) On getting a user, any roles that aren't in the system should be
	 * removed
	 * 
	 * Still a possibility of a race condition allowing adding a deleted role to
	 * a user after step 3, and then the role being re-added with different
	 * semantics, which would mean that users that erroneously have the role
	 * would be granted the new semantics, which is wrong
	 * Might not be worth worrying about
	 */
	
	private final AuthStorage storage;
	private final IdentityProviderFactory idFactory;
	private final TokenGenerator tokens;
	private final PasswordCrypt pwdcrypt;
	
	public Authentication(
			final AuthStorage storage,
			final IdentityProviderFactory identityProviderFactory) {
		System.out.println("starting application");
		try {
			tokens = new TokenGenerator();
			pwdcrypt = new PasswordCrypt();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("This should be impossible", e);
		}
		if (storage == null) {
			throw new NullPointerException("storage");
		}
		if (identityProviderFactory == null) {
			throw new NullPointerException("identityProviderFactory");
		}
		this.storage = storage;
		this.idFactory = identityProviderFactory;
	}

	// don't expose this method to general users, blatantly obviously
	public void createRoot(final Password pwd) throws AuthStorageException {
		if (pwd == null) {
			throw new NullPointerException("pwd");
		}
		final byte[] salt = pwdcrypt.generateSalt();
		final byte[] passwordHash = pwdcrypt.getEncryptedPassword(
				pwd.getPassword(), salt);
		pwd.clear();
		storage.createRoot(UserName.ROOT, "root", "root@unknown.unknown",
				new HashSet<>(Arrays.asList(Role.ROOT)),
				new Date(), passwordHash, salt);
		clear(passwordHash);
		clear(salt);
	}
	
	public Password createLocalUser(
			final IncomingToken adminToken,
			final UserName userName,
			final String fullName,
			final String email)
			throws AuthStorageException, UserExistsException,
			MissingParameterException, UnauthorizedException,
			InvalidTokenException {
		getUser(adminToken, Role.ROOT, Role.CREATE_ADMIN, Role.ADMIN);
		if (userName == null) {
			throw new NullPointerException("userName");
		}
		if (userName.isRoot()) {
			throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
					"Cannot create ROOT user");
		}
		checkString(fullName, "full name");
		checkString(email, "email");
		final Password pwd = new Password(tokens.getTemporaryPassword(10));
		final byte[] salt = pwdcrypt.generateSalt();
		final byte[] passwordHash = pwdcrypt.getEncryptedPassword(
				pwd.getPassword(), salt);
		final LocalUser lu = new LocalUser(userName, email, fullName, null,
				null, new Date(), null, passwordHash, salt, true);
		storage.createLocalUser(lu);
		clear(passwordHash);
		clear(salt);
		return pwd;
	}
	
	public NewToken localLogin(final UserName userName, final Password pwd)
			throws AuthenticationException, AuthStorageException {
		final LocalUser u;
		try {
			u = storage.getLocalUser(userName);
		} catch (NoSuchUserException e) {
			throw new AuthenticationException(ErrorType.AUTHENTICATION_FAILED,
					"Username / password mismatch");
		}
		if (!pwdcrypt.authenticate(pwd.getPassword(), u.getPasswordHash(),
				u.getSalt())) {
			throw new AuthenticationException(ErrorType.AUTHENTICATION_FAILED,
					"Username / password mismatch");
		}
		pwd.clear();
		//TODO PWD if reset required, make reset token
		final NewToken t = new NewToken(TokenType.LOGIN, tokens.getToken(),
				userName,
				//TODO CONFIG make token lifetime configurable
				14 * 24 * 60 * 60 * 1000);
		storage.storeToken(t.getHashedToken());
		setLastLogin(userName);
		return t;
	}

	// used when it's known that the user exists
	private void setLastLogin(final UserName userName)
			throws AuthStorageException {
		try {
			storage.setLastLogin(userName, new Date());
		} catch (NoSuchUserException e) {
			throw new AuthStorageException(
					"Something is very broken. User should exist but doesn't: "
							+ e.getMessage(), e);
		}
	}

	public TokenSet getTokens(final IncomingToken token)
			throws AuthStorageException, InvalidTokenException {
		final HashedToken ht = getToken(token);
		return new TokenSet(ht, storage.getTokens(ht.getUserName()));
	}

	// converts a no such token exception into an invalid token exception.
	public HashedToken getToken(final IncomingToken token)
			throws AuthStorageException, InvalidTokenException {
		if (token == null) {
			throw new NullPointerException("token");
		}
		try {
			return storage.getToken(token.getHashedToken());
		} catch (NoSuchTokenException e) {
			throw new InvalidTokenException();
		}
	}

	public NewToken createToken(
			final IncomingToken token,
			final String tokenName,
			final boolean serverToken)
			throws AuthStorageException, MissingParameterException,
			InvalidTokenException, UnauthorizedException {
		checkString(tokenName, "token name");
		final HashedToken t = getToken(token);
		if (!t.getTokenType().equals(TokenType.LOGIN)) {
			throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
					"Only login tokens may be used to create a token");
		}
		final AuthUser au = getUser(t);
		final Role reqRole = serverToken ? Role.SERV_TOKEN : Role.DEV_TOKEN;
		if (!reqRole.isSatisfiedBy(au.getRoles())) {
			throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
					"User %s is not authorized to create this token type.");
		}
		final long life;
		//TODO CONFIG make token lifetime configurable
		if (serverToken) {
			life = Long.MAX_VALUE;
		} else {
			life = 90L * 24L * 60L * 60L * 1000L;
		}
		final NewToken nt = new NewToken(TokenType.EXTENDED_LIFETIME,
				tokenName, tokens.getToken(), au.getUserName(), life);
		storage.storeToken(nt.getHashedToken());
		return nt;
	}
	
	// gets user for token
	public AuthUser getUser(final IncomingToken token)
			throws InvalidTokenException, AuthStorageException {
		try {
			return getUser(token, new Role[0]);
		} catch (UnauthorizedException e) {
			throw new RuntimeException(
					"Good job dude, you just broke reality", e); 
		}
	}
	
	// gets user for token
	private AuthUser getUser(
			final IncomingToken token,
			final Role ... required)
			throws AuthStorageException, InvalidTokenException,
			UnauthorizedException {
		final HashedToken ht = getToken(token);
		final AuthUser u = getUser(ht);
		if (required.length > 0) {
			final Set<Role> has = u.getRoles().stream()
					.flatMap(r -> r.included().stream())
					.collect(Collectors.toSet());
			has.retainAll(Arrays.asList(required)); // intersection
			if (has.isEmpty()) {
				throw new UnauthorizedException(ErrorType.UNAUTHORIZED);
			}
		}
		
		return u;
	}

	// assumes hashed token is good
	private AuthUser getUser(final HashedToken ht) throws AuthStorageException {
		try {
			return storage.getUser(ht.getUserName());
		} catch (NoSuchUserException e) {
			throw new RuntimeException("There seems to be an error in the " +
					"storage system. Token was valid, but no user", e);
		}
	}

	// get a (possibly) different user 
	public AuthUser getUser(
			final IncomingToken token,
			final UserName user)
			throws AuthStorageException, InvalidTokenException,
			NoSuchUserException {
		final HashedToken ht = getToken(token);
		final AuthUser u = storage.getUser(user);
		if (ht.getUserName().equals(u.getUserName())) {
			return u;
		} else {
			//TODO PRIVACY this shouldn't return roles
			//TODO PRIVACY only return fullname & email if info is public - actually, never return email
			return u;
		}
	}

	public void revokeToken(
			final IncomingToken token,
			final UUID tokenId)
			throws AuthStorageException,
			NoSuchTokenException, InvalidTokenException {
		final HashedToken ht = getToken(token);
		storage.deleteToken(ht.getUserName(), tokenId);
	}
	
	//note returns null if the token could not be found 
	public HashedToken revokeToken(final IncomingToken token)
			throws AuthStorageException {
		if (token == null) {
			throw new NullPointerException("token");
		}
		HashedToken ht = null;
		try {
			ht = storage.getToken(token.getHashedToken());
			storage.deleteToken(ht.getUserName(), ht.getId());
		} catch (NoSuchTokenException e) {
			// no problem, continue
		}
		return ht;
	}

	public void revokeTokens(final IncomingToken token)
			throws AuthStorageException, InvalidTokenException {
		final HashedToken ht = getToken(token);
		storage.deleteTokens(ht.getUserName());
	}


	public AuthUser getUserAsAdmin(
			final IncomingToken adminToken,
			final UserName userName)
			throws AuthStorageException, NoSuchUserException,
			InvalidTokenException, UnauthorizedException {
		if (userName == null) {
			throw new NullPointerException("userName");
		}
		getUser(adminToken, Role.ROOT, Role.CREATE_ADMIN, Role.ADMIN);
		return storage.getUser(userName);
	}
	
	public void updateRoles(
			final IncomingToken adminToken,
			final UserName userName,
			final Set<Role> roles)
			throws NoSuchUserException, AuthStorageException,
			UnauthorizedException, InvalidTokenException {
		if (userName == null) {
			throw new NullPointerException("userName");
		}
		if (roles == null) {
			throw new NullPointerException("roles");
		}
		if (adminToken == null) {
			throw new NullPointerException("adminToken");
		}
		for (final Role r: roles) {
			if (r == null) {
				throw new NullPointerException("no null roles");
			}
		}
		
		if (userName.isRoot()) {
			throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
					"Cannot change ROOT roles");
		}
		final AuthUser admin = getUser(adminToken,
				Role.ROOT, Role.CREATE_ADMIN, Role.ADMIN);
		/* TODO CODE RACE fix race condition when updating roles
		 * Send the prior roles in with the new roles. Have the storage system
		 * throw a special exception when the roles aren't the same, then
		 * retry until it works with a retry fail count to prevent infinite
		 * loops.
		 */
		//TODO ROLES allow removing your own roles (except for root)
		final AuthUser u = storage.getUser(userName);
		final Set<Role> canGrant = admin.getRoles().stream()
				.flatMap(r -> r.grants().stream()).collect(Collectors.toSet());
		
		final Set<Role> add = new HashSet<>(roles);
		add.removeAll(u.getRoles());
		final Set<Role> sub = new HashSet<>(u.getRoles());
		sub.removeAll(roles);
		
		add.removeAll(canGrant);
		sub.removeAll(canGrant);
		if (!add.isEmpty()) {
			throwUnauth("grant", add);
		}
		if (!sub.isEmpty()) {
			throwUnauth("remove", sub);
		}
		storage.setRoles(userName, roles);
	}

	private void throwUnauth(final String action, final Set<Role> roles)
			throws UnauthorizedException {
		throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
				String.format("Not authorized to %s role(s): %s", action,
						String.join(", ",
								roles.stream().map(r -> r.getDescription())
								.collect(Collectors.toSet()))));
	}

	public void setCustomRole(
			final IncomingToken incomingToken,
			final String id,
			final String description)
			throws MissingParameterException, AuthStorageException,
			InvalidTokenException, UnauthorizedException {
		getUser(incomingToken, Role.ADMIN);
		storage.setCustomRole(new CustomRole(id, description));
	}

	public Set<CustomRole> getCustomRoles(final IncomingToken incomingToken)
			throws AuthStorageException, InvalidTokenException,
			UnauthorizedException {
		getUser(incomingToken, Role.ROOT, Role.CREATE_ADMIN, Role.ADMIN);
		return storage.getCustomRoles();
	}

	public void updateCustomRoles(
			final IncomingToken adminToken,
			final UserName userName,
			final Set<String> roleIds)
			throws AuthStorageException, NoSuchUserException,
			NoSuchRoleException, InvalidTokenException, UnauthorizedException {
		getUser(adminToken, Role.ADMIN);
		final Set<CustomRole> roles = storage.getCustomRoles(roleIds);
		final Set<String> rstr = roles.stream().map(r -> r.getID())
				.collect(Collectors.toSet());
		for (final String r: roleIds) {
			if (!rstr.contains(r)) {
				throw new NoSuchRoleException(r);
			}
		}
		storage.setCustomRoles(userName, rstr);
	}


	//TODO CODE don't expose id providers. Expose a smaller interface mainly to hide the client secret.
	public List<IdentityProvider> getIdentityProviders() {
		return idFactory.getProviders();
	}

	// note not saved in DB
	public String getBareToken() {
		return tokens.getToken();
	}

	//TODO CODE don't expose id providers. Expose a smaller interface mainly to hide the client secret.
	public IdentityProvider getIdentityProvider(final String provider)
			throws NoSuchIdentityProviderException {
		return idFactory.getProvider(provider);
	}

	// split from getloginstate since the user may need to make a choice
	// we assume that this is via a html page and therefore a redirect should
	// occur before said choice to hide the authcode, hence the temporary
	// token instead of returning the choices directly
	public LoginToken login(final String provider, final String authcode)
			throws MissingParameterException, IdentityRetrievalException,
			AuthStorageException, NoSuchIdentityProviderException {
		final IdentityProvider idp = getIdentityProvider(provider);
		if (authcode == null || authcode.trim().isEmpty()) {
			throw new MissingParameterException("authorization code");
		}
		final Set<RemoteIdentity> ids = idp.getIdentities(authcode, false);
		final Set<RemoteIdentity> noUser = new HashSet<>();
		final Map<RemoteIdentityWithID, AuthUser> hasUser = new HashMap<>();
		for (final RemoteIdentity id: ids) {
			final AuthUser user = storage.getUser(id);
			if (user != null) {
				hasUser.put(user.getIdentity(id), user);
			} else {
				noUser.add(id);
			}
		}
		final LoginToken lr;
		if (hasUser.size() == 1 && noUser.isEmpty()) {
			final AuthUser user = hasUser.values().iterator().next();
			final NewToken t = new NewToken(TokenType.LOGIN, tokens.getToken(),
					//TODO CONFIG make token lifetime configurable
					user.getUserName(), 14 * 24 * 60 * 60 * 1000);
			storage.storeToken(t.getHashedToken());
			setLastLogin(user.getUserName());
			lr = new LoginToken(t);
		} else {
			final TemporaryToken tt = new TemporaryToken(tokens.getToken(),
					10 * 60 * 1000);
			final Set<RemoteIdentityWithID> store = noUser.stream()
					.map(id -> id.withID()).collect(Collectors.toSet());
			hasUser.keySet().stream().forEach(id -> store.add(id));

			storage.storeIdentitiesTemporarily(tt.getHashedToken(), store);
			lr = new LoginToken(tt);
		}
		return lr;
	}


	public Map<RemoteIdentityWithID, AuthUser> getLoginState(
			final IncomingToken token)
			throws AuthStorageException, InvalidTokenException {
		final Set<RemoteIdentityWithID> ids = getTemporaryIdentities(token);
		final Map<RemoteIdentityWithID, AuthUser> ret = new HashMap<>();
		
		String provider = null;
		for (final RemoteIdentityWithID ri: ids) {
			if (provider == null) {
				provider = ri.getRemoteID().getProvider();
			} else if (!provider.equals(ri.getRemoteID().getProvider())) {
				throw new AuthStorageException("More than one identity " +
						"provider associated with this token");
			}
			final AuthUser u = storage.getUser(ri);
			if (u == null) {
				ret.put(ri, null);
			} else if (!ret.containsValue(u)){
				//don't use the updated ri here since the ri associated with
				//the temporary token has not been updated
				ret.put(ri, u);
			}
		}
		return ret;
	}

	private Set<RemoteIdentityWithID> getTemporaryIdentities(
			final IncomingToken token)
			throws AuthStorageException, InvalidTokenException {
		if (token == null) {
			throw new NullPointerException("token");
		}
		try {
			return storage.getTemporaryIdentities(token.getHashedToken());
		} catch (NoSuchTokenException e) {
			throw new InvalidTokenException();
		}
	}

	public NewToken createUser(
			final IncomingToken token,
			final UUID identityID,
			final UserName userName,
			final String fullName,
			final String email,
			final boolean sessionLogin,
			final boolean privateNameEmail)
			throws AuthStorageException, AuthenticationException,
				UserExistsException, UnauthorizedException {
		//TODO USER_CONFIG handle sessionLogin, privateNameEmail
		if (userName == null) {
			throw new NullPointerException("userName");
		}
		if (userName.isRoot()) {
			throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
					"Cannot create ROOT user");
		}
		final RemoteIdentityWithID match =
				getIdentity(token, identityID);
		final Date now = new Date();
		storage.createUser(new AuthUser(userName, email, fullName,
				new HashSet<>(Arrays.asList(match)), null, null, now, now));
		final NewToken nt = new NewToken(TokenType.LOGIN, tokens.getToken(),
				userName,
				//TODO CONFIG make token lifetime configurable
				14 * 24 * 60 * 60 * 1000);
		storage.storeToken(nt.getHashedToken());
		return nt;
	}


	public NewToken login(final IncomingToken token, final UUID identityID)
			throws AuthenticationException, AuthStorageException {
		final RemoteIdentity ri = getIdentity(token, identityID);
		final AuthUser u = storage.getUser(ri);
		if (u == null) {
			// someone's trying to login to an account they haven't created yet
			// The UI shouldn't allow this, but they can always curl
			throw new AuthenticationException(ErrorType.AUTHENTICATION_FAILED,
					"There is no account linked to the provided identity");
		}
		
		final NewToken nt = new NewToken(TokenType.LOGIN, tokens.getToken(),
				u.getUserName(),
				//TODO CONFIG make token lifetime configurable
				14 * 24 * 60 * 60 * 1000);
		storage.storeToken(nt.getHashedToken());
		setLastLogin(u.getUserName());
		return nt;
	}
	
	private RemoteIdentityWithID getIdentity(
			final IncomingToken token,
			final UUID identityID)
			throws AuthStorageException, AuthenticationException {
		final Set<RemoteIdentityWithID> ids = getTemporaryIdentities(token);
		RemoteIdentityWithID match = null;
		for (final RemoteIdentityWithID ri: ids) {
			if (ri.getID().equals(identityID)) {
				match = ri;
			}
		}
		if (match == null) {
			throw new AuthenticationException(ErrorType.AUTHENTICATION_FAILED,
					"Not authorized to manage account linked to provided identity");
		}
		return match;
	}

	// split from getlinkstate since the user may need to make a choice
	// we assume that this is via a html page and therefore a redirect should
	// occur before said choice to hide the authcode, hence the temporary
	// token instead of returning the choices directly
	public LinkToken link(
			final IncomingToken token,
			final String provider,
			final String authcode)
			throws InvalidTokenException, AuthStorageException,
			MissingParameterException, IdentityRetrievalException,
			LinkFailedException, NoSuchIdentityProviderException {
		final AuthUser u = getUser(token);
		if (u.isLocal()) {
			throw new LinkFailedException(
					"Cannot link identities to local accounts");
		}
		final IdentityProvider idp = getIdentityProvider(provider);
		if (authcode == null || authcode.trim().isEmpty()) {
			throw new MissingParameterException("authorization code");
		}
		final Set<RemoteIdentity> ids = idp.getIdentities(authcode, true);
		filterLinkCandidates(ids);
		final LinkToken lt;
		//TODO CONFIG allow forcing choice per id provider
		if (ids.size() == 1) {
			try {
				storage.link(u.getUserName(), ids.iterator().next().withID());
			} catch (NoSuchUserException e) {
				throw new AuthStorageException(
						"User unexpectedly disappeared from the database", e);
			}
			lt = new LinkToken();
		} else {
			final TemporaryToken tt = new TemporaryToken(tokens.getToken(),
					10 * 60 * 1000);
			storage.storeIdentitiesTemporarily(tt.getHashedToken(),
					ids.stream().map(r -> r.withID())
					.collect(Collectors.toSet()));
			lt = new LinkToken(tt);
		}
		return lt;
	}

	private void filterLinkCandidates(final Set<? extends RemoteIdentity> rids)
			throws AuthStorageException, LinkFailedException {
		final Iterator<? extends RemoteIdentity> iter = rids.iterator();
		while (iter.hasNext()) {
			if (storage.getUser(iter.next()) != null) {
				iter.remove();
			}
		}
		if (rids.isEmpty()) {
			throw new LinkFailedException(
					"All provided identities are already linked");
		}
	}
	
	public LinkIdentities getLinkState(
			final IncomingToken token,
			final IncomingToken linktoken)
			throws InvalidTokenException, AuthStorageException,
			LinkFailedException {
		final AuthUser u = getUser(token);
		final Set<RemoteIdentityWithID> ids =
				getTemporaryIdentities(linktoken);
		filterLinkCandidates(ids);
		return new LinkIdentities(u, ids);
	}


	public void link(
			final IncomingToken token,
			final IncomingToken linktoken,
			final UUID identityID)
			throws AuthStorageException, AuthenticationException,
			LinkFailedException {
		final HashedToken ht = getToken(token);
		final RemoteIdentityWithID ri = getIdentity(linktoken, identityID);
		try {
			storage.link(ht.getUserName(), ri);
		} catch (NoSuchUserException e) {
			throw new AuthStorageException("Token without a user: " +
					ht.getId());
		}
	}


	public void unlink(
			final IncomingToken token,
			final UUID id)
			throws InvalidTokenException, AuthStorageException,
			UnLinkFailedException {
		if (id == null) {
			throw new NullPointerException("id");
		}
		final HashedToken ht = getToken(token);
		storage.unlink(ht.getUserName(), id);
		
	}


	public void updateUser(
			final IncomingToken token,
			final UserUpdate update)
			throws InvalidTokenException, AuthStorageException {
		if (!update.hasUpdates()) {
			return; //noop
		}
		final HashedToken ht = getToken(token);
		try {
			storage.updateUser(ht.getUserName(), update);
		} catch (NoSuchUserException e) {
			throw new AuthStorageException("Token without a user: " +
					ht.getId());
		}
	}
}
