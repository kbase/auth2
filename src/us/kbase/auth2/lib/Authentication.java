package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.checkString;
import static us.kbase.auth2.lib.Utils.clear;

import java.net.URI;
import java.net.URL;
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
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.AuthConfig.ProviderConfig;
import us.kbase.auth2.lib.AuthConfig.TokenLifetimeType;
import us.kbase.auth2.lib.exceptions.AuthenticationException;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
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
import us.kbase.auth2.lib.storage.exceptions.StorageInitException;
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
	//TODO AUTH server root should return server version (and urls for endpoints?)
	//TODO AUTH check workspace for other useful things like the schema manager
	//TODO LOG logging everywhere - on login, on logout, on create / delete / expire token
	//TODO SCOPES configure scopes via ui
	//TODO SCOPES configure scope on login via ui
	//TODO SCOPES restricted scopes - allow for specific roles or users (or for specific clients via oauth2)
	//TODO USER_PROFILE_SERVICE email & username change propagation
	//TODO DEPLOY jetty should start app immediately & fail if app fails
	
	private static final int MAX_RETURNED_USERS = 10000;
	private static final int TEMP_PWD_LENGTH = 10;
	
	private static final DisplayName UNKNOWN_DISPLAY_NAME;
	static {
		try {
			UNKNOWN_DISPLAY_NAME = new DisplayName("unknown");
		} catch (IllegalParameterException | MissingParameterException e) {
			throw new RuntimeException("this is impossible", e);
		}
	}
	
	private final AuthStorage storage;
	private final IdentityProviderFactory idFactory;
	private final TokenGenerator tokens;
	private final PasswordCrypt pwdcrypt;
	private final ConfigManager cfg;
	
	public Authentication(
			final AuthStorage storage,
			final IdentityProviderFactory identityProviderFactory,
			final ExternalConfig defaultExternalConfig)
			throws StorageInitException {
		
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
		idFactory.lock();
		final Map<String, ProviderConfig> provs = new HashMap<>();
		for (final String provname: idFactory.getProviders()) {
			provs.put(provname, AuthConfig.DEFAULT_PROVIDER_CONFIG);
		}
		final AuthConfig ac =  new AuthConfig(AuthConfig.DEFAULT_LOGIN_ALLOWED, provs,
				AuthConfig.DEFAULT_TOKEN_LIFETIMES_MS);
		try {
			storage.updateConfig(new AuthConfigSet<ExternalConfig>(
					ac, defaultExternalConfig), false);
		} catch (AuthStorageException e) {
			throw new StorageInitException("Failed to set config in storage: " +
					e.getMessage(), e);
		}
		try {
			cfg = new ConfigManager(storage);
		} catch (AuthStorageException e) {
			throw new StorageInitException("Failed to initialize config manager: " +
					e.getMessage(), e);
		}
	}
	
	private static class CollectingExternalConfig implements ExternalConfig {
		
		private final Map<String, String> cfg;
		
		private CollectingExternalConfig(
				final Map<String, String> map) {
			cfg = map;
		}
		
		@Override
		public Map<String, String> toMap() {
			return cfg;
		}

		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder();
			builder.append("CollectingExternalConfig [cfg=");
			builder.append(cfg);
			builder.append("]");
			return builder.toString();
		}
	}
	
	private class ConfigManager {
	
		private static final int CFG_UPDATE_INTERVAL_SEC = 30;
		
		private AuthConfigSet<CollectingExternalConfig> cfg;
		private Date nextConfigUpdate;
		private AuthStorage storage;
		
		public ConfigManager(final AuthStorage storage)
				throws AuthStorageException {
			this.storage = storage;
			updateConfig();
		}
		
		public synchronized AuthConfigSet<CollectingExternalConfig> getConfig()
				throws AuthStorageException {
			if (new Date().after(nextConfigUpdate)) {
				updateConfig();
			}
			return cfg;
		}
		
		public AuthConfig getAppConfig() throws AuthStorageException {
			return getConfig().getCfg();
		}
	
		public synchronized void updateConfig() throws AuthStorageException {
			try {
				cfg = storage.getConfig(m -> new CollectingExternalConfig(m));
			} catch (ExternalConfigMappingException e) {
				throw new RuntimeException("This should be impossible", e);
			}
			nextConfigUpdate = new Date(new Date().getTime() +
					CFG_UPDATE_INTERVAL_SEC * 1000);
		}
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
		final DisplayName root;
		final EmailAddress email;
		try {
			root = new DisplayName("root");
			email = new EmailAddress("root@unknown.unknown");
		} catch (IllegalParameterException | MissingParameterException e) {
			throw new RuntimeException("This is impossible", e);
		}
		storage.createRoot(UserName.ROOT, root, email,
				new HashSet<>(Arrays.asList(Role.ROOT)),
				new Date(), passwordHash, salt);
		clear(passwordHash);
		clear(salt);
	}
	
	public Password createLocalUser(
			final IncomingToken adminToken,
			final UserName userName,
			final DisplayName displayName,
			final EmailAddress email)
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
		if (displayName == null) {
			throw new NullPointerException("displayName");
		}
		if (email == null) {
			throw new NullPointerException("email");
		}
		final Password pwd = new Password(tokens.getTemporaryPassword(TEMP_PWD_LENGTH));
		final byte[] salt = pwdcrypt.generateSalt();
		final byte[] passwordHash = pwdcrypt.getEncryptedPassword(pwd.getPassword(), salt);
		final NewLocalUser lu = new NewLocalUser(userName, email, displayName, new Date(), null,
				passwordHash, salt, true);
		storage.createLocalUser(lu);
		clear(passwordHash);
		clear(salt);
		return pwd;
	}
	
	public LocalLoginResult localLogin(final UserName userName, final Password pwd)
			throws AuthenticationException, AuthStorageException, UnauthorizedException {
		final LocalUser u = getLocalUser(userName, pwd);
		if (u.isPwdResetRequired()) {
			return new LocalLoginResult(u.getUserName());
		}
		return new LocalLoginResult(login(u.getUserName()));
	}

	private LocalUser getLocalUser(final UserName userName, final Password pwd)
			throws AuthStorageException, AuthenticationException, UnauthorizedException {
		final LocalUser u;
		try {
			u = storage.getLocalUser(userName);
		} catch (NoSuchUserException e) {
			throw new AuthenticationException(ErrorType.AUTHENTICATION_FAILED,
					"Username / password mismatch");
		}
		if (!pwdcrypt.authenticate(pwd.getPassword(), u.getPasswordHash(), u.getSalt())) {
			throw new AuthenticationException(ErrorType.AUTHENTICATION_FAILED,
					"Username / password mismatch");
		}
		if (!cfg.getAppConfig().isLoginAllowed() && !Role.isAdmin(u.getRoles())) {
			throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
					"Non-admin login is disabled");
		}
		if (u.isDisabled()) {
			throw new UnauthorizedException(ErrorType.DISABLED, "This account is disabled");
		}
		pwd.clear();
		return u;
	}

	public void localPasswordChange(
			final UserName userName,
			final Password pwdold,
			final Password pwdnew)
			throws AuthenticationException, UnauthorizedException, AuthStorageException {
		//TODO PWD do any cross pwd checks like checking they're not the same
		//TODO INPUT check nulls
		getLocalUser(userName, pwdold); //checks pwd validity
		final byte[] salt = pwdcrypt.generateSalt();
		final byte[] passwordHash = pwdcrypt.getEncryptedPassword(pwdnew.getPassword(), salt);
		pwdnew.clear();
		try {
			storage.changePassword(userName, passwordHash, salt, false);
		} catch (NoSuchUserException e) {
			// we know user already exists and is local so this can't happen
			throw new RuntimeException("Sorry, you ceased to exist in the last ~10ms.", e);
		}
		clear(passwordHash);
		clear(salt);
	}


	public Password resetPassword(final IncomingToken token, final UserName userName)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException,
			NoSuchUserException {
		if (userName == null) {
			throw new NullPointerException("userName");
		}
		getUser(token, Role.ADMIN); // force admin
		
		final Password pwd = new Password(tokens.getTemporaryPassword(TEMP_PWD_LENGTH));
		final byte[] salt = pwdcrypt.generateSalt();
		final byte[] passwordHash = pwdcrypt.getEncryptedPassword(pwd.getPassword(), salt);
		storage.changePassword(userName, passwordHash, salt, true);
		clear(passwordHash);
		clear(salt);
		return pwd;
	}
	
	public void forceResetPassword(final IncomingToken token, final UserName userName)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException,
			NoSuchUserException {
		if (userName == null) {
			throw new NullPointerException("userName");
		}
		getUser(token, Role.ADMIN); // force admin
		storage.forcePasswordReset(userName);
	}

	public void forceResetAllPasswords(final IncomingToken token)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException {
		getUser(token, Role.ADMIN); // force admin
		storage.forcePasswordReset();
	}
	
	private NewToken login(final UserName userName) throws AuthStorageException {
		final NewToken nt = new NewToken(TokenType.LOGIN, tokens.getToken(),
				userName, cfg.getAppConfig().getTokenLifetimeMS(TokenLifetimeType.LOGIN));
		storage.storeToken(nt.getHashedToken());
		setLastLogin(userName);
		return nt;
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

	public Set<HashedToken> getTokens(final IncomingToken token, final UserName userName)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException {
		if (userName == null) {
			throw new NullPointerException("userName");
		}
		getUser(token, Role.ADMIN); // force admin
		return storage.getTokens(userName);
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
		final AuthConfig c = cfg.getAppConfig();
		if (serverToken) {
			life = c.getTokenLifetimeMS(TokenLifetimeType.SERV);
		} else {
			life = c.getTokenLifetimeMS(TokenLifetimeType.DEV);
		}
		final NewToken nt = new NewToken(TokenType.EXTENDED_LIFETIME,
				tokenName, tokens.getToken(), au.getUserName(), life);
		storage.storeToken(nt.getHashedToken());
		return nt;
	}
	
	// gets user for token
	public AuthUser getUser(final IncomingToken token)
			throws InvalidTokenException, AuthStorageException, DisabledUserException {
		try {
			return getUser(token, new Role[0]);
		} catch (DisabledUserException e) {
			throw e;
		} catch (UnauthorizedException e) {
			throw new RuntimeException("Good job dude, you just broke reality", e);
		}
	}
	
	// gets user for token
	private AuthUser getUser(
			final IncomingToken token,
			final Role ... required)
			throws AuthStorageException, InvalidTokenException, UnauthorizedException {
		return getUser(getToken(token), required);
	}

	// assumes hashed token is good
	private AuthUser getUser(final HashedToken ht, final Role ... required)
			throws AuthStorageException, UnauthorizedException {
		final AuthUser u;
		try {
			u = storage.getUser(ht.getUserName());
		} catch (NoSuchUserException e) {
			throw new RuntimeException("There seems to be an error in the " +
					"storage system. Token was valid, but no user", e);
		}
		if (u.isDisabled()) {
			// apparently this disabled user still has some tokens, so kill 'em all
			storage.deleteTokens(ht.getUserName());
			throw new DisabledUserException("This account is disabled");
		}
		if (required.length > 0) {
			final Set<Role> has = u.getRoles().stream().flatMap(r -> r.included().stream())
					.collect(Collectors.toSet());
			//TODO CODE why Arrays.asList here? write tests and then remove
			has.retainAll(Arrays.asList(required)); // intersection
			if (has.isEmpty()) {
				throw new UnauthorizedException(ErrorType.UNAUTHORIZED);
			}
		}
		return u;
	}

	// get a (possibly) different user 
	public ViewableUser getUser(
			final IncomingToken token,
			final UserName user)
			throws AuthStorageException, InvalidTokenException,
			NoSuchUserException {
		final HashedToken ht = getToken(token);
		final AuthUser u = storage.getUser(user);
		if (ht.getUserName().equals(u.getUserName())) {
			return new ViewableUser(u, true);
		} else {
			return new ViewableUser(u, false);
		}
	}

	public Map<UserName, DisplayName> getUserDisplayNames(
			final IncomingToken token,
			final Set<UserName> usernames)
			throws InvalidTokenException, AuthStorageException, IllegalParameterException {
		getToken(token); // just check the token is valid
		if (usernames.size() > MAX_RETURNED_USERS) {
			throw new IllegalParameterException(
					"User count exceeds maximum of " + MAX_RETURNED_USERS);
		}
		if (usernames.isEmpty()) {
			return new HashMap<>();
		}
		return storage.getUserDisplayNames(usernames);
	}
	
	// if searchfields is empty searches all fields
	public Map<UserName, DisplayName> getUserDisplayNames(
			final IncomingToken token,
			final String prefix,
			final Set<SearchField> searchFields)
			throws InvalidTokenException, AuthStorageException, IllegalParameterException {
		getToken(token); // just check the token is valid
		if (prefix == null || prefix.length() < 1) {
			throw new IllegalParameterException("prefix must contain at least one character");
		}
		if (searchFields == null) {
			throw new NullPointerException("searchFields");
		}
		return storage.getUserDisplayNames(prefix, searchFields, MAX_RETURNED_USERS);
	}
	
	public void revokeToken(
			final IncomingToken token,
			final UUID tokenID)
			throws AuthStorageException,
			NoSuchTokenException, InvalidTokenException {
		if (tokenID == null){
			throw new NullPointerException("tokenID");
		}
		final HashedToken ht = getToken(token);
		storage.deleteToken(ht.getUserName(), tokenID);
	}

	public void revokeToken(
			final IncomingToken token,
			final UserName userName,
			final UUID tokenID)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException,
			NoSuchTokenException {
		getUser(token, Role.ADMIN); // ensure admin
		if (userName == null) {
			throw new NullPointerException("userName");
		}
		if (tokenID == null) {
			throw new NullPointerException("tokenID");
		}
		storage.deleteToken(userName, tokenID);
		
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
	
	public void revokeAllTokens(final IncomingToken token)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException {
		getUser(token, Role.ADMIN); // ensure admin
		storage.deleteTokens();
	}
	

	public void revokeAllTokens(final IncomingToken token, final UserName userName)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException {
		if (userName == null) {
			throw new NullPointerException("userName");
		}
		getUser(token, Role.ADMIN); // ensure admin
		storage.deleteTokens(userName);
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
		final AuthUser admin = getUser(adminToken, Role.ROOT, Role.CREATE_ADMIN, Role.ADMIN);
		/* TODO CODE RACE fix race condition when updating roles
		 * Send the prior roles in with the new roles. Have the storage system
		 * throw a special exception when the roles aren't the same, then
		 * retry until it works with a retry fail count to prevent infinite
		 * loops.
		 */
		//TODO ROLES allow removing your own regular and custom roles (except for root)
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
	
	public void deleteCustomRole(
			final IncomingToken token,
			final String roleId)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException,
			NoSuchRoleException, MissingParameterException {
		if (roleId == null || roleId.isEmpty()) {
			throw new MissingParameterException("roleId cannot be null or empty");
		}
		getUser(token, Role.ADMIN); // ensure admin
		storage.deleteCustomRole(roleId);
	}

	/* may need to restrict to a subset of users in the future */
	public Set<CustomRole> getCustomRoles(final IncomingToken token, final boolean forceAdmin)
			throws AuthStorageException, InvalidTokenException, UnauthorizedException {
		if (forceAdmin) {
			getUser(token, Role.ADMIN, Role.CREATE_ADMIN, Role.ROOT);
		} else {
			getToken(token); // check for valid token
		}
		return storage.getCustomRoles();
	}

	public void updateCustomRoles(
			final IncomingToken adminToken,
			final UserName userName,
			final Set<String> roleIds)
			throws AuthStorageException, NoSuchUserException,
			NoSuchRoleException, InvalidTokenException, UnauthorizedException {
		getUser(adminToken, Role.ADMIN);
		storage.setCustomRoles(userName, roleIds);
	}


	public List<String> getIdentityProviders() throws AuthStorageException {
		final AuthConfig ac = cfg.getAppConfig();
		return idFactory.getProviders().stream()
				.filter(p -> ac.getProviderConfig(p).isEnabled())
				.collect(Collectors.toList());
	}
	
	private IdentityProvider getIdentityProvider(final String provider)
			throws NoSuchIdentityProviderException, AuthStorageException {
		final IdentityProvider ip = idFactory.getProvider(provider);
		if (!cfg.getAppConfig().getProviderConfig(provider).isEnabled()) {
			throw new NoSuchIdentityProviderException(provider);
		}
		return ip;
	}
	
	public URI getIdentityProviderImageURI(final String provider)
			throws NoSuchIdentityProviderException, AuthStorageException {
		return getIdentityProvider(provider).getImageURI();
	}
	
	public URL getIdentityProviderURL(
			final String provider,
			final String state,
			final boolean link)
			throws NoSuchIdentityProviderException, AuthStorageException {
		return getIdentityProvider(provider).getLoginURL(state, link);
	}

	// note not saved in DB
	public String getBareToken() {
		return tokens.getToken();
	}

	/* split from getLoginState() since the user may need to make a choice
	 * This function is almost certainly being called as a result of a redirect from a 3rd party
	 * with the authcode in the url. Hence another redirect should
	 * occur before said choice to hide the authcode, hence the temporary
	 * token instead of returning the choices directly
	 */
	public LoginToken login(final String provider, final String authcode)
			throws MissingParameterException, IdentityRetrievalException,
			AuthStorageException, NoSuchIdentityProviderException {
		final IdentityProvider idp = getIdentityProvider(provider);
		if (authcode == null || authcode.trim().isEmpty()) {
			throw new MissingParameterException("authorization code");
		}
		final Set<RemoteIdentity> ids = idp.getIdentities(authcode, false);
		AuthUser lastUser = null;
		final Set<UserName> names = new HashSet<>();
		final Set<RemoteIdentity> noUser = new HashSet<>();
		final Set<RemoteIdentityWithID> hasUser = new HashSet<>();
		for (final RemoteIdentity id: ids) {
			lastUser = storage.getUser(id);
			if (lastUser != null) {
				hasUser.add(lastUser.getIdentity(id));
				// since AuthUser equals and hashcode situation is too complex
				names.add(lastUser.getUserName()); 
			} else {
				noUser.add(id);
			}
		}
		final LoginToken lr;
		if (names.size() == 1 && noUser.isEmpty()) {
			/* Don't throw an error here since an auth UI is not controlling the call in most
			 * cases - this call is almost certainly the result of a redirect from a 3rd party
			 * provider. Any controllable error should be thrown when the process flow is back
			 * under the control of the primary auth UI.
			 * 
			 * There's a tiny chance here that the user could be made an admin, be enabled, or
			 * non-admin login be enabled between this step and the getLoginState() step. The
			 * consequence is that they'll have to choose from one account in the next step,
			 * so who cares.
			 */
			if (!cfg.getAppConfig().isLoginAllowed() && !Role.isAdmin(lastUser.getRoles())) {
				lr = storeIdentitiesTemporarily(noUser, hasUser);
			} else if (lastUser.isDisabled()) {
				lr = storeIdentitiesTemporarily(noUser, hasUser);
			} else {
				lr = new LoginToken(login(lastUser.getUserName()));
			}
		} else {
			// store the identities so the user can create an account or choose from more than one
			// account
			lr = storeIdentitiesTemporarily(noUser, hasUser);
		}
		return lr;
	}

	private LoginToken storeIdentitiesTemporarily(
			final Set<RemoteIdentity> noUser,
			final Set<RemoteIdentityWithID> hasUser)
			throws AuthStorageException {
		final Set<RemoteIdentityWithID> store = noUser.stream()
				.map(id -> id.withID()).collect(Collectors.toSet());
		hasUser.stream().forEach(id -> store.add(id));

		final TemporaryToken tt = new TemporaryToken(tokens.getToken(), 10 * 60 * 1000);
		storage.storeIdentitiesTemporarily(tt.getHashedToken(), store);
		return new LoginToken(tt);
	}


	public LoginState getLoginState(final IncomingToken token)
			throws AuthStorageException, InvalidTokenException {
		final Set<RemoteIdentityWithID> ids = getTemporaryIdentities(token);
		if (ids.isEmpty()) {
			throw new RuntimeException(
					"Programming error: temporary login token stored with no identities");
		}
		final String provider = ids.iterator().next().getRemoteID().getProvider();
		final LoginState.Builder builder = new LoginState.Builder(provider,
				cfg.getAppConfig().isLoginAllowed());
		for (final RemoteIdentityWithID ri: ids) {
			final AuthUser u = storage.getUser(ri);
			if (u == null) {
				builder.addIdentity(ri);
			} else {
				//don't use the updated RemoteIdentity from the AuthUser here since the ri
				// associated with the temporary token has not been updated
				builder.addUser(u, ri);
			}
		}
		return builder.build();
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
			final DisplayName displayName,
			final EmailAddress email)
			throws AuthStorageException, AuthenticationException,
				UserExistsException, UnauthorizedException {
		if (!cfg.getAppConfig().isLoginAllowed()) {
			throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
					"Account creation is disabled");
		}
		//TODO INPUT check all inputs
		if (userName == null) {
			throw new NullPointerException("userName");
		}
		if (userName.isRoot()) {
			throw new UnauthorizedException(ErrorType.UNAUTHORIZED, "Cannot create ROOT user");
		}
		final RemoteIdentityWithID match = getIdentity(token, identityID);
		final Date now = new Date();
		storage.createUser(new NewUser(userName, email, displayName,
				new HashSet<>(Arrays.asList(match)), now, now));
		return login(userName);
	}


	public NewToken login(final IncomingToken token, final UUID identityID)
			throws AuthenticationException, AuthStorageException,
			UnauthorizedException {
		final RemoteIdentity ri = getIdentity(token, identityID);
		final AuthUser u = storage.getUser(ri);
		if (u == null) {
			// someone's trying to login to an account they haven't created yet
			// The UI shouldn't allow this, but they can always curl
			throw new AuthenticationException(ErrorType.AUTHENTICATION_FAILED,
					"There is no account linked to the provided identity ID");
		}
		if (!cfg.getAppConfig().isLoginAllowed() && !Role.isAdmin(u.getRoles())) {
			throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
					"Non-admin login is disabled");
		}
		if (u.isDisabled()) {
			throw new DisabledUserException("This account is disabled");
		}
		return login(u.getUserName());
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

	/* split from getLinkState() since the user may need to make a choice
	 * This function is almost certainly being called as a result of a redirect from a 3rd party
	 * with the authcode in the url. Hence another redirect should
	 * occur before said choice to hide the authcode, hence the temporary
	 * token instead of returning the choices directly
	 */
	public LinkToken link(
			final IncomingToken token,
			final String provider,
			final String authcode)
			throws InvalidTokenException, AuthStorageException,
			MissingParameterException, IdentityRetrievalException,
			LinkFailedException, NoSuchIdentityProviderException, DisabledUserException {
		final AuthUser u = getUser(token); // UI shouldn't allow disabled users to link
		if (u.isLocal()) {
			// the ui shouldn't allow local users to link accounts, so ok to throw this
			throw new LinkFailedException("Cannot link identities to local accounts");
		}
		final IdentityProvider idp = getIdentityProvider(provider);
		if (authcode == null || authcode.trim().isEmpty()) {
			throw new MissingParameterException("authorization code");
		}
		final Set<RemoteIdentity> ids = idp.getIdentities(authcode, true);
		filterLinkCandidates(ids);
		/* Don't throw an error if ids are empty since an auth UI is not controlling the call in
		 * most cases - this call is almost certainly the result of a redirect from a 3rd party
		 * provider. Any controllable error should be thrown when the process flow is back
		 * under the control of the primary auth UI.
		 */
		final LinkToken lt;
		final ProviderConfig pc = cfg.getAppConfig().getProviderConfig(provider);
		if (ids.size() == 1 && !pc.isForceLinkChoice()) {
			try {
				/* throws link failed exception if u is a local user or the id is already linked
				 * Since we already checked those, only a rare race condition can cause a link
				 * failed exception, and the consequence is trivial so don't worry about it
				 */
				storage.link(u.getUserName(), ids.iterator().next().withID());
			} catch (NoSuchUserException e) {
				throw new AuthStorageException(
						"User unexpectedly disappeared from the database", e);
			}
			lt = new LinkToken();
		} else { // will store an ID set if said set is empty.
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
			throws AuthStorageException {
		final Iterator<? extends RemoteIdentity> iter = rids.iterator();
		while (iter.hasNext()) {
			if (storage.getUser(iter.next()) != null) {
				iter.remove();
			}
		}
	}
	
	public LinkIdentities getLinkState(
			final IncomingToken token,
			final IncomingToken linktoken)
			throws InvalidTokenException, AuthStorageException,
			LinkFailedException, DisabledUserException {
		final AuthUser u = getUser(token);
		if (u.isLocal()) {
			throw new LinkFailedException("Cannot link identities to local accounts");
		}
		final Set<RemoteIdentityWithID> ids = getTemporaryIdentities(linktoken);
		filterLinkCandidates(ids);
		if (ids.isEmpty()) {
			throw new LinkFailedException("All provided identities are already linked");
		}
		return new LinkIdentities(u, ids);
	}

	public void link(
			final IncomingToken token,
			final IncomingToken linktoken,
			final UUID identityID)
			throws AuthStorageException, AuthenticationException,
			LinkFailedException, DisabledUserException {
		final AuthUser ht = getUser(token);
		final RemoteIdentityWithID ri = getIdentity(linktoken, identityID);
		try {
			storage.link(ht.getUserName(), ri);
		} catch (NoSuchUserException e) {
			throw new AuthStorageException("User magically disappeared from database: " +
					ht.getUserName().getName());
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
	

	public void disableAccount(
			final IncomingToken token,
			final UserName user,
			final boolean disable,
			final String reason)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException,
			IllegalParameterException, NoSuchUserException {
		final AuthUser admin = getUser(token, Role.ROOT, Role.CREATE_ADMIN, Role.ADMIN);
		if (user == null) {
			throw new NullPointerException("user");
		}
		if (disable) {
			if (user.isRoot() && !admin.isRoot()) {
				throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
						"Only the root user can disable the root account");
			}
			if (reason == null || reason.isEmpty()) {
				throw new IllegalParameterException(
						"Must provide a reason why the account was disabled");
			}
			storage.deleteTokens(user); //not really necessary but doesn't hurt
			storage.disableAccount(user, admin.getUserName(), reason);
			/* there's a tiny chance a login could be in process right now and have have passed the
			 * disabled check, and then have the token created after the next line, but that's
			 * so improbable I'm not going to worry about it
			 * The getUser method checks to see if a user is disabled if if so deletes their tokens
			 * as well as a backup
			 */
			storage.deleteTokens(user);
		} else {
			storage.enableAccount(user, admin.getUserName());
		}
		
	}
	
	public <T extends ExternalConfig> void updateConfig(
			final IncomingToken token,
			final AuthConfigSet<T> acs)
			throws InvalidTokenException, UnauthorizedException,
			AuthStorageException, NoSuchIdentityProviderException {
		getUser(token, Role.ADMIN);
		for (final String provider: acs.getCfg().getProviders().keySet()) {
			//throws an exception if no provider by given name
			idFactory.getProvider(provider);
		}
		storage.updateConfig(acs, true);
		cfg.updateConfig();
	}
	
	public <T extends ExternalConfig> AuthConfigSet<T> getConfig(
			final IncomingToken token,
			final ExternalConfigMapper<T> mapper)
			throws InvalidTokenException, UnauthorizedException,
			AuthStorageException, ExternalConfigMappingException {
		getUser(token, Role.ADMIN);
		final AuthConfigSet<CollectingExternalConfig> acs = cfg.getConfig();
		return new AuthConfigSet<T>(acs.getCfg(),
				mapper.fromMap(acs.getExtcfg().toMap()));
	}
	
	public long getSuggestedTokenCacheTime() throws AuthStorageException {
		return cfg.getAppConfig().getTokenLifetimeMS(TokenLifetimeType.EXT_CACHE);
	}
	
	// don't expose in public api
	public <T extends ExternalConfig> T getExternalConfig(
			final ExternalConfigMapper<T> mapper)
			throws AuthStorageException, ExternalConfigMappingException {
		final AuthConfigSet<CollectingExternalConfig> acs = cfg.getConfig();
		return mapper.fromMap(acs.getExtcfg().toMap());
	}

	// do not expose this method in the public API
	public void importUser(final RemoteIdentity ri)
			throws IllegalParameterException, UserExistsException,
			AuthStorageException {
		if (ri == null) {
			throw new NullPointerException("ri");
		}
		String username = ri.getDetails().getUsername();
		/* Do NOT otherwise change the username here - this is importing
		 * existing users, and so changing the username will mean erroneous
		 * resource assignments
		 */
		if (username.contains("@")) {
			username = username.split("@")[0];
			if (username.isEmpty()) {
				throw new IllegalParameterException(
						ErrorType.ILLEGAL_USER_NAME,
						ri.getDetails().getUsername());
			}
		}
		final UserName un;
		try {
			un = new UserName(username);
		} catch (MissingParameterException e) {
			throw new RuntimeException("Impossible", e);
		}
		DisplayName dn;
		try { // hacky, but eh. Python guys will like it though
			dn = new DisplayName(ri.getDetails().getFullname());
		} catch (IllegalParameterException | MissingParameterException e) {
			dn = UNKNOWN_DISPLAY_NAME;
		}
		EmailAddress email;
		try {
			email = new EmailAddress(ri.getDetails().getEmail());
		} catch (IllegalParameterException | MissingParameterException e) {
			email = EmailAddress.UNKNOWN;
		}
		storage.createUser(new NewUser(un, email, dn,
				new HashSet<>(Arrays.asList(ri.withID())),
				new Date(), null));
	}
}
