package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.checkString;
import static us.kbase.auth2.lib.Utils.clear;
import static us.kbase.auth2.lib.Utils.nonNull;
import static us.kbase.auth2.lib.Utils.noNulls;

import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.cryptutils.PasswordCrypt;
import us.kbase.auth2.cryptutils.RandomDataGenerator;
import us.kbase.auth2.cryptutils.SHA1RandomDataGenerator;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.IdentityLinkedException;
import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.IllegalPasswordException;
import us.kbase.auth2.lib.config.AuthConfig;
import us.kbase.auth2.lib.config.AuthConfigSet;
import us.kbase.auth2.lib.config.CollectingExternalConfig;
import us.kbase.auth2.lib.config.ExternalConfig;
import us.kbase.auth2.lib.config.ExternalConfigMapper;
import us.kbase.auth2.lib.config.AuthConfig.ProviderConfig;
import us.kbase.auth2.lib.config.AuthConfig.TokenLifetimeType;
import us.kbase.auth2.lib.config.CollectingExternalConfig.CollectingExternalConfigMapper;
import us.kbase.auth2.lib.exceptions.AuthenticationException;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.LinkFailedException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UnLinkFailedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.storage.exceptions.StorageInitException;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.lib.token.TokenName;
import us.kbase.auth2.lib.token.TokenSet;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.lib.user.LocalUser;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.auth2.lib.token.IncomingToken;

/** The main class for the Authentication application.
 * 
 * Handles creating accounts, login & un/linking accounts via OAuth2 flow, creating, deleting, and
 * validating tokens, handling internal and external configuration, managing user roles and
 * passwords, and searching for users.
 * 
 * Manages two types of accounts. Standard users are created and logged into via OAuth2 identity
 * providers and always have at least one 3rd party identity associated with the user. Local users
 * have no linked identities and are accessed by a traditional password scheme. The intent is
 * that local user accounts are used sparingly for admins for the authorization application,
 * admins for other services, and owners of long-lived server tokens. The vast majority of users
 * should use standard accounts.
 * 
 * Manages two types of roles. Built in roles define which actions a user may take with regard to
 * the authentication application. Additionally, administrators may define custom roles and
 * assign them to users. It is expected that the number of custom roles are relatively small (on
 * the order of thousands at most) per storage instance.
 * 
 * Many methods require a token for a user with specific roles. Most often this is the
 * administrator role. In some, but not all, cases the create administrator and root roles can also
 * perform the action. The root role's only purpose is to grant the the create administrator role.
 * The create administrator role's only purpose is to grant the administrator role.
 * 
 * @author gaprice@lbl.gov
 *
 */
public class Authentication {

	//TODO TEST test unicode for inputs and outputs
	//TODO TEST unit tests
	//TODO TEST test logging on startup
	//TODO TEST test logging on calls
	//TODO ZZLATER EMAIL validate email address by sending an email
	//TODO AUTH server root should return server version (and urls for endpoints?)
	//TODO LOG logging everywhere - on login, on logout, on create / delete / expire token, etc.
	//TODO ZLATER SCOPES configure scopes via ui
	//TODO ZLATER SCOPES configure scope on login via ui
	//TODO ZLATER SCOPES restricted scopes - allow for specific roles or users (or for specific clients via oauth2)
	//TODO ZLATER DEPLOY jetty should start app immediately & fail if app fails - can't figure out how to do this
	//TODO SECURITY keep track of logins over last X seconds, lock account for Y seconds after Z failures
	//TODO ZLATER USER_INPUT check for obscene/offensive content and reject
	//TODO CODE code analysis https://www.codacy.com/
	//TODO CODE code analysis https://find-sec-bugs.github.io/
	//TODO ZLATER POLICYIDS maintain admin settable list of required policy IDs, check on login & force choice page if missing. fail login or create if missing. Return missing with choice data
	//TODO ZLATER SCOPES use token types as scopes for some activities - for example admin actions should require a login token.
	
	private static final int LINK_TOKEN_LIFETIME_MS = 10 * 60 * 1000;
	private static final int MAX_RETURNED_USERS = 10000;
	private static final int TEMP_PWD_LENGTH = 10;
	
	private static final UserName DEFAULT_SUGGESTED_USER_NAME;
	private static final DisplayName UNKNOWN_DISPLAY_NAME;
	static {
		try {
			DEFAULT_SUGGESTED_USER_NAME = new UserName("user");
			UNKNOWN_DISPLAY_NAME = new DisplayName("unknown");
		} catch (IllegalParameterException | MissingParameterException e) {
			throw new RuntimeException("this should be impossible", e);
		}
	}
	
	private static final Map<TokenType, TokenLifetimeType> TOKEN_LIFE_TYPE = ImmutableMap.of(
			TokenType.LOGIN, TokenLifetimeType.LOGIN,
			TokenType.AGENT, TokenLifetimeType.AGENT,
			TokenType.DEV, TokenLifetimeType.DEV,
			TokenType.SERV, TokenLifetimeType.SERV);

	private final AuthStorage storage;
	// DO NOT modify this after construction, not thread safe
	private final TreeMap<String, IdentityProvider> idProviderSet = new TreeMap<>(
			String.CASE_INSENSITIVE_ORDER);
	private final RandomDataGenerator randGen;
	private final PasswordCrypt pwdcrypt;
	private final ConfigManager cfg;
	private final Clock clock;
	
	//TODO UI show this with note that it'll take X seconds to sync to other server instance
	private int cfgUpdateIntervalSec = 30;
	
	/** Create a new Authentication instance.
	 * @param storage the storage system to use for information persistance.
	 * @param identityProviderSet the set of identity providers that are supported for standard
	 * accounts. E.g. Google, Globus, etc.
	 * @param defaultExternalConfig the external configuration default settings. Any settings
	 * that do not already exist in the storage system will be persisted. Pre-existing settings
	 * are not overwritten.
	 * @throws StorageInitException if the storage system cannot be accessed.
	 */
	public Authentication(
			final AuthStorage storage,
			final Set<IdentityProvider> identityProviderSet,
			final ExternalConfig defaultExternalConfig)
			throws StorageInitException {
		this(storage,
				identityProviderSet,
				defaultExternalConfig,
				getDefaultRandomGenerator(),
				Clock.systemDefaultZone()); // don't care about time zone, not using it
	}

	private static RandomDataGenerator getDefaultRandomGenerator() {
		try {
			return new SHA1RandomDataGenerator();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("This should be impossible", e);
		}
	}
	
	/* This constructor is for testing purposes only. */
	private Authentication(
			final AuthStorage storage,
			final Set<IdentityProvider> identityProviderSet,
			final ExternalConfig defaultExternalConfig,
			final RandomDataGenerator randGen,
			final Clock clock)
			throws StorageInitException {
		this.clock = clock;
		this.randGen = randGen;
		try {
			pwdcrypt = new PasswordCrypt();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("This should be impossible", e);
		}
		nonNull(storage, "storage");
		nonNull(identityProviderSet, "identityProviderSet");
		noNulls(identityProviderSet, "Null identity provider in set");
		nonNull(defaultExternalConfig, "defaultExternalConfig");
		this.storage = storage;
		for (final IdentityProvider idp: identityProviderSet) {
			if (idProviderSet.containsKey(idp.getProviderName())) { // case insensitive
				throw new IllegalArgumentException("Duplicate provider name: " +
						idp.getProviderName());
			}
			idProviderSet.put(idp.getProviderName(), idp);
		}
		final Map<String, ProviderConfig> provs = idProviderSet.keySet().stream().collect(
				Collectors.toMap(Function.identity(), n -> AuthConfig.DEFAULT_PROVIDER_CONFIG));
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
	
	// for test purposes. Resets the next update time to be the previous update + seconds.
	@SuppressWarnings("unused")
	private void setConfigUpdateInterval(int seconds) {
		final Instant prevUpdate = cfg.getNextUpdateTime();
		final Instant newUpdate = prevUpdate.minusSeconds(cfgUpdateIntervalSec)
				.plusSeconds(seconds);
		cfgUpdateIntervalSec = seconds;
		cfg.setNextUpdateTime(newUpdate);
	}
	
	/* Caches the configuration to avoid pulling the configuration from the storage system
	 * on every request. Synchronized to prevent multiple storage accesses for one update.
	 */
	//TODO TEST config manager
	private class ConfigManager {
	
		private AuthConfigSet<CollectingExternalConfig> cfg;
		private Instant nextConfigUpdate;
		private AuthStorage storage;
		
		public ConfigManager(final AuthStorage storage)
				throws AuthStorageException {
			this.storage = storage;
			updateConfig();
		}
		
		// for testing purposes.
		public synchronized Instant getNextUpdateTime() {
			return nextConfigUpdate;
		}
		
		// for testing purposes.
		public synchronized void setNextUpdateTime(final Instant time) {
			nextConfigUpdate = time;
		}
		
		public synchronized AuthConfigSet<CollectingExternalConfig> getConfig()
				throws AuthStorageException {
			if (Instant.now().isAfter(nextConfigUpdate)) {
				updateConfig();
			}
			return cfg;
		}
		
		public AuthConfig getAppConfig() throws AuthStorageException {
			return getConfig().getCfg();
		}
	
		public synchronized void updateConfig() throws AuthStorageException {
			try {
				cfg = storage.getConfig(new CollectingExternalConfigMapper());
			} catch (ExternalConfigMappingException e) {
				throw new RuntimeException("This should be impossible", e);
			}
			nextConfigUpdate = Instant.now().plusSeconds(cfgUpdateIntervalSec);
		}
	}

	/** Create a root account, or update the root account password if one does not already exist.
	 * If the root account exists and is disabled, it will be enabled.
	 * 
	 * This method should not be exposed in public APIs.
	 * 
	 * The method calls pwd.clear() on the passed-in password as soon as possible.
	 * 
	 * @param pwd the new password for the root account.
	 * @throws AuthStorageException if updating the root account fails.
	 */
	public void createRoot(final Password pwd)
			throws AuthStorageException, IllegalPasswordException {
		nonNull(pwd, "pwd");
		try {
			pwd.checkValidity();
		} catch (IllegalPasswordException e) {
			pwd.clear();
			throw e;
		}
		final char[] pwd_copy = pwd.getPassword();
		final byte[] salt = randGen.generateSalt();
		final byte[] passwordHash = pwdcrypt.getEncryptedPassword(pwd_copy, salt);
		Password.clearPasswordArray(pwd_copy);
		try {
			pwd.clear();
			final DisplayName dn;
			try {
				dn = new DisplayName("root");
			} catch (IllegalParameterException | MissingParameterException e) {
				throw new RuntimeException("This is impossible", e);
			}
			final LocalUser root = LocalUser.getBuilder(
					UserName.ROOT, dn, clock.instant(), passwordHash, salt).build();
			try {
				storage.createLocalUser(root);
				// only way to avoid a race condition. Checking existence before creating user
				// means if user is added between check and update update will fail
			} catch (UserExistsException uee) {
				try {
					storage.changePassword(UserName.ROOT, passwordHash, salt, false);
					if (storage.getUser(UserName.ROOT).isDisabled()) {
						storage.enableAccount(UserName.ROOT, UserName.ROOT);
					}
				} catch (NoSuchUserException nsue) {
					throw new RuntimeException("OK. This is really bad. I give up.", nsue);
				}
			} catch (NoSuchRoleException e) {
				throw new RuntimeException("didn't supply any roles", e);
			}
		} finally {
			pwd.clear();
			clear(passwordHash);
			clear(salt);
		}
	}
	
	/** Creates a new local user.
	 * @param adminToken a token for a user with the administrator, create administrator, or root
	 * role.
	 * @param userName the name of the new user.
	 * @param displayName the display name of the new user.
	 * @param email the email address of the new user.
	 * @return the new password for the local user.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws UserExistsException if the username is already in use.
	 * @throws UnauthorizedException if the user for the token is not an admin, the username to
	 * be created is the root user name, or the token is not a login token.
	 * @throws InvalidTokenException if the token is invalid.
	 */
	public Password createLocalUser(
			final IncomingToken adminToken,
			final UserName userName,
			final DisplayName displayName,
			final EmailAddress email)
			throws AuthStorageException, UserExistsException, UnauthorizedException,
			InvalidTokenException {
		nonNull(userName, "userName");
		nonNull(displayName, "displayName");
		nonNull(email, "email");
		if (userName.isRoot()) {
			throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
					"Cannot create ROOT user");
		}
		getUser(adminToken, set(TokenType.LOGIN), Role.ROOT, Role.CREATE_ADMIN, Role.ADMIN);
		Password pwd = null;
		char [] pwd_copy = null;
		byte[] salt = null;
		byte[] passwordHash = null;
		try {
			pwd = new Password(randGen.getTemporaryPassword(TEMP_PWD_LENGTH));
			salt = randGen.generateSalt();
			pwd_copy = pwd.getPassword();
			passwordHash = pwdcrypt.getEncryptedPassword(pwd_copy, salt);
			final LocalUser lu = LocalUser.getBuilder(
					userName, displayName, clock.instant(), passwordHash, salt)
					.withEmailAddress(email).withForceReset(true).build();
			storage.createLocalUser(lu);
		} catch (NoSuchRoleException e) {
			throw new RuntimeException("didn't supply any roles", e);
		} catch (Throwable t) {
			if (pwd != null) {
				pwd.clear(); // no way to test pwd was actually cleared. Prob never stored anyway
			}
			throw t;
		} finally {
			// at least with mockito I don't see how to capture these in an error condition,
			// since the create user storage call needs to throw an exception so can't use an
			// Answer
			clear(passwordHash);
			clear(salt);
			Password.clearPasswordArray(pwd_copy);
		}
		return pwd;
	}
	
	/** Login with a local user.
	 * 
	 * The password is always cleared once the password has been verified or if an error occurs.
	 * 
	 * @param userName the username of the account.
	 * @param password the password for the account.
	 * @return the result of the login attempt.
	 * @throws AuthenticationException if the login attempt failed.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws UnauthorizedException if the user is not an admin and non-admin login is disabled or
	 * the user account is disabled.
	 */
	public LocalLoginResult localLogin(final UserName userName, final Password password)
			throws AuthenticationException, AuthStorageException, UnauthorizedException {
		final LocalUser u = getLocalUser(userName, password);
		if (u.isPwdResetRequired()) {
			return new LocalLoginResult(u.getUserName());
		}
		return new LocalLoginResult(login(u.getUserName()));
	}

	private LocalUser getLocalUser(final UserName userName, final Password password)
			throws AuthStorageException, AuthenticationException, UnauthorizedException {
		nonNull(password, "password");
		final LocalUser u;
		try {
			nonNull(userName, "userName");
			try {
				u = storage.getLocalUser(userName);
			} catch (NoSuchUserException e) {
				throw new AuthenticationException(ErrorType.AUTHENTICATION_FAILED,
						"Username / password mismatch");
			}
			if (!pwdcrypt.authenticate(password.getPassword(), u.getPasswordHash(), u.getSalt())) {
				throw new AuthenticationException(ErrorType.AUTHENTICATION_FAILED,
						"Username / password mismatch");
			}
			password.clear();
			if (!cfg.getAppConfig().isLoginAllowed() && !Role.isAdmin(u.getRoles())) {
				throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
						"Non-admin login is disabled");
			}
			if (u.isDisabled()) {
				throw new DisabledUserException();
			}
		} finally {
			password.clear();
		}
		return u;
	}

	/** Change a local user's password.
	 * 
	 * Clears the passwords as soon as they're no longer needed or when an error occurs.
	 * 
	 * @param userName the user name of the account.
	 * @param password the old password for the user account.
	 * @param pwdnew the new password for the user account.
	 * @throws AuthenticationException if the username and password do not match.
	 * @throws UnauthorizedException if the user is not an admin and non-admin login is disabled or
	 * the user account is disabled.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 */
	public void localPasswordChange(
			final UserName userName,
			final Password password,
			final Password pwdnew)
			throws AuthenticationException, UnauthorizedException, AuthStorageException,
					IllegalPasswordException {
		byte[] salt = null;
		byte[] passwordHash = null;
		try {
			nonNull(pwdnew, "pwdnew");
			if(pwdnew.equals(password)) {
				throw new IllegalPasswordException("Old and new passwords are identical.");
			}
			pwdnew.checkValidity();
			getLocalUser(userName, password); //checks pwd validity and nulls
			salt = randGen.generateSalt();
			final char [] pwd_copy = pwdnew.getPassword();
			passwordHash = pwdcrypt.getEncryptedPassword(pwd_copy, salt);
			Password.clearPasswordArray(pwd_copy);
			pwdnew.clear();
			storage.changePassword(userName, passwordHash, salt, false);
		} catch (NoSuchUserException e) {
			// we know user already exists and is local so this can't happen
			throw new AuthStorageException("Sorry, you ceased to exist in the last ~10ms.", e);
		} finally {
			if (password != null) {
				password.clear();
			}
			if (pwdnew != null) {
				pwdnew.clear();
			}
			// at least with mockito I don't see how to capture these in an error condition,
			// since the create user storage call needs to throw an exception so can't use an
			// Answer
			clear(passwordHash);
			clear(salt);
		}
	}

	/** Reset a local user's password to a random password.
	 * @param token a token for a user with the administrator role.
	 * @param userName the user name of the account to reset.
	 * @return the new password.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws UnauthorizedException if the user account associated with the token does not
	 * have the administrator role or the token is not a login token.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws NoSuchUserException if there is no user corresponding to the given user name.
	 */
	public Password resetPassword(final IncomingToken token, final UserName userName)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException,
			NoSuchUserException {
		checkCanResetPassword(token, userName);
		Password pwd = null;
		byte[] salt = null;
		byte[] passwordHash = null;
		try {
			pwd = new Password(randGen.getTemporaryPassword(TEMP_PWD_LENGTH));
			salt = randGen.generateSalt();
			passwordHash = pwdcrypt.getEncryptedPassword(pwd.getPassword(), salt);
			storage.changePassword(userName, passwordHash, salt, true);
		} catch (Throwable t) {
			if (pwd != null) {
				pwd.clear(); // no way to test pwd was actually cleared. Prob never stored anyway
			}
			throw t;
		} finally {
			// at least with mockito I don't see how to capture these in an error condition,
			// since the create user storage call needs to throw an exception so can't use an
			// Answer
			clear(passwordHash);
			clear(salt);
		}
		return pwd;
	}
	
	private void checkCanResetPassword(final IncomingToken token, final UserName userName)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException,
			NoSuchUserException {
		// this method is gross. rethink. ideally based on the grantable roles somehow.
		nonNull(userName, "userName");
		final AuthUser admin = getUser(token, set(TokenType.LOGIN),
				Role.ADMIN, Role.CREATE_ADMIN, Role.ROOT); 
		final AuthUser user = storage.getUser(userName);
		if (!user.isLocal()) {
			throw new NoSuchUserException(String.format(
					"%s is not a local user and has no password", userName.getName()));
		}
		if (!Role.isAdmin(user.getRoles())) {
			return; //ok, any admin can change a std user's pwd.
		}
		if (admin.getUserName().equals(user.getUserName())) {
			return; //ok, an admin can always change their own pwd.
		}
		if (admin.isRoot()) {
			return; //ok, duh. It's root.
		}
		if (user.isRoot()) { // already know admin isn't root, so bail out.
			throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
					"Only root can reset root password");
		}
		// only root and the owner of an account with the CREATE_ADMIN role can change the pwd
		if (Role.CREATE_ADMIN.isSatisfiedBy(user.getRoles())) {
			throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
					"Cannot reset password of user with create administrator role");
		}
		/* at this point we know user is a standard admin and admin is not root. That means
		 * that admin has to have CREATE_ADMIN to proceed. 
		 */
		if (!Role.CREATE_ADMIN.isSatisfiedBy(admin.getRoles())) {
			throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
					"Cannot reset password of user with administrator role");
		}
		// user is a standard admin and admin has the CREATE_ADMIN role so changing the pwd is ok.
	}

	/** Force a local user to reset their password on their next login.
	 * @param token a token for a user with the administrator role.
	 * @param userName the user name of the account for which a password reset is required.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws UnauthorizedException if the user account associated with the token does not
	 * have the administrator role or the token is not a login token.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws NoSuchUserException if there is no user corresponding to the given user name.
	 */
	public void forceResetPassword(final IncomingToken token, final UserName userName)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException,
			NoSuchUserException {
		checkCanResetPassword(token, userName);
		storage.forcePasswordReset(userName);
	}

	/** Force all local users to reset their password on their next login.
	 * @param token a token for a user with the administrator role.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws UnauthorizedException if the user account associated with the token does not
	 * have the administrator role or the token is not a login token.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 */
	public void forceResetAllPasswords(final IncomingToken token)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException {
		getUser(token, set(TokenType.LOGIN), Role.CREATE_ADMIN, Role.ROOT); // force admin
		storage.forcePasswordReset();
	}
	
	private NewToken login(final UserName userName) throws AuthStorageException {
		final NewToken nt = new NewToken(StoredToken.getBuilder(
					TokenType.LOGIN, randGen.randomUUID(), userName)
				.withLifeTime(clock.instant(),
						cfg.getAppConfig().getTokenLifetimeMS(TokenLifetimeType.LOGIN))
				.build(),
				randGen.getToken());
		storage.storeToken(nt.getStoredToken(), nt.getTokenHash());
		setLastLogin(userName);
		return nt;
	}

	// used when it's known that the user exists
	private void setLastLogin(final UserName userName)
			throws AuthStorageException {
		try {
			storage.setLastLogin(userName, clock.instant());
		} catch (NoSuchUserException e) {
			throw new AuthStorageException(
					"Something is very broken. User should exist but doesn't: "
							+ e.getMessage(), e);
		}
	}

	/** Get a random token. This token is not persisted in the storage system.
	 * @return a token.
	 */
	public String getBareToken() {
		return randGen.getToken();
	}

	/** Get the tokens associated with a user account associated with a possessed token.
	 * @param token a user token for the account in question.
	 * @return the tokens.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws UnauthorizedException if the token is not a login token.
	 */
	public TokenSet getTokens(final IncomingToken token)
			throws AuthStorageException, InvalidTokenException, UnauthorizedException {
		final StoredToken ht = getToken(token, set(TokenType.LOGIN));
		return new TokenSet(ht, storage.getTokens(ht.getUserName()));
	}

	/** Get the tokens associated with an arbitrary user account.
	 * 
	 * @param token a token for a user with the administrator role.
	 * @param userName the user name of the account.
	 * @return the tokens associated with the given account.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws UnauthorizedException if the user account associated with the token does not
	 * have the administrator role or the token is not a login token.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 */
	public Set<StoredToken> getTokens(final IncomingToken token, final UserName userName)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException {
		nonNull(userName, "userName");
		getUser(token, set(TokenType.LOGIN), Role.ADMIN); // force admin
		return storage.getTokens(userName);
	}

	// converts a no such token exception into an invalid token exception.
	/** Get details about a token.
	 * @param token the token in question.
	 * @return the token's details.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 */
	public StoredToken getToken(final IncomingToken token)
			throws AuthStorageException, InvalidTokenException {
		try {
			return getToken(token, set());
		} catch (UnauthorizedException e) {
			throw new RuntimeException("Didn't require any particular token", e);
		}
	}
	
	private StoredToken getToken(final IncomingToken token, final Set<TokenType> allowedTypes)
			throws AuthStorageException, InvalidTokenException, UnauthorizedException {
		nonNull(token, "token");
		try {
			final StoredToken ht = storage.getToken(token.getHashedToken());
			if (!allowedTypes.isEmpty() && !allowedTypes.contains(ht.getTokenType())) {
				throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
						ht.getTokenType().getDescription() +
						" tokens are not allowed for this operation");
			}
			return ht;
		} catch (NoSuchTokenException e) {
			throw new InvalidTokenException();
		}
	}

	/** Create a new agent, developer or service token.
	 * @param token a token for the user that wishes to create a new token.
	 * @param tokenName a name for the token.
	 * @param tokenType the type of token to create. Note that login tokens may not be created
	 * other than via logging in.
	 * @return the new token.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws InvalidTokenException if the provided token is not valid.
	 * @throws UnauthorizedException if the provided token is not a login token or the user does
	 * not have the role required to create the token type.
	 */
	public NewToken createToken(
			final IncomingToken token,
			final TokenName tokenName,
			final TokenType tokenType)
			throws AuthStorageException, InvalidTokenException, UnauthorizedException {
		nonNull(tokenName, "tokenName");
		nonNull(tokenType, "tokenType");
		if (TokenType.LOGIN.equals(tokenType)) {
			throw new IllegalArgumentException("Cannot create a login token without logging in");
		}
		// check for disabled user for all token type targets as well
		final AuthUser au = getUser(token, set(TokenType.LOGIN));
		if (!TokenType.AGENT.equals(tokenType)) {
			final Role reqRole = TokenType.SERV.equals(tokenType) ?
					Role.SERV_TOKEN : Role.DEV_TOKEN;
			if (!reqRole.isSatisfiedBy(au.getRoles())) {
				throw new UnauthorizedException(ErrorType.UNAUTHORIZED, String.format(
						"User %s is not authorized to create this token type.",
						au.getUserName().getName()));
			}
		}
		final AuthConfig c = cfg.getAppConfig();
		final long life = c.getTokenLifetimeMS(TOKEN_LIFE_TYPE.get(tokenType));
		final Instant now = clock.instant();
		final NewToken nt = new NewToken(StoredToken.getBuilder(
					tokenType, randGen.randomUUID(), au.getUserName())
				.withLifeTime(now, life)
				.withTokenName(tokenName).build(),
				randGen.getToken());
		storage.storeToken(nt.getStoredToken(), nt.getTokenHash());
		return nt;
	}
	
	/** Get a user from an incoming token.
	 * @param token the token.
	 * @return the user.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws DisabledUserException if the user is disabled.
	 */
	public AuthUser getUser(final IncomingToken token)
			throws InvalidTokenException, AuthStorageException, DisabledUserException {
		try {
			return getUser(token, new Role[0]);
		} catch (DisabledUserException e) {
			// this catch block is here because a disabled user exception is a subclass of
			// unauthorized exception. We want to throw DUE but not UE.
			throw e;
		} catch (UnauthorizedException e) { // this is impossible to test
			throw new RuntimeException("Good job dude, you just broke reality", e);
		}
	}

	// requires the user to have at least one of the required roles
	private AuthUser getUser(
			final IncomingToken token,
			final Role ... required)
			throws AuthStorageException, InvalidTokenException, UnauthorizedException {
		return getUser(getToken(token), required);
	}
	
	// requires the user to have at least one of the required roles
	private AuthUser getUser(
			final IncomingToken token,
			final Set<TokenType> allowedTokenTypes)
					throws AuthStorageException, InvalidTokenException, UnauthorizedException {
		return getUser(getToken(token, allowedTokenTypes), new Role[0]);
	}

	// requires the user to have at least one of the required roles
	private AuthUser getUser(
			final IncomingToken token,
			final Set<TokenType> allowedTokenTypes,
			final Role ... requiredRoles)
					throws AuthStorageException, InvalidTokenException, UnauthorizedException {
		return getUser(getToken(token, allowedTokenTypes), requiredRoles);
	}

	//TODO ZLATER CODE might want to make a requirements class that captures token and role requirements
	
	// assumes hashed token is good
	// requires the user to have at least one of the required roles
	private AuthUser getUser(final StoredToken ht, final Role ... required)
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
			throw new DisabledUserException();
		}
		if (required.length > 0) {
			final Set<Role> has = u.getRoles().stream().flatMap(r -> r.included().stream())
					.collect(Collectors.toSet());
			has.retainAll(Arrays.asList(required)); // intersection
			if (has.isEmpty()) {
				throw new UnauthorizedException(ErrorType.UNAUTHORIZED);
			}
		}
		return u;
	}

	/** Get a restricted view of a user. Typically used for one user viewing another.
	 * @param token the token of the user requesting the view.
	 * @param user the username of the user to view.
	 * @return a view of the user.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws NoSuchUserException if there is no user corresponding to the given user name or the
	 * user is disabled.
	 */
	public ViewableUser getUser(
			final IncomingToken token,
			final UserName user)
			throws AuthStorageException, InvalidTokenException,
			NoSuchUserException {
		nonNull(user, "userName");
		final StoredToken ht = getToken(token);
		final AuthUser u = storage.getUser(user);
		final boolean sameUser = ht.getUserName().equals(u.getUserName());
		if (u.isDisabled()) {
			if (sameUser) {
				storage.deleteTokens(u.getUserName());
			}
			throw new NoSuchUserException(u.getUserName().getName());
		}
		return new ViewableUser(u, sameUser);
	}

	/** Get a user as an admin.
	 * @param adminToken a token for a user with the administator, create administator, or root
	 * role.
	 * @param userName the name of the user account to get.
	 * @return the user.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws NoSuchUserException if no user exists with the given user name.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws UnauthorizedException if the user account associated with the token does not have
	 * one of the required roles or the token is not a login token.
	 */
	public AuthUser getUserAsAdmin(
			final IncomingToken adminToken,
			final UserName userName)
			throws AuthStorageException, NoSuchUserException,
			InvalidTokenException, UnauthorizedException {
		nonNull(userName, "userName");
		getUser(adminToken, set(TokenType.LOGIN), Role.ROOT, Role.CREATE_ADMIN, Role.ADMIN);
		return storage.getUser(userName);
	}

	/** Look up display names for a set of user names. A maximum of 10000 users may be looked up
	 * at once. Never returns the root user name or disabled users.
	 * @param token a token for the user requesting the lookup.
	 * @param userNames the user names to look up.
	 * @return the display names for each user name. Any non-existent user names will be missing.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws IllegalParameterException if the number of requested user names is greater than the
	 * limit.
	 */
	public Map<UserName, DisplayName> getUserDisplayNames(
			final IncomingToken token,
			final Set<UserName> userNames)
			throws InvalidTokenException, AuthStorageException, IllegalParameterException {
		nonNull(userNames, "userNames");
		noNulls(userNames, "Null name in userNames");
		getToken(token); // just check the token is valid
		if (userNames.isEmpty()) {
			return new HashMap<>();
		}
		if (userNames.size() > MAX_RETURNED_USERS) {
			throw new IllegalParameterException(
					"User count exceeds maximum of " + MAX_RETURNED_USERS);
		}
		
		final Map<UserName, DisplayName> displayNames = storage.getUserDisplayNames(userNames);
		displayNames.remove(UserName.ROOT);
		return displayNames;
	}
	
	/** Look up display names based on a search specification. A maximum of 10000 users will be
	 * returned.
	 * @param token a token for the user requesting the lookup.
	 * @param spec the search specification.
	 * @return the display names of the users.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws UnauthorizedException if the user does not have the administrator, create
	 * administrator, or root role and a role search, prefix-less search is requested or the
	 * results are to include the root use or disabled users.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 */
	public Map<UserName, DisplayName> getUserDisplayNames(
			final IncomingToken token,
			final UserSearchSpec spec)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException {
		nonNull(spec, "spec");
		if (spec.isRegex()) {
			throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
					"Regex search is currently for internal use only");
		}
		final AuthUser user = getUser(token);
		if (!Role.isAdmin(user.getRoles())) {
			if (spec.isCustomRoleSearch() || spec.isRoleSearch()) {
				throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
						"Only admins may search on roles");
			}
			if (!spec.getSearchPrefix().isPresent()) {
				throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
						"Only admins may search without a prefix");
			}
			if (spec.isRootIncluded() || spec.isDisabledIncluded()) {
				throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
						"Only admins may search with root or disabled users included");
			}
		}
		final Map<UserName, DisplayName> displayNames = storage.getUserDisplayNames(
				spec, MAX_RETURNED_USERS);
		if (!spec.isRootIncluded()) {
			displayNames.remove(UserName.ROOT);
		}
		return displayNames;
	}
	

	/** Get a currently available user name given a user name suggestion. Returns absent
	 * if a reasonable user name cannot be found.
	 * @param suggestedUserName the suggested user name.
	 * @return an available user name.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 */
	public Optional<UserName> getAvailableUserName(final String suggestedUserName)
			throws AuthStorageException {
		nonNull(suggestedUserName, "suggestedUserName");
		final Optional<UserName> target = UserName.sanitizeName(suggestedUserName);
		Optional<UserName> availableUserName = Optional.absent();
		if (target.isPresent()) {
			availableUserName = getAvailableUserName(target.get(), false, true);
		}
		if (!availableUserName.isPresent()) {
			availableUserName = getAvailableUserName(DEFAULT_SUGGESTED_USER_NAME, true, false);
		}
		return availableUserName;
	}
	
	private Optional<UserName> getAvailableUserName(
			final UserName suggestedUserName,
			final boolean forceNumericSuffix,
			final boolean startAt2)
			throws AuthStorageException {
		// lots of opportunities for speed optimization in this method, but it probably doesn't
		// matter
		
		final String sugName = suggestedUserName.getName();
		final String sugStrip = sugName.replaceAll("\\d*$", "");
		/* this might return a lot of names, but not super likely and it'd take a *lot* to cause
		 * problems. Make this smarter if necessary. E.g. could store username and numeric suffix
		 * db side and search and sort db side.
		 */
		final UserSearchSpec spec = UserSearchSpec.getBuilder()
				// checked that this does indeed use an index for the mongo implementation
				.withSearchRegex("^" + Pattern.quote(sugStrip) + "\\d*$")
				.withSearchOnUserName(true).withIncludeDisabled(true).build();
		final Map<UserName, DisplayName> users = storage.getUserDisplayNames(spec, -1);
		final boolean match = users.containsKey(suggestedUserName);
		final boolean hasNumSuffix = sugStrip.length() != sugName.length();
		if (!match && (!forceNumericSuffix || hasNumSuffix)) {
			return Optional.of(suggestedUserName);
		}
		final Set<String> names = users.keySet().stream().map(u -> u.getName())
				.collect(Collectors.toSet());
		final long start = startAt2 ? 2 : 1;
		for (long i = start; i < Long.MAX_VALUE; i++) {
			final String potential = sugStrip + i;
			if (potential.length() > UserName.MAX_NAME_LENGTH) {
				return Optional.absent();
			}
			if (!names.contains(potential)) {
				try {
					return Optional.of(new UserName(potential));
				} catch (IllegalParameterException | MissingParameterException e) {
					throw new RuntimeException("this should be impossible", e);
				}
			}
		}
		// this means there's > 10^63 names in the database. Not testing this path.
		return Optional.absent();
	}

	/** Revoke a token.
	 * @param token the user's token.
	 * @param tokenID the id of the token to revoke.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws NoSuchTokenException if the user does not possess a token with the given id.
	 * @throws InvalidTokenException if the user's token is invalid.
	 * @throws UnauthorizedException if the incoming token is not a login token.
	 */
	public void revokeToken(
			final IncomingToken token,
			final UUID tokenID)
			throws AuthStorageException,
			NoSuchTokenException, InvalidTokenException, UnauthorizedException {
		nonNull(tokenID, "tokenID");
		final StoredToken ht = getToken(token, set(TokenType.LOGIN));
		storage.deleteToken(ht.getUserName(), tokenID);
	}

	/* maybe combine this with the above method...? The username is a good check that you're
	 * revoking the right token though.
	 */
	/** Revokes an arbitrary users's token.
	 * @param token a token for a user with the administrator role.
	 * @param userName the user name of the account for which a token will be revoked.
	 * @param tokenID the ID of the token to revoke.
	 * @throws InvalidTokenException if the admin token is invalid.
	 * @throws UnauthorizedException if the user account associated with the token does not have
	 * the administrator role or the incoming token is not a login token.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws NoSuchTokenException if there is no token for the specified user with the
	 * specified ID.
	 */
	public void revokeToken(
			final IncomingToken token,
			final UserName userName,
			final UUID tokenID)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException,
			NoSuchTokenException {
		nonNull(userName, "userName");
		nonNull(tokenID, "tokenID");
		getUser(token, set(TokenType.LOGIN), Role.ADMIN); // ensure admin
		storage.deleteToken(userName, tokenID);
		
	}
	
	/** Revoke the current token. Returns an empty Optional if the token does not exist in the
	 * database, and thus there is nothing to revoke.
	 * @param token the token to be revoked.
	 * @return the revoked token, or an empty Optional.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 */
	public Optional<StoredToken> revokeToken(final IncomingToken token)
			throws AuthStorageException {
		nonNull(token, "token");
		StoredToken ht = null;
		try {
			ht = storage.getToken(token.getHashedToken());
			storage.deleteToken(ht.getUserName(), ht.getId());
			return Optional.of(ht);
		} catch (NoSuchTokenException e) {
			// no problem, continue
		}
		return Optional.absent();
	}

	/** Revokes all of a user's tokens.
	 * @param token the token for the user.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws UnauthorizedException if the token is not a login token.
	 */
	public void revokeTokens(final IncomingToken token)
			throws AuthStorageException, InvalidTokenException, UnauthorizedException {
		final StoredToken ht = getToken(token, set(TokenType.LOGIN));
		storage.deleteTokens(ht.getUserName());
	}
	
	/** Revokes all tokens across all users, including the current user.
	 * @param token a token for a user with the administrator role.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws UnauthorizedException if the user account associated with the token does not have
	 * the administrator role or the token is not a login token.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 */
	public void revokeAllTokens(final IncomingToken token)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException {
		getUser(token, set(TokenType.LOGIN), Role.ADMIN); // ensure admin
		storage.deleteTokens();
	}
	

	/** Revoke all of a user's tokens as an admin.
	 * @param token a token for a user with the administrator role.
	 * @param userName the name of the user account for which all tokens will be revoked.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws UnauthorizedException if the user account associated with the token does not have
	 * the administrator role or the token is not a login token.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 */
	public void revokeAllTokens(final IncomingToken token, final UserName userName)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException {
		nonNull(userName, "userName");
		getUser(token, set(TokenType.LOGIN), Role.ADMIN); // ensure admin
		storage.deleteTokens(userName);
	}
	
	/** Remove roles from a user.
	 * @param token the user's token.
	 * @param removeRoles the roles to remove.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws UnauthorizedException if the user is the root user or the token is not a login
	 * token.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 */
	public void removeRoles(final IncomingToken token, final Set<Role> removeRoles)
			throws InvalidTokenException, UnauthorizedException,
			AuthStorageException {
		final StoredToken ht = getToken(token, set(TokenType.LOGIN));
		try {
			updateRoles(token, ht.getUserName(), Collections.emptySet(), removeRoles);
		} catch (NoSuchUserException e) {
			throw new RuntimeException("There seems to be an error in the " +
					"storage system. Token was valid, but no user", e);
		} catch (IllegalParameterException e) {
			throw new RuntimeException(
					"Reality appears to be broken. Please turn it off and then back on again");
		}
	}
	
	/** Update a user's roles. Any user can remove their own roles, but certain roles must be
	 * possessed to grant or remove certain other roles.
	 * 
	 * @see Role
	 * @param userToken the token of the user adding or removing roles.
	 * @param userName the user name of the user account for which roles are to be altered.
	 * @param addRoles the roles to add to the user account.
	 * @param removeRoles the roles to remove from the user account.
	 * @throws NoSuchUserException if there is no user account with the given name.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws UnauthorizedException if the user account associated with the token is not
	 * authorized to make the changes requested or the token is not a login token.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws IllegalParameterException if a role is to be both removed and added.
	 */
	public void updateRoles(
			final IncomingToken userToken,
			final UserName userName,
			final Set<Role> addRoles,
			final Set<Role> removeRoles)
			throws NoSuchUserException, AuthStorageException,
			UnauthorizedException, InvalidTokenException, IllegalParameterException {
		nonNull(userName, "userName");
		nonNull(addRoles, "addRoles");
		nonNull(removeRoles, "removeRoles");
		noNulls(addRoles, "Null role in addRoles");
		noNulls(removeRoles, "Null role in removeRoles");
		
		final Set<Role> intersect = new HashSet<>(addRoles);
		intersect.retainAll(removeRoles);
		if (!intersect.isEmpty()) {
			throw new IllegalParameterException(
					"One or more roles is to be both removed and added: " +
					String.join(", ", rolesToDescriptions(intersect)));
		}
		if (userName.isRoot()) {
			throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
					"Cannot change ROOT roles");
		}
		final AuthUser actinguser = getUser(userToken, set(TokenType.LOGIN));
		
		final Set<Role> add = new HashSet<>(addRoles);
		add.removeAll(actinguser.getGrantableRoles());
		final Set<Role> sub = new HashSet<>(removeRoles);
		sub.removeAll(actinguser.getGrantableRoles());
		
		if (!add.isEmpty()) {
			throwUnauthorizedToManageRoles("grant", add);
		}
		if (!sub.isEmpty() && !userName.equals(actinguser.getUserName())) {
			throwUnauthorizedToManageRoles("remove", sub);
		}
		storage.updateRoles(userName, addRoles, removeRoles);
	}

	private void throwUnauthorizedToManageRoles(final String action, final Set<Role> roles)
			throws UnauthorizedException {
		throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
				String.format("Not authorized to %s role(s): %s", action,
						String.join(", ", rolesToDescriptions(roles))));
	}

	private Set<String> rolesToDescriptions(final Set<Role> roles) {
		return roles.stream().map(r -> r.getDescription()).collect(Collectors.toSet());
	}

	/** Create or update a custom role.
	 * @param token a token for a user account with the administrator privilege.
	 * @param role the role to create, or if it already exists based on the ID, update.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws UnauthorizedException if the user account associated with the token does not have
	 * the administrator role or the token is not a login token.
	 * @throws InvalidTokenException if the token is invalid.
	 */
	public void setCustomRole(
			final IncomingToken token,
			final CustomRole role)
			throws AuthStorageException, InvalidTokenException, UnauthorizedException {
		nonNull(role, "role");
		getUser(token, set(TokenType.LOGIN), Role.ADMIN);
		storage.setCustomRole(role);
	}
	
	/** Delete a custom role. Deletes the role from all users.
	 * @param token a token for a user account with the administrator privilege.
	 * @param roleId the id of the role.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws UnauthorizedException if the user account associated with the token does not have
	 * the administrator role or the token is not a login token.
	 * @throws NoSuchRoleException if there is no role by the given ID.
	 * @throws MissingParameterException if the role ID is missing.
	 * @throws IllegalParameterException if the role ID is illegal.
	 */
	public void deleteCustomRole(
			final IncomingToken token,
			final String roleId)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException,
			NoSuchRoleException, MissingParameterException, IllegalParameterException {
		if (roleId == null || roleId.trim().isEmpty()) {
			throw new MissingParameterException("roleId cannot be null or empty");
		}
		getUser(token, set(TokenType.LOGIN), Role.ADMIN); // ensure admin
		storage.deleteCustomRole(roleId);
	}

	/* may need to restrict to a subset of users in the future */
	/** Get all custom roles.
	 * @param token a user's token.
	 * @param forceAdmin ensure the user has the administrator, create administrator, or root role.
	 * @return the custom roles.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws UnauthorizedException if the user account associated with the token does not have
	 * an appropriate role and forceAdmin is true, or if the token is not a login token.
	 * @throws InvalidTokenException if the token is invalid.
	 */
	public Set<CustomRole> getCustomRoles(final IncomingToken token, final boolean forceAdmin)
			throws AuthStorageException, InvalidTokenException, UnauthorizedException {
		if (forceAdmin) {
			getUser(token, set(TokenType.LOGIN), Role.ADMIN, Role.CREATE_ADMIN, Role.ROOT);
		} else {
			getToken(token, set(TokenType.LOGIN)); // check for valid token
		}
		return storage.getCustomRoles();
	}

	/** Update a user's custom roles.
	 * @param userToken a token for a user account with the administrator role.
	 * @param userName the name of the user for which the custom roles will be altered.
	 * @param addRoles the roles to add.
	 * @param removeRoles the roles to remove.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws UnauthorizedException if the user account associated with the token does not have
	 * the administrator role or the token is not a login token.
	 * @throws NoSuchUserException if there is no user account with the given name.
	 * @throws NoSuchRoleException if one of the roles does not exist in the database.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws IllegalParameterException if a role is to be both removed and added.
	 */
	public void updateCustomRoles(
			final IncomingToken userToken,
			final UserName userName,
			final Set<String> addRoles,
			final Set<String> removeRoles)
			throws AuthStorageException, NoSuchUserException, NoSuchRoleException,
			InvalidTokenException, UnauthorizedException, IllegalParameterException {
		// some of this code is similar to the updateRoles function, refactor?
		nonNull(userName, "userName");
		nonNull(addRoles, "addRoles");
		nonNull(removeRoles, "removeRoles");
		noNulls(addRoles, "Null role in addRoles");
		noNulls(removeRoles, "Null role in removeRoles");
		
		final Set<String> intersect = new HashSet<>(addRoles);
		intersect.retainAll(removeRoles);
		if (!intersect.isEmpty()) {
			throw new IllegalParameterException(
					"One or more roles is to be both removed and added: " +
					String.join(", ", intersect));
		}
		/* for now don't allow users to remove their own custom roles, since admins may want
		 * to set roles for users that users can't change. However, there's no reason not to allow
		 * users to remove standard roles, which are privileges, not tags 
		 */
		getUser(userToken, set(TokenType.LOGIN), Role.ADMIN);
		storage.updateCustomRoles(userName, addRoles, removeRoles);
	}

	/** Get an ordered list of the supported and enabled identity providers.
	 * @return the identity provider names.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 */
	public List<String> getIdentityProviders() throws AuthStorageException {
		final AuthConfig ac = cfg.getAppConfig();
		final List<String> provs = new LinkedList<>();
		for (final String prov: idProviderSet.navigableKeySet()) {
			try {
				if (ac.getProviderConfig(prov).isEnabled()) {
					provs.add(prov);
				}
			} catch (NoSuchIdentityProviderException e) {
				throw new RuntimeException(String.format("Programming error. The configuration " +
						"for the provider %s is no longer accessible in the storage system",
						prov), e);
			}
		}
		return provs;
	}
	
	// looks up the provider, case insensitive 
	private IdentityProvider getIdentityProvider(final String provider)
			throws NoSuchIdentityProviderException, AuthStorageException {
		nonNull(provider, "provider");
		final IdentityProvider idp = idProviderSet.get(provider);
		if (idp == null) {
			throw new NoSuchIdentityProviderException(provider);
		}
		if (!cfg.getAppConfig().getProviderConfig(idp.getProviderName()).isEnabled()) {
			throw new NoSuchIdentityProviderException(provider);
		}
		return idp;
	}
	
	/** Get a redirection url for an identity provider.
	 * Applications should redirect to this url to initiate an OAuth2 flow.
	 * @param provider the name of the provider that will service the OAuth2 request.
	 * @param state the OAuth2 state variable to send with the request.
	 * @param link true if the action is a link request rather than a login request.
	 * @return the redirect url.
	 * @throws NoSuchIdentityProviderException if the provider does not exist or is not enabled.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 */
	public URL getIdentityProviderURL(
			final String provider,
			final String state,
			final boolean link)
			throws NoSuchIdentityProviderException, AuthStorageException {
		if (state == null || state.trim().isEmpty()) {
			throw new IllegalArgumentException("state cannot be null or empty");
		}
		return getIdentityProvider(provider).getLoginURL(state, link);
	}

	/** Continue the local portion of an OAuth2 login flow after redirection from a 3rd party
	 * identity provider.
	 * If the information returned from the identity provider allows the login to occur
	 * immediately, a login token is returned.
	 * If user interaction is required, a temporary token is returned that is associated with the
	 * state of the login request. This token can be used to retrieve the login state via
	 * {@link #getLoginState(IncomingToken)}.
	 * 
	 * In some cases, this method will have
	 * been called after a redirect from a 3rd party identity provider, and as such, the login
	 * flow is not under the control of any UI elements at that point. Hence, if the login cannot
	 * proceed immediately, the state is stored so the user can be redirected to the appropriate
	 * UI element, which can then retrieve the login state and continue. A secondary point is that
	 * the URL will contain the identity provider authcode, and so the user should be redirected
	 * to a new URL that does not contain said authcode as soon as possible.
	 * 
	 * @param provider the name of the identity provider that is servicing the login request.
	 * @param authcode the authcode provided by the provider.
	 * @return either a login token or temporary token.
	 * @throws MissingParameterException if the authcode is missing.
	 * @throws IdentityRetrievalException if an error occurred when trying to retrieve identities
	 * from the provider.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws NoSuchIdentityProviderException if there is no provider by the given name.
	 */
	public LoginToken login(final String provider, final String authcode)
			throws MissingParameterException, IdentityRetrievalException,
			AuthStorageException, NoSuchIdentityProviderException {
		
		if (authcode == null || authcode.trim().isEmpty()) {
			throw new MissingParameterException("authorization code");
		}
		final IdentityProvider idp = getIdentityProvider(provider);
		final Set<RemoteIdentity> ris = idp.getIdentities(authcode, false);
		final LoginState ls = getLoginState(ris);
		final ProviderConfig pc = cfg.getAppConfig().getProviderConfig(idp.getProviderName());
		final LoginToken lr;
		if (ls.getUsers().size() == 1 &&
				ls.getIdentities().isEmpty() &&
				!pc.isForceLoginChoice()) {
			final UserName userName = ls.getUsers().iterator().next();
			final AuthUser user = ls.getUser(userName);
			/* Don't throw an error here since an auth UI may not be controlling the call -
			 * this call may be the result of a redirect from a 3rd party
			 * provider. Any controllable error should be thrown when the process flow is back
			 * under the control of the primary auth UI.
			 * 
			 * There's a tiny chance here that the user could be made an admin, be enabled, or
			 * non-admin login be enabled between this step and the getLoginState() step. The
			 * consequence is that they'll have to choose from one account in the next step,
			 * so who cares.
			 */
			if (!cfg.getAppConfig().isLoginAllowed() && !Role.isAdmin(user.getRoles())) {
				lr = storeIdentitiesTemporarily(ls);
			} else if (user.isDisabled()) {
				lr = storeIdentitiesTemporarily(ls);
			} else {
				lr = new LoginToken(login(user.getUserName()), ls);
			}
		} else {
			// store the identities so the user can create an account or choose from more than one
			// account
			lr = storeIdentitiesTemporarily(ls);
		}
		return lr;
	}

	private LoginToken storeIdentitiesTemporarily(final LoginState ls)
			throws AuthStorageException {
		final Set<RemoteIdentity> store = new HashSet<>(ls.getIdentities());
		ls.getUsers().stream().forEach(u -> store.addAll(ls.getIdentities(u)));
		final TemporaryToken tt = storeIdentitiesTemporarily(store, 30 * 60 * 1000);
		return new LoginToken(tt, ls);
	}

	/** Get the current state of a login process associated with a temporary token.
	 * This method is expected to be called after {@link #login(String, String)}.
	 * After user interaction is completed, a new user can be created via
	 * {@link #createUser(IncomingToken, String, UserName, DisplayName, EmailAddress, Set, boolean)}
	 * or the login can complete via {@link #login(IncomingToken, String, Set, boolean)}.
	 * @param token the temporary token.
	 * @return the state of the login process.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws InvalidTokenException if the token is invalid.
	 */
	public LoginState getLoginState(final IncomingToken token)
			throws AuthStorageException, InvalidTokenException {
		final Set<RemoteIdentity> ids = getTemporaryIdentities(token);
		if (ids.isEmpty()) {
			throw new RuntimeException(
					"Programming error: temporary login token stored with no identities");
		}
		return getLoginState(ids);
	}

	private LoginState getLoginState(final Set<RemoteIdentity> ids)
			throws AuthStorageException {
		final String provider = ids.iterator().next().getRemoteID().getProviderName();
		final LoginState.Builder builder = LoginState.getBuilder(provider,
				cfg.getAppConfig().isLoginAllowed());
		for (final RemoteIdentity ri: ids) {
			final Optional<AuthUser> u = storage.getUser(ri);
			if (!u.isPresent()) {
				builder.withIdentity(ri);
			} else {
				builder.withUser(u.get(), ri);
			}
		}
		return builder.build();
	}

	private Set<RemoteIdentity> getTemporaryIdentities(
			final IncomingToken token)
			throws AuthStorageException, InvalidTokenException {
		nonNull(token, "Temporary token");
		try {
			return storage.getTemporaryIdentities(token.getHashedToken());
		} catch (NoSuchTokenException e) {
			throw new InvalidTokenException("Temporary token");
		}
	}

	/** Create a new user linked to a 3rd party identity.
	 * 
	 * This method is expected to be called after {@link #getLoginState(IncomingToken)}.
	 * @param token a temporary token associated with the login process state.
	 * @param identityID the id of the identity to link to the new user. This identity must be
	 * included in the login state associated with the temporary token. 
	 * @param userName the user name for the new user.
	 * @param displayName the display name for the new user.
	 * @param email the email address for the new user.
	 * @param policyIDs the policy IDs to be added to the user account.
	 * @param linkAll link all other available identities associated with the temporary token to
	 * this account.
	 * @return a new login token for the new user.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws UnauthorizedException if the id is not included in the login state associated with
	 * the token or if login is disabled.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws UserExistsException if the user name is already in use.
	 * @throws UnauthorizedException if login is disabled or the username is the root user name.
	 * @throws IdentityLinkedException if the specified identity is already linked to a user.
	 * @throws MissingParameterException if the identity ID is null or the empty string.
	 */
	public NewToken createUser(
			final IncomingToken token,
			final String identityID,
			final UserName userName,
			final DisplayName displayName,
			final EmailAddress email,
			final Set<PolicyID> policyIDs,
			final boolean linkAll)
			throws AuthStorageException, InvalidTokenException, UserExistsException,
			UnauthorizedException, IdentityLinkedException, MissingParameterException {
		nonNull(userName, "userName");
		nonNull(displayName, "displayName");
		nonNull(email, "email");
		nonNull(policyIDs, "policyIDs");
		noNulls(policyIDs, "null item in policyIDs");
		if (userName.isRoot()) {
			throw new UnauthorizedException(ErrorType.UNAUTHORIZED, "Cannot create ROOT user");
		}
		if (!cfg.getAppConfig().isLoginAllowed()) {
			throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
					"Account creation is disabled");
		}
		final Set<RemoteIdentity> ids = getTemporaryIdentities(token);
		final Optional<RemoteIdentity> match = getIdentity(identityID, ids);
		if (!match.isPresent()) {
			throw new UnauthorizedException(ErrorType.UNAUTHORIZED, String.format(
					"Not authorized to create user with remote identity %s", identityID));
		}
		final Instant now = clock.instant();
		final NewUser.Builder b = NewUser.getBuilder(userName, displayName, now, match.get())
				 // no need to set last login, will be set in the login() call below
				.withEmailAddress(email);
		for (final PolicyID pid: policyIDs) {
			b.withPolicyID(pid, now);
		}
		try {
			storage.createUser(b.build());
		} catch (NoSuchRoleException e) {
			throw new RuntimeException("Didn't supply any roles", e);
		}
		if (linkAll) {
			ids.remove(match.get());
			filterLinkCandidates(ids);
			link(userName, ids);
		}
		return login(userName);
	}

	/** Complete the OAuth2 login process.
	 * 
	 * This method is expected to be called after {@link #getLoginState(IncomingToken)}.
	 * @param token a temporary token associated with the login process state.
	 * @param identityID the id of the identity associated with the user account that is the login
	 * target. This identity must be included in the login state associated with the temporary
	 * token. 
	 * @param policyIDs the policy IDs to add to the user account.
	 * @param linkAll link all other available identities associated with the temporary token to
	 * this account.
	 * @return a new login token.
	 * @throws AuthenticationException if the id is not included in the login state associated with
	 * the token or there is no user associated with the remote identity.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws UnauthorizedException if the user is not an administrator and non-admin login
	 * is not allowed or the user account is disabled.
	 * @throws MissingParameterException  if the identity ID is null or the empty string.
	 */
	public NewToken login(
			final IncomingToken token,
			final String identityID,
			final Set<PolicyID> policyIDs,
			final boolean linkAll)
			throws AuthenticationException, AuthStorageException, UnauthorizedException,
				MissingParameterException {
		nonNull(policyIDs, "policyIDs");
		noNulls(policyIDs, "null item in policyIDs");
		final Set<RemoteIdentity> ids = getTemporaryIdentities(token);
		final Optional<RemoteIdentity> ri = getIdentity(identityID, ids);
		if (!ri.isPresent()) {
			throw new UnauthorizedException(ErrorType.UNAUTHORIZED, String.format(
					"Not authorized to login to user with remote identity %s", identityID));
		}
		final Optional<AuthUser> u = storage.getUser(ri.get());
		if (!u.isPresent()) {
			// someone's trying to login to an account they haven't created yet
			// The UI shouldn't allow this, but they can always curl
			throw new AuthenticationException(ErrorType.AUTHENTICATION_FAILED,
					"There is no account linked to the provided identity ID");
		}
		if (!cfg.getAppConfig().isLoginAllowed() && !Role.isAdmin(u.get().getRoles())) {
			throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
					"Non-admin login is disabled");
		}
		if (u.get().isDisabled()) {
			throw new DisabledUserException();
		}
		addPolicyIDs(u.get().getUserName(), policyIDs);
		if (linkAll) {
			ids.remove(ri.get());
			filterLinkCandidates(ids);
			link(u.get().getUserName(), ids);
		}
		return login(u.get().getUserName());
	}
	
	private Optional<RemoteIdentity> getIdentity(
			final String identityID,
			final Set<RemoteIdentity> identities)
			throws MissingParameterException {
		checkString(identityID, "identityID");
		for (final RemoteIdentity ri: identities) {
			if (ri.getRemoteID().getID().equals(identityID)) {
				return Optional.of(ri);
			}
		}
		return Optional.absent();
	}

	// assumes inputs have been checked and the user exists
	private void addPolicyIDs(final UserName user, final Set<PolicyID> pids)
			throws AuthStorageException {
		if (pids.isEmpty()) {
			return;
		}
		try {
			storage.addPolicyIDs(user, pids);
		} catch (NoSuchUserException e) {
			throw new AuthStorageException(
					"Something is very broken. User should exist but doesn't: "
							+ e.getMessage(), e);
		}
	}
	
	/** Remove a policy ID from all users. Primarily used to remove policy IDs that may have been
	 * added in error.
	 * @param token the user's token
	 * @param policyID the policyID to remove.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws UnauthorizedException if the user is not authorized to remove policy IDs or the
	 * token is not a login token.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 */
	public void removePolicyID(final IncomingToken token, final PolicyID policyID)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException {
		nonNull(policyID, "policyID");
		getUser(token, set(TokenType.LOGIN), Role.ADMIN);
		storage.removePolicyID(policyID);
	}
	
	/** Continue the local portion of an OAuth2 link flow after redirection from a 3rd party
	 * identity provider.
	 * 
	 * Unlike {@link #link(IncomingToken, String, String)} this method never links immediately
	 * nor does it check the state of the user to ensure linking is allowed.
	 * 
	 * A temporary token is returned that is associated with the
	 * state of the link request. This token can be used to retrieve the link state via
	 * {@link #getLinkState(IncomingToken, IncomingToken)}.
	 * 
	 * In some cases, this method will have
	 * been called after a redirect from a 3rd party identity provider, and as such, the link
	 * flow is not under the control of any UI elements at that point. Hence, the method continues
	 * if no accounts are available for linking, and an error thrown in later stages of the
	 * linking process. The state is stored so the user can be redirected to the appropriate
	 * UI element, which can then retrieve the link state and continue. A secondary point is that
	 * the URL will contain the identity provider authcode, and so the user should be redirected
	 * to a new URL that does not contain said authcode as soon as possible.
	 * 
	 * @param provider the name of the identity provider that is servicing the link request.
	 * @param authcode the authcode provided by the provider.
	 * @return a temporary token.
	 * @throws MissingParameterException if the authcode is missing.
	 * @throws IdentityRetrievalException if an error occurred when trying to retrieve identities
	 * from the provider.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws NoSuchIdentityProviderException if there is no provider by the given name.
	 */
	public TemporaryToken link(
			final String provider,
			final String authcode)
			throws InvalidTokenException, AuthStorageException,
			MissingParameterException, IdentityRetrievalException,
			NoSuchIdentityProviderException {
		final Set<RemoteIdentity> ids = getLinkCandidates(getIdentityProvider(provider), authcode);
		/* Don't throw an error if ids are empty since an auth UI is not controlling the call in
		 * some cases - this call is almost certainly the result of a redirect from a 3rd party
		 * provider. Any controllable error should be thrown when the process flow is back
		 * under the control of the primary auth UI.
		 */
		return storeIdentitiesTemporarily(ids, LINK_TOKEN_LIFETIME_MS);
	}
	
	private TemporaryToken storeIdentitiesTemporarily(
			final Set<RemoteIdentity> ids,
			final int tokenLifeTimeMS)
			throws AuthStorageException {
		final TemporaryToken tt = new TemporaryToken(randGen.randomUUID(),
				randGen.getToken(), clock.instant(), tokenLifeTimeMS);
		storage.storeIdentitiesTemporarily(tt.getHashedToken(), ids);
		return tt;
	}

	private Set<RemoteIdentity> getLinkCandidates(
			final IdentityProvider idp,
			final String authcode)
			throws NoSuchIdentityProviderException, AuthStorageException,
			MissingParameterException, IdentityRetrievalException {
		if (authcode == null || authcode.trim().isEmpty()) {
			throw new MissingParameterException("authorization code");
		}
		final Set<RemoteIdentity> ris = idp.getIdentities(authcode, true);
		filterLinkCandidates(ris);
		return ris;
	}
	
	/** Continue the local portion of an OAuth2 link flow after redirection from a 3rd party
	 * identity provider.
	 * If the information returned from the identity provider allows the link to occur
	 * immediately, the account is linked to the remote identity immediately.
	 * 
	 * If user interaction is required, a temporary token is returned that is associated with the
	 * state of the link request. This token can be used to retrieve the link state via
	 * {@link #getLinkState(IncomingToken, IncomingToken)}.
	 * 
	 * In some cases, this method will have
	 * been called after a redirect from a 3rd party identity provider, and as such, the link
	 * flow is not under the control of any UI elements at that point. Hence, if the link cannot
	 * proceed immediately, the state is stored so the user can be redirected to the appropriate
	 * UI element, which can then retrieve the link state and continue. A secondary point is that
	 * the URL will contain the identity provider authcode, and so the user should be redirected
	 * to a new URL that does not contain said authcode as soon as possible.
	 * 
	 * @param token the user's token.
	 * @param provider the name of the identity provider that is servicing the link request.
	 * @param authcode the authcode provided by the provider.
	 * @return a temporary token if required.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws MissingParameterException if the authcode is missing.
	 * @throws IdentityRetrievalException if an error occurred when trying to retrieve identities
	 * from the provider.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws NoSuchIdentityProviderException if there is no provider by the given name.
	 * @throws LinkFailedException if the user is a local user.
	 * @throws DisabledUserException if the user account is disabled.
	 * @throws UnauthorizedException if the token is not a login token.
	 */
	public LinkToken link(
			final IncomingToken token,
			final String provider,
			final String authcode)
			throws InvalidTokenException, AuthStorageException,
				MissingParameterException, IdentityRetrievalException,
				LinkFailedException, NoSuchIdentityProviderException, DisabledUserException,
				UnauthorizedException {
		final IdentityProvider idp = getIdentityProvider(provider);
		 // UI shouldn't allow disabled users to link
		final AuthUser u = getUser(token, set(TokenType.LOGIN));
		if (u.isLocal()) {
			// the ui shouldn't allow local users to link accounts, so ok to throw this
			throw new LinkFailedException("Cannot link identities to local accounts");
		}
		final Set<RemoteIdentity> ids = getLinkCandidates(idp, authcode);
		/* Don't throw an error if ids are empty since an auth UI is not controlling the call in
		 * some cases - this call is almost certainly the result of a redirect from a 3rd party
		 * provider. Any controllable error should be thrown when the process flow is back
		 * under the control of the primary auth UI.
		 */
		final LinkToken lt;
		final ProviderConfig pc = cfg.getAppConfig().getProviderConfig(idp.getProviderName());
		if (ids.size() == 1 && !pc.isForceLinkChoice()) {
			lt = getLinkToken(idp, u, ids.iterator().next());
		} else { // will store an ID set if said set is empty.
			final TemporaryToken tt = storeIdentitiesTemporarily(ids, LINK_TOKEN_LIFETIME_MS);
			if (ids.isEmpty()) {
				lt = new LinkToken(tt, new LinkIdentities(u, idp.getProviderName()));
			} else {
				lt = new LinkToken(tt, new LinkIdentities(u, ids));
			}
		}
		return lt;
	}

	// expects that u is not a local user. Will throw link failed if so.
	// will store empty identity set if identity is already linked.
	private LinkToken getLinkToken(
			final IdentityProvider idp,
			final AuthUser u,
			final RemoteIdentity remoteIdentity)
			throws AuthStorageException, LinkFailedException {
		try {
			storage.link(u.getUserName(), remoteIdentity);
			return new LinkToken();
		} catch (NoSuchUserException e) {
			throw new AuthStorageException(
					"User unexpectedly disappeared from the database", e);
		} catch (IdentityLinkedException e) {
			// well, crap. race condition and now there are no link candidates left.
			final TemporaryToken tt = storeIdentitiesTemporarily(Collections.emptySet(),
					LINK_TOKEN_LIFETIME_MS);
			return new LinkToken(tt, new LinkIdentities(u, idp.getProviderName()));
		}
	}

	private void filterLinkCandidates(final Set<? extends RemoteIdentity> rids)
			throws AuthStorageException {
		final Iterator<? extends RemoteIdentity> iter = rids.iterator();
		while (iter.hasNext()) {
			if (storage.getUser(iter.next()).isPresent()) {
				iter.remove();
			}
		}
	}
	
	/** Get the current state of a linking process associated with a temporary token.
	 * This method is expected to be called after {@link #link(IncomingToken, String, String)} or
	 * {@link #link(String, String)}.
	 * After user interaction is completed, the link can be completed by calling
	 * {@link #link(IncomingToken, IncomingToken, String)} or
	 * {@link #linkAll(IncomingToken, IncomingToken)}.
	 * 
	 * @param token the user's token.
	 * @param linktoken the temporary token associated with the link state.
	 * @return the state of the linking process.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws InvalidTokenException if either token is invalid.
	 * @throws LinkFailedException if the user is a local user or there are no available identities
	 * to link.
	 * @throws DisabledUserException if the user is disabled.
	 * @throws UnauthorizedException if the token is not a login token.
	 */
	public LinkIdentities getLinkState(
			final IncomingToken token,
			final IncomingToken linktoken)
			throws InvalidTokenException, AuthStorageException,
			LinkFailedException, DisabledUserException, UnauthorizedException {
		final AuthUser u = getUser(token, set(TokenType.LOGIN));
		if (u.isLocal()) {
			throw new LinkFailedException("Cannot link identities to local accounts");
		}
		final Set<RemoteIdentity> ids = getTemporaryIdentities(linktoken);
		filterLinkCandidates(ids);
		if (ids.isEmpty()) {
			throw new LinkFailedException("All provided identities are already linked");
		}
		return new LinkIdentities(u, ids);
	}

	/** Complete the OAuth2 account linking process by linking one identity to the current user.
	 * 
	 * This method is expected to be called after
	 * {@link #getLinkState(IncomingToken, IncomingToken)}.
	 * 
	 * @param token the user's token.
	 * @param linktoken a temporary token associated with the link process state.
	 * @param identityID the id of the remote identity to link to the user's account. This identity
	 * must be included in the link state associated with the temporary token. 
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws LinkFailedException if the id is not included in
	 * the link state associated with the temporary token or the user is a local user.
	 * @throws IdentityLinkedException if the identity is already linked to another user.
	 * @throws DisabledUserException if the user is disabled.
	 * @throws UnauthorizedException if the token is not a login token.
	 * @throws InvalidTokenException if either token is invalid.
	 * @throws MissingParameterException if the identity ID is null or the empty string.
	 */
	public void link(
			final IncomingToken token,
			final IncomingToken linktoken,
			final String identityID)
			throws AuthStorageException, LinkFailedException, DisabledUserException,
				InvalidTokenException, IdentityLinkedException, UnauthorizedException,
				MissingParameterException {
		final AuthUser au = getUser(token, set(TokenType.LOGIN)); // checks user isn't disabled
		if (au.isLocal()) {
			throw new LinkFailedException("Cannot link identities to local accounts");
		}
		final Set<RemoteIdentity> ids = getTemporaryIdentities(linktoken);
		final Optional<RemoteIdentity> ri = getIdentity(identityID, ids);
		if (!ri.isPresent()) {
			throw new LinkFailedException(String.format("Not authorized to link identity %s",
					identityID));
		}
		link(au.getUserName(), ri.get());
	}
	
	/** Complete the OAuth2 account linking process by linking all available identities to the
	 * current user.
	 * 
	 * This method is expected to be called after
	 * {@link #getLinkState(IncomingToken, IncomingToken)}.
	 * 
	 * @param token the user's token.
	 * @param linkToken a temporary token associated with the link process state.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws LinkFailedException if the user is a local user.
	 * @throws DisabledUserException if the user is disabled.
	 * @throws UnauthorizedException if the token isn't a login token.
	 * @throws InvalidTokenException if either token is invalid.
	 */
	public void linkAll(final IncomingToken token, final IncomingToken linkToken)
			throws InvalidTokenException, AuthStorageException, DisabledUserException,
			UnauthorizedException, LinkFailedException {
		final AuthUser au = getUser(token, set(TokenType.LOGIN)); // checks user isn't disabled
		if (au.isLocal()) {
			throw new LinkFailedException("Cannot link identities to local accounts");
		}
		final Set<RemoteIdentity> identities = getTemporaryIdentities(linkToken);
		filterLinkCandidates(identities);
		link(au.getUserName(), identities);
	}
	
	private void link(final UserName userName, final RemoteIdentity id)
			throws AuthStorageException, IdentityLinkedException {
		link(userName, new HashSet<>(Arrays.asList(id)), true);
	}

	private void link(final UserName userName, final Set<RemoteIdentity> identities)
			throws AuthStorageException {
		try {
			link(userName, identities, false);
		} catch (IdentityLinkedException e) {
			// don't care if we miss an identity in this context. This catch block is here simply
			// to avoid having the checked exception in the throws clause
		}
	}
	
	// assumes user is not local, and that the user exists
	private void link(
			final UserName userName,
			final Set<RemoteIdentity> identities,
			final boolean throwExceptionIfIdentityLinked)
			throws AuthStorageException, IdentityLinkedException {
		for (final RemoteIdentity ri: identities) {
			// could make a bulk op, but probably not necessary. Wait for now.
			try {
				storage.link(userName, ri);
			} catch (NoSuchUserException e) {
				throw new AuthStorageException("User magically disappeared from database: " +
						userName.getName(), e);
			} catch (IdentityLinkedException e) {
				if (throwExceptionIfIdentityLinked) {
					throw e;
				}
			} catch (LinkFailedException e) {
				throw new RuntimeException(
						"Programming error: this method should not be called on a local user", e);
			}
		}
	}

	/** Remove a remote identity from a user account.
	 * @param token the user's token.
	 * @param identityID the ID of the remote identity to remove.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws UnLinkFailedException if the user has only one identity or is a local user.
	 * @throws DisabledUserException if the user is disabled.
	 * @throws UnauthorizedException if the token is not a login token.
	 * @throws NoSuchIdentityException if the user does not possess the identity.
	 * @throws MissingParameterException if the identity id is null or the empty string. 
	 */
	public void unlink(
			final IncomingToken token,
			final String identityID)
			throws InvalidTokenException, AuthStorageException, UnLinkFailedException,
			DisabledUserException, UnauthorizedException, NoSuchIdentityException,
			MissingParameterException {
		checkString(identityID, "identityID");
		final AuthUser au = getUser(token, set(TokenType.LOGIN));
		if (au.isLocal()) {
			throw new UnLinkFailedException("Local users don't have remote identities");
		}
		try {
			storage.unlink(au.getUserName(), identityID);
		} catch (NoSuchUserException e) {
			throw new AuthStorageException("User magically disappeared from database: " +
					au.getUserName().getName());
		}
		
	}

	/** Update a user's details.
	 * @param token the user's token.
	 * @param update the update.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws UnauthorizedException if the token is not a login token.
	 */
	public void updateUser(
			final IncomingToken token,
			final UserUpdate update)
			throws InvalidTokenException, AuthStorageException, UnauthorizedException {
		nonNull(update, "update");
		if (!update.hasUpdates()) {
			return; //noop
		}
		final StoredToken ht = getToken(token, set(TokenType.LOGIN));
		try {
			storage.updateUser(ht.getUserName(), update);
		} catch (NoSuchUserException e) {
			throw new RuntimeException("There seems to be an error in the " +
					"storage system. Token was valid, but no user", e);
		}
	}

	/** Disable an account.
	 * @param token a token for a user with the administrator, create administrator, or root
	 * role.
	 * @param userName the user name of the account to disable.
	 * @param reason the reason the account was disabled.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws UnauthorizedException if the user account associated with the token doesn't have
	 * the appropriate role, or if any user other than the root user attempts to disable the root
	 * account, or the token is not a login token.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws IllegalParameterException if the reason is more than 1000 Unicode code points.
	 * @throws MissingParameterException if the reason is null or the empty string.
	 * @throws NoSuchUserException if the specified user doesn't exist.
	 */
	public void disableAccount(
			final IncomingToken token,
			final UserName userName,
			final String reason)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException,
			IllegalParameterException, NoSuchUserException, MissingParameterException {
		nonNull(userName, "userName");
		checkString(reason, "reason", 1000);
		final AuthUser admin = getUser(token, set(TokenType.LOGIN),
				Role.ROOT, Role.CREATE_ADMIN, Role.ADMIN);
		if (userName.isRoot() && !admin.isRoot()) {
			throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
					"Only the root user can disable the root account");
		}
		storage.deleteTokens(userName); //not really necessary but doesn't hurt
		storage.disableAccount(userName, admin.getUserName(), reason);
		/* there's a tiny chance a login could be in process right now and have have passed the
		 * disabled check, and then have the token created after the next line, but that's
		 * so improbable I'm not going to worry about it
		 * The getUser method checks to see if a user is disabled and if so deletes their tokens
		 * as well as a backup
		 */
		storage.deleteTokens(userName);
	}
	
	/** Enable an account.
	 * @param token a token for a user with the administrator, create administrator, or root
	 * role.
	 * @param userName the user name of the account to enable.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws UnauthorizedException if the user account associated with the token doesn't have
	 * the appropriate role, or if the user to be enabled is the root user, or the token is not a
	 * login token.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws NoSuchUserException if the specified user doesn't exist.
	 */
	public void enableAccount(final IncomingToken token, final UserName userName)
			throws UnauthorizedException, InvalidTokenException, AuthStorageException,
				NoSuchUserException {
		nonNull(userName, "userName");
		final AuthUser admin = getUser(token, set(TokenType.LOGIN),
				Role.ROOT, Role.CREATE_ADMIN, Role.ADMIN);
		if (userName.isRoot()) {
			throw new UnauthorizedException(ErrorType.UNAUTHORIZED,
					"The root user cannot be enabled via this method");
		}
		storage.enableAccount(userName, admin.getUserName());
	}
	
	/** Update the server configuration.
	 * @param token a token for a user with the administrator role.
	 * @param acs the new server configuration.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws UnauthorizedException if the user account associated with the token doesn't have
	 * the appropriate role or the token is not a login token.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws NoSuchIdentityProviderException if a provider specified in the new configuration
	 * is not supported by this authentication instance.
	 */
	public <T extends ExternalConfig> void updateConfig(
			final IncomingToken token,
			final AuthConfigSet<T> acs)
			throws InvalidTokenException, UnauthorizedException,
			AuthStorageException, NoSuchIdentityProviderException {
		nonNull(acs, "acs");
		getUser(token, set(TokenType.LOGIN), Role.ADMIN);
		for (final String provider: acs.getCfg().getProviders().keySet()) {
			// since idProviderSet is case insensitive
			final IdentityProvider idp = idProviderSet.get(provider);
			if (idp == null || !idp.getProviderName().equals(provider)) {
				throw new NoSuchIdentityProviderException(provider);
			}
		}
		storage.updateConfig(acs, true);
		cfg.updateConfig();
	}
	
	/** Gets the authentication configuration.
	 * @param token a token for a user with the administrator role.
	 * @param mapper a mapper for the external configuration.
	 * @return the authentication configuration.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws UnauthorizedException if the user account associated with the token doesn't have
	 * the appropriate role or if the token is not a login token.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws ExternalConfigMappingException if the mapper failed to map the external
	 * configuration into a class.
	 */
	public <T extends ExternalConfig> AuthConfigSet<T> getConfig(
			final IncomingToken token,
			final ExternalConfigMapper<T> mapper)
			throws InvalidTokenException, UnauthorizedException,
			AuthStorageException, ExternalConfigMappingException {
		nonNull(mapper, "mapper");
		getUser(token, set(TokenType.LOGIN), Role.ADMIN);
		final AuthConfigSet<CollectingExternalConfig> acs = cfg.getConfig();
		return new AuthConfigSet<T>(acs.getCfg(),
				mapper.fromMap(acs.getExtcfg().toMap()));
	}
	
	/** Returns the suggested cache time for tokens.
	 * @return the suggested cache time.
	 * @throws AuthStorageException if an error occurred accessing the storage system. 
	 */
	public long getSuggestedTokenCacheTime() throws AuthStorageException {
		return cfg.getAppConfig().getTokenLifetimeMS(TokenLifetimeType.EXT_CACHE);
	}
	
	/** Get the external configuration without providing any credentials.
	 * 
	 * This method should not be exposed in a public API.
	 * 
	 * @param mapper a mapper for the external configuration.
	 * @return the external configuration.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws ExternalConfigMappingException if the mapper failed to map the external
	 * configuration into a class.
	 */
	public <T extends ExternalConfig> T getExternalConfig(
			final ExternalConfigMapper<T> mapper)
			throws AuthStorageException, ExternalConfigMappingException {
		nonNull(mapper, "mapper");
		final AuthConfigSet<CollectingExternalConfig> acs = cfg.getConfig();
		return mapper.fromMap(acs.getExtcfg().toMap());
	}

	/** Imports a user from an external service without requiring credentials.
	 * 
	 * Do not expose this method in a public API.
	 * 
	 * @param userName the user name for the user.
	 * @param remoteIdentity the remote identity to link to the new user.
	 * @throws UserExistsException if the user name is already in use.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws IdentityLinkedException if the identity is already linked to a user.
	 */
	public void importUser(final UserName userName, final RemoteIdentity remoteIdentity)
			throws UserExistsException, AuthStorageException, IdentityLinkedException {
		nonNull(userName, "userName");
		nonNull(remoteIdentity, "remoteIdentity");
		DisplayName dn;
		try { // hacky, but eh. Python guys will like it though
			dn = new DisplayName(remoteIdentity.getDetails().getFullname());
		} catch (IllegalParameterException | MissingParameterException e) {
			dn = UNKNOWN_DISPLAY_NAME;
		}
		EmailAddress email;
		try {
			email = new EmailAddress(remoteIdentity.getDetails().getEmail());
		} catch (IllegalParameterException | MissingParameterException e) {
			email = EmailAddress.UNKNOWN;
		}
		try {
			storage.createUser(NewUser.getBuilder(userName, dn, clock.instant(), remoteIdentity)
					.withEmailAddress(email).build());
		} catch (NoSuchRoleException e) {
			throw new RuntimeException("didn't supply any roles", e);
		}
	}
	
	@SafeVarargs
	public static <T> Set<T> set(T... objects) {
		return new HashSet<T>(Arrays.asList(objects));
	}
}
