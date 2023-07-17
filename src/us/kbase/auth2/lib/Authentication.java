package us.kbase.auth2.lib;

import static java.util.Objects.requireNonNull;
import static us.kbase.auth2.lib.Utils.checkString;
import static us.kbase.auth2.lib.Utils.checkStringNoCheckedException;
import static us.kbase.auth2.lib.Utils.clear;
import static us.kbase.auth2.lib.Utils.noNulls;

import java.net.URI;
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
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.lang3.ArrayUtils;
import org.slf4j.LoggerFactory;

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
import us.kbase.auth2.lib.TemporarySessionData.Operation;
import us.kbase.auth2.lib.config.AuthConfig;
import us.kbase.auth2.lib.config.AuthConfigSet;
import us.kbase.auth2.lib.config.AuthConfigSetWithUpdateTime;
import us.kbase.auth2.lib.config.AuthConfigUpdate;
import us.kbase.auth2.lib.config.AuthConfigUpdate.Builder;
import us.kbase.auth2.lib.config.AuthConfigUpdate.ProviderUpdate;
import us.kbase.auth2.lib.config.CollectingExternalConfig;
import us.kbase.auth2.lib.config.ExternalConfig;
import us.kbase.auth2.lib.config.ExternalConfigMapper;
import us.kbase.auth2.lib.config.AuthConfig.ProviderConfig;
import us.kbase.auth2.lib.config.AuthConfig.TokenLifetimeType;
import us.kbase.auth2.lib.config.CollectingExternalConfig.CollectingExternalConfigMapper;
import us.kbase.auth2.lib.config.ConfigAction.Action;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.exceptions.AuthenticationException;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.LinkFailedException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchEnvironmentException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;
import us.kbase.auth2.lib.exceptions.NoSuchLocalUserException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.PasswordMismatchException;
import us.kbase.auth2.lib.exceptions.TestModeException;
import us.kbase.auth2.lib.exceptions.IdentityProviderErrorException;
import us.kbase.auth2.lib.exceptions.UnLinkFailedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
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
 * Handles creating accounts, login and un/linking accounts via OAuth2 flow, creating, deleting, and
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
	//TODO TEST LOG test logging on startup and log appropriate startup messages
	//TODO ZZLATER EMAIL validate email address by sending an email
	//TODO ZLATER LOG Make a way to note that an exception stack trace shouldn't be logged - usually for unauthorized exceptions
	//TODO ZLATER SCOPES configure scopes via ui
	//TODO ZLATER SCOPES configure scope on login via ui
	//TODO ZLATER SCOPES restricted scopes - allow for specific roles or users (or for specific clients via oauth2)
	//TODO ZLATER DEPLOY jetty should start app immediately & fail if app fails - can't figure out how to do this
	//TODO SECURITY keep track of logins over last X seconds, lock account for Y seconds after Z failures
	//TODO ZLATER USER_INPUT check for obscene/offensive content and reject
	//TODO CODE code analysis https://www.codacy.com/
	//TODO CODE code analysis https://find-sec-bugs.github.io/
	//TODO ZLATER POLICYIDS maintain admin settable list of required policy IDs, check on login & force choice page if missing. fail login or create if missing. Return missing with choice data
	//TODO TEST test with gzip compression in header
	
	//TODO DOCS better API docs. Also document JSON structures for HTML endpoints.
	
	private static final int LINK_TOKEN_LIFETIME_MS = 10 * 60 * 1000;
	private static final int LOGIN_TOKEN_LIFETIME_MS = 30 * 60 * 1000;
	private static final int MAX_RETURNED_USERS = 10000;
	private static final int TEMP_PWD_LENGTH = 10;
	private static final int TEST_MODE_DATA_LIFETIME_MS = 60 * 60 * 1000; // 1 hr
	
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
	private final ExternalConfig defaultExternalConfig;
	private final boolean testMode;
	
	// note that this value is supposed to be a constant, but is mutable for testing purposes.
	// do not make it mutable for any other reason.
	private int cfgUpdateIntervalMillis = 30000;
	
	/** Create a new Authentication instance.
	 * @param storage the storage system to use for information persistence.
	 * @param identityProviderSet the set of identity providers that are supported for standard
	 * accounts. E.g. Google, Globus, etc.
	 * @param defaultExternalConfig the external configuration default settings. Any settings
	 * that do not already exist in the storage system will be persisted. Pre-existing settings
	 * are not overwritten.
	 * @param testMode true to start the system with test mode enabled.
	 * @throws StorageInitException if the storage system cannot be accessed.
	 */
	public Authentication(
			final AuthStorage storage,
			final Set<IdentityProvider> identityProviderSet,
			final ExternalConfig defaultExternalConfig,
			final boolean testMode)
			throws StorageInitException {
		this(storage,
				identityProviderSet,
				defaultExternalConfig,
				testMode,
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
			final boolean testMode,
			final RandomDataGenerator randGen,
			final Clock clock)
			throws StorageInitException {
		this.testMode = testMode;
		this.clock = clock;
		this.randGen = randGen;
		try {
			pwdcrypt = new PasswordCrypt();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("This should be impossible", e);
		}
		requireNonNull(storage, "storage");
		requireNonNull(defaultExternalConfig, "defaultExternalConfig");
		this.defaultExternalConfig = defaultExternalConfig;
		this.storage = storage;
		setUpIdentityProviders(identityProviderSet);
		final AuthConfigUpdate<ExternalConfig> acu = buildDefaultConfig();
		try {
			storage.updateConfig(acu, false);
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

	private void setUpIdentityProviders(final Set<IdentityProvider> identityProviderSet) {
		requireNonNull(identityProviderSet, "identityProviderSet");
		noNulls(identityProviderSet, "Null identity provider in set");
		if (identityProviderSet.isEmpty()) {
			return;
		}
		final IdentityProvider prov = identityProviderSet.iterator().next();
		for (final IdentityProvider idp: identityProviderSet) {
			requireNonNull(idp.getProviderName(), "provider name");
			if (!idp.getEnvironments().equals(prov.getEnvironments())) {
				throw new IllegalArgumentException(String.format(
						"Provider %s environments %s do not match provider %s environments %s",
						prov.getProviderName(), prov.getEnvironments(),
						idp.getProviderName(), idp.getEnvironments()));
			}
			if (idProviderSet.containsKey(idp.getProviderName())) { // case insensitive
				throw new IllegalArgumentException("Duplicate provider name: " +
						idp.getProviderName());
			}
			idProviderSet.put(idp.getProviderName(), idp);
		}
	}
	
	// for test purposes. Resets the next update time to be the previous update + millis.
	@SuppressWarnings("unused")
	private void setConfigUpdateInterval(int millis) {
		final Instant prevUpdate = cfg.getNextUpdateTime();
		final Instant newUpdate = prevUpdate.minusMillis(cfgUpdateIntervalMillis)
				.plusMillis(millis);
		cfgUpdateIntervalMillis = millis;
		cfg.setNextUpdateTime(newUpdate);
	}
	
	/* Caches the configuration to avoid pulling the configuration from the storage system
	 * on every request. Synchronized to prevent multiple storage accesses for one update.
	 */
	private class ConfigManager {
	
		private AuthConfigSet<CollectingExternalConfig> cfg;
		private Instant nextConfigUpdate;
		
		public ConfigManager(final AuthStorage storage)
				throws AuthStorageException {
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
			nextConfigUpdate = Instant.now().plusMillis(cfgUpdateIntervalMillis);
		}
	}
	
	private void logInfo(final String format, final Object... params) {
		LoggerFactory.getLogger(getClass()).info(format, params);
	}
	
	private void logErr(final String format, final Object... params) {
		LoggerFactory.getLogger(getClass()).error(format, params);
	}
	
	private static class OpReqs {
		
		public final String format;
		public final Object[] args;
		
		// at least one is required for the operation, empty = no roles required
		public final Set<Role> requiredRoles = new TreeSet<>();
		
		// empty = any token type ok
		public final Set<TokenType> allowedTokenTypes = new TreeSet<>();
		
		public OpReqs(final String operation, final Object... args) {
			this.format = operation;
			this.args = args;
		}
		
		public OpReqs roles(final Role... roles) {
			for (final Role r: roles) {
				requiredRoles.add(r);
			}
			return this;
		}
		
		public OpReqs types(final TokenType... types) {
			for (final TokenType t: types) {
				allowedTokenTypes.add(t);
			}
			return this;
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
	 * @throws IllegalPasswordException if the supplied password is illegal.
	 */
	public void createRoot(final Password pwd)
			throws AuthStorageException, IllegalPasswordException {
		requireNonNull(pwd, "pwd");
		try {
			pwd.checkValidity();
		} catch (IllegalPasswordException e) {
			pwd.clear();
			throw e;
		}
		final char[] pwd_copy = pwd.getPassword();
		pwd.clear();
		final byte[] salt = randGen.generateSalt();
		final byte[] passwordHash = pwdcrypt.getEncryptedPassword(pwd_copy, salt);
		Password.clearPasswordArray(pwd_copy);
		try {
			final DisplayName dn;
			try {
				dn = new DisplayName("root");
			} catch (IllegalParameterException | MissingParameterException e) {
				throw new RuntimeException("This is impossible", e);
			}
			final LocalUser root = LocalUser.getLocalUserBuilder(
					UserName.ROOT, randGen.randomUUID(), dn, clock.instant()).build();
			try {
				storage.createLocalUser(root, new PasswordHashAndSalt(passwordHash, salt));
				// only way to avoid a race condition. Checking existence before creating user
				// means if user is added between check and update update will fail
				logInfo("created root user");
			} catch (UserExistsException uee) {
				try {
					storage.changePassword(
							UserName.ROOT, new PasswordHashAndSalt(passwordHash, salt), false);
					logInfo("changed root user password");
					if (storage.getUser(UserName.ROOT).isDisabled()) {
						storage.enableAccount(UserName.ROOT, UserName.ROOT);
						logInfo("enabled root user");
					}
				} catch (NoSuchUserException nsue) {
					throw new RuntimeException("OK. This is really bad. I give up.", nsue);
				}
			} catch (NoSuchRoleException e) {
				throw new RuntimeException("didn't supply any roles", e);
			}
		} finally {
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
		requireNonNull(userName, "userName");
		requireNonNull(displayName, "displayName");
		requireNonNull(email, "email");
		final AuthUser admin = getUser(adminToken,
				new OpReqs("create local user {}", userName.getName())
						.types(TokenType.LOGIN).roles(Role.ROOT, Role.CREATE_ADMIN, Role.ADMIN));
		if (userName.isRoot()) {
			logErr("User {} attempted to create ROOT user and was thwarted",
					admin.getUserName().getName());
			throw new UnauthorizedException("Cannot create ROOT user");
		}
		Password pwd = null;
		char[] pwd_copy = null;
		byte[] salt = null;
		byte[] passwordHash = null;
		try {
			pwd = new Password(randGen.getTemporaryPassword(TEMP_PWD_LENGTH));
			salt = randGen.generateSalt();
			pwd_copy = pwd.getPassword();
			passwordHash = pwdcrypt.getEncryptedPassword(pwd_copy, salt);
			final LocalUser lu = LocalUser.getLocalUserBuilder(
					userName, randGen.randomUUID(), displayName, clock.instant())
					.withEmailAddress(email).withForceReset(true).build();
			storage.createLocalUser(lu, new PasswordHashAndSalt(passwordHash, salt));
			logInfo("Local user {} created by admin {}",
					userName.getName(), admin.getUserName().getName());
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
	 * @param tokenCtx the context under which the token will be created.
	 * @return the result of the login attempt.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws PasswordMismatchException if the username and password do not match.
	 * @throws DisabledUserException if the user is disabled.
	 * @throws UnauthorizedException if the user is not an admin and non-admin login is disabled.
	 */
	public LocalLoginResult localLogin(
			final UserName userName,
			final Password password,
			final TokenCreationContext tokenCtx)
			throws AuthStorageException, PasswordMismatchException, DisabledUserException,
				UnauthorizedException {
		requireNonNull(tokenCtx, "tokenCtx");
		final LocalUser u = getLocalUser(userName, password);
		if (u.isPwdResetRequired()) {
			logInfo("Local user {} log in attempt. Password reset is required",
					userName.getName());
			return new LocalLoginResult(u.getUserName());
		}
		return new LocalLoginResult(login(u.getUserName(), tokenCtx));
	}

	private LocalUser getLocalUser(final UserName userName, final Password password)
			throws AuthStorageException, PasswordMismatchException, DisabledUserException,
				UnauthorizedException {
		requireNonNull(password, "password");
		final char[] pwd_copy = password.getPassword(); // no way to test this is cleared
		password.clear();
		final LocalUser u;
		PasswordHashAndSalt creds = null;
		try {
			requireNonNull(userName, "userName");
			try {
				creds = storage.getPasswordHashAndSalt(userName);
				if (!pwdcrypt.authenticate(pwd_copy, creds.getPasswordHash(), creds.getSalt())) {
					throw new PasswordMismatchException(userName.getName());
				}
				Password.clearPasswordArray(pwd_copy);
				creds.clear();
				u = storage.getLocalUser(userName);
			} catch (NoSuchLocalUserException e) {
				throw new PasswordMismatchException(userName.getName());
			}
			if (!cfg.getAppConfig().isLoginAllowed() && !Role.isAdmin(u.getRoles())) {
				throw new UnauthorizedException("User " + userName.getName() +
						" cannot log in because non-admin login is disabled");
			}
			if (u.isDisabled()) {
				throw new DisabledUserException(userName.getName());
			}
		} finally {
			Password.clearPasswordArray(pwd_copy);
			if (creds != null) {
				creds.clear();
			}
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
	 * @throws PasswordMismatchException if the username and password do not match.
	 * @throws DisabledUserException if the user is disabled.
	 * @throws UnauthorizedException if the user is not an admin and non-admin login is disabled.
	 * @throws IllegalPasswordException if the new password is not a legal password or if the
	 * new and old passwords are identical.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 */
	public void localPasswordChange(
			final UserName userName,
			final Password password,
			final Password pwdnew)
			throws PasswordMismatchException, DisabledUserException, UnauthorizedException,
				AuthStorageException, IllegalPasswordException {
		byte[] salt = null;
		byte[] passwordHash = null;
		try {
			requireNonNull(pwdnew, "pwdnew");
			if (pwdnew.equals(password)) {
				// note username is not verified at this point
				throw new IllegalPasswordException("Old and new passwords are identical.");
			}
			pwdnew.checkValidity();
			getLocalUser(userName, password); //checks pwd validity and nulls
			salt = randGen.generateSalt();
			final char [] pwd_copy = pwdnew.getPassword();
			pwdnew.clear();
			passwordHash = pwdcrypt.getEncryptedPassword(pwd_copy, salt);
			Password.clearPasswordArray(pwd_copy);
			storage.changePassword(userName, new PasswordHashAndSalt(passwordHash, salt), false);
			logInfo("Password change for local user " + userName.getName());
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
		requireNonNull(userName, "userName");
		final AuthUser admin = checkCanResetPassword(
				token, userName, "reset password for user {}", userName.getName());
		Password pwd = null;
		byte[] salt = null;
		byte[] passwordHash = null;
		try {
			final char[] temporaryPassword = randGen.getTemporaryPassword(TEMP_PWD_LENGTH);
			pwd = new Password(temporaryPassword);
			salt = randGen.generateSalt();
			passwordHash = pwdcrypt.getEncryptedPassword(temporaryPassword, salt);
			Password.clearPasswordArray(temporaryPassword);
			storage.changePassword(userName, new PasswordHashAndSalt(passwordHash, salt), true);
			logInfo("Admin {} changed user {}'s password", admin.getUserName().getName(),
					userName.getName());
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
	
	private AuthUser checkCanResetPassword(
			final IncomingToken token,
			final UserName userName,
			final String format,
			final Object... args)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException,
				NoSuchUserException {
		// this method is gross. rethink. ideally based on the grantable roles somehow.
		final AuthUser admin = getUser(token, new OpReqs(format, args)
				.types(TokenType.LOGIN).roles(Role.ROOT, Role.CREATE_ADMIN, Role.ADMIN)); 
		final AuthUser user;
		try {
			user = storage.getUser(userName);
		} catch (NoSuchUserException e) {
			logErr("Admin {} tried to get non-existant user {}", admin.getUserName().getName(),
					userName.getName());
			throw e;
		}
		if (!user.isLocal()) {
			logErr("Admin {} tried to get standard user {} as a local user",
					admin.getUserName().getName(), userName.getName());
			throw new NoSuchUserException(String.format(
					"%s is not a local user and has no password", userName.getName()));
		}
		if (!Role.isAdmin(user.getRoles())) {
			return admin; //ok, any admin can change a std user's pwd.
		}
		if (admin.getUserName().equals(user.getUserName())) {
			return admin; //ok, an admin can always change their own pwd.
		}
		if (admin.isRoot()) {
			return admin; //ok, duh. It's root.
		}
		if (user.isRoot()) { // already know admin isn't root, so bail out.
			logErr("Admin {} tried to reset the ROOT password", admin.getUserName().getName());
			throw new UnauthorizedException("Only root can reset root password");
		}
		// only root and the owner of an account with the CREATE_ADMIN role can change the pwd
		if (Role.CREATE_ADMIN.isSatisfiedBy(user.getRoles())) {
			logErr("Admin {} tried to reset admin with create power {}'s password",
					admin.getUserName().getName(), user.getUserName().getName());
			throw new UnauthorizedException(
					"Cannot reset password of user with create administrator role");
		}
		/* at this point we know user is a standard admin and admin is not root. That means
		 * that admin has to have CREATE_ADMIN to proceed. 
		 */
		if (!Role.CREATE_ADMIN.isSatisfiedBy(admin.getRoles())) {
			logErr("Admin {} tried to reset admin {}'s password", admin.getUserName().getName(),
					user.getUserName().getName());
			throw new UnauthorizedException(
					"Cannot reset password of user with administrator role");
		}
		return admin;
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
		requireNonNull(userName, "userName");
		final AuthUser admin = checkCanResetPassword(token, userName,
				"force password reset for user {}", userName.getName());
		storage.forcePasswordReset(userName);
		logInfo("Admin {} required user {} to reset their password on the next login",
				admin.getUserName().getName(), userName.getName());
		
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
		final AuthUser admin = getUser(token, new OpReqs("force password reset for all users")
				.types(TokenType.LOGIN).roles(Role.ROOT, Role.CREATE_ADMIN));
		storage.forcePasswordReset();
		logInfo("Admin {} required all users to reset their password on the next login",
				admin.getUserName().getName());
	}
	
	private NewToken login(final UserName userName, final TokenCreationContext tokenCtx)
			throws AuthStorageException {
		final NewToken nt = new NewToken(StoredToken.getBuilder(
					TokenType.LOGIN, randGen.randomUUID(), userName)
				.withLifeTime(clock.instant(),
						cfg.getAppConfig().getTokenLifetimeMS(TokenLifetimeType.LOGIN))
				.withContext(tokenCtx)
				.build(),
				randGen.getToken());
		storage.storeToken(nt.getStoredToken(), nt.getTokenHash());
		setLastLogin(userName);
		logInfo("Logged in user {} with token {}",
				userName.getName(), nt.getStoredToken().getId());
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

	/** Get the tokens associated with a user account associated with a possessed token.
	 * @param token a user token for the account in question.
	 * @return the tokens.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws UnauthorizedException if the token is not a login token.
	 */
	public TokenSet getTokens(final IncomingToken token)
			throws AuthStorageException, InvalidTokenException, UnauthorizedException {
		final StoredToken ht = getToken(token, new OpReqs("get tokens").types(TokenType.LOGIN));
		final TokenSet tokenSet = new TokenSet(ht, storage.getTokens(ht.getUserName()));
		logInfo("User {} accessed their tokens", ht.getUserName().getName());
		return tokenSet;
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
		requireNonNull(userName, "userName");
		final AuthUser admin = getUser(token,
				new OpReqs("get tokens for user {}", userName.getName())
				.types(TokenType.LOGIN).roles(Role.ADMIN));
		final Set<StoredToken> tokens = storage.getTokens(userName);
		logInfo("Admin {} accessed user {}'s tokens",
				admin.getUserName().getName(), userName.getName());
		return tokens;
	}

	/** Get details about a token.
	 * @param token the token in question.
	 * @return the token's details.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 */
	public StoredToken getToken(final IncomingToken token)
			throws AuthStorageException, InvalidTokenException {
		final StoredToken st = getTokenSuppressUnauthorized(token, "get token");
		logInfo("User {} accessed {} token {}", st.getUserName().getName(), st.getTokenType(),
				st.getId());
		return st;
	}

	private StoredToken getTokenSuppressUnauthorized(
			final IncomingToken token,
			final String format,
			final Object... args)
			throws InvalidTokenException, AuthStorageException {
		try {
			return getToken(token, new OpReqs(format, args));
		} catch (UnauthorizedException e) {
			throw new RuntimeException("Didn't require any particular token", e);
		}
	}
	
	// converts a no such token exception into an invalid token exception.
	private StoredToken getToken(final IncomingToken token, final OpReqs reqs)
			throws AuthStorageException, InvalidTokenException, UnauthorizedException {
		requireNonNull(token, "token");
		try {
			final Set<TokenType> allowedTypes = reqs.allowedTokenTypes;
			final StoredToken st = storage.getToken(token.getHashedToken());
			if (!allowedTypes.isEmpty() && !allowedTypes.contains(st.getTokenType())) {
				logDisallowedTokenType(st, reqs);
				throw new UnauthorizedException(st.getTokenType().getDescription() +
						" tokens are not allowed for this operation");
			}
			return st;
		} catch (NoSuchTokenException e) {
			throw new InvalidTokenException();
		}
	}

	private void logDisallowedTokenType(final StoredToken st, final OpReqs reqs) {
		
		final List<String> types = reqs.allowedTokenTypes.stream().map(r -> r.getID())
				.collect(Collectors.toList());
		final String typesStr = String.join(", ", types);
		final Object[] args = ArrayUtils.addAll(new Object[] {st.getUserName().getName(),
						st.getTokenType().getDescription(), typesStr}, reqs.args);
		logErr("User {} with token type {} attempted an operation that requires a " +
				"token type of one of [{}]: " + reqs.format, args);
	}

	/** Create a new agent, developer or service token.
	 * @param token a token for the user that wishes to create a new token.
	 * @param tokenName a name for the token.
	 * @param tokenType the type of token to create. Note that login tokens may not be created
	 * other than via logging in.
	 * @param tokenCtx the context under which the token will be created.
	 * @return the new token.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws InvalidTokenException if the provided token is not valid.
	 * @throws UnauthorizedException if the provided token is not a login token or the user does
	 * not have the role required to create the token type.
	 */
	public NewToken createToken(
			final IncomingToken token,
			final TokenName tokenName,
			final TokenType tokenType,
			final TokenCreationContext tokenCtx)
			throws AuthStorageException, InvalidTokenException, UnauthorizedException {
		requireNonNull(tokenName, "tokenName");
		requireNonNull(tokenType, "tokenType");
		requireNonNull(tokenCtx, "tokenCtx");
		if (TokenType.LOGIN.equals(tokenType)) {
			throw new IllegalArgumentException("Cannot create a login token without logging in");
		}
		// check for disabled user for all token type targets as well
		final AuthUser au = getUser(token,
				new OpReqs("create {} token", tokenType.getDescription()).types(TokenType.LOGIN));
		if (!TokenType.AGENT.equals(tokenType)) {
			final Role reqRole = TokenType.SERV.equals(tokenType) ?
					Role.SERV_TOKEN : Role.DEV_TOKEN;
			if (!reqRole.isSatisfiedBy(au.getRoles())) {
				throw new UnauthorizedException(String.format(
						"User %s is not authorized to create the %s token type.",
						au.getUserName().getName(), tokenType.getDescription()));
			}
		}
		final AuthConfig c = cfg.getAppConfig();
		final long life = c.getTokenLifetimeMS(TOKEN_LIFE_TYPE.get(tokenType));
		final UUID id = randGen.randomUUID();
		final NewToken nt = new NewToken(StoredToken.getBuilder(tokenType, id, au.getUserName())
				.withLifeTime(clock.instant(), life)
				.withContext(tokenCtx)
				.withTokenName(tokenName).build(),
				randGen.getToken());
		storage.storeToken(nt.getStoredToken(), nt.getTokenHash());
		logInfo("User {} created {} token {}", au.getUserName().getName(), tokenType, id);
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
		final AuthUser u = getUserSuppressUnauthorized(token, "get self user");
		logInfo("User {} accessed their user data", u.getUserName().getName());
		return u;
	}

	private AuthUser getUserSuppressUnauthorized(
			final IncomingToken token,
			final String format,
			final Object... args)
			throws AuthStorageException, InvalidTokenException, DisabledUserException {
		try {
			return getUser(token, new OpReqs(format, args));
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
			final OpReqs reqs)
			throws AuthStorageException, InvalidTokenException, UnauthorizedException {
		final StoredToken ht = getToken(token, reqs);
		final AuthUser u = getUser(ht.getUserName());
		if (reqs.requiredRoles.size() > 0) {
			final Set<Role> has = u.getRoles().stream().flatMap(r -> r.included().stream())
					.collect(Collectors.toSet());
			has.retainAll(reqs.requiredRoles); // intersection
			if (has.isEmpty()) {
				logUnauthorized(u.getUserName(), reqs);
				throw new UnauthorizedException();
			}
		}
		return u;
	}

	// assumes that the token has already been checked and is valid for this user.
	private AuthUser getUser(final UserName userName)
			throws AuthStorageException, DisabledUserException {
		final AuthUser u;
		try {
			u = storage.getUser(userName);
		} catch (NoSuchUserException e) {
			throw new RuntimeException("There seems to be an error in the " +
					"storage system. Token was valid, but no user", e);
		}
		if (u.isDisabled()) {
			// apparently this disabled user still has some tokens, so kill 'em all
			storage.deleteTokens(u.getUserName());
			throw new DisabledUserException(u.getUserName().getName());
		}
		return u;
	}
	
	private void logUnauthorized(final UserName name, final OpReqs reqs) {
		final List<String> roles = reqs.requiredRoles.stream()
				.map(r -> r.getID()).collect(Collectors.toList());
		final String rolesStr = String.join(", ", roles);
		final Object[] args = ArrayUtils.addAll(
				new Object[] {name.getName(), rolesStr}, reqs.args);
		logErr("User {} does not have one of the required roles [{}] for operation " + reqs.format,
				args);
		
	}

	/** Get a restricted view of a user. Typically used for one user viewing another.
	 * @param token the token of the user requesting the view.
	 * @param user the username of the user to view.
	 * @return a view of the user.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws NoSuchUserException if there is no user corresponding to the given user name or the
	 * user is disabled.
	 * @throws DisabledUserException if the requesting user is disabled.
	 */
	public ViewableUser getUser(
			final IncomingToken token,
			final UserName user)
			throws AuthStorageException, InvalidTokenException,
				NoSuchUserException, DisabledUserException {
		requireNonNull(user, "userName");
		final AuthUser requestingUser = getUserSuppressUnauthorized(token, "get viewable user");
		final AuthUser otherUser = storage.getUser(user);
		if (otherUser.isDisabled()) {
			// if requesting user was disabled a DisabledUserEx would already have been thrown
			throw new NoSuchUserException(otherUser.getUserName().getName());
		}
		final boolean sameUser = requestingUser.getUserName().equals(otherUser.getUserName());
		logInfo("User {} accessed user {}'s user data", requestingUser.getUserName().getName(),
				otherUser.getUserName().getName());
		return new ViewableUser(otherUser, sameUser);
	}

	/** Get a user as an admin.
	 * @param adminToken a token for a user with the administrator, create administrator, or root
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
		requireNonNull(userName, "userName");
		final AuthUser admin = getUser(adminToken,
				new OpReqs("get user {} as admin", userName.getName())
				.types(TokenType.LOGIN).roles(Role.ROOT, Role.CREATE_ADMIN, Role.ADMIN));
		final AuthUser user = storage.getUser(userName);
		logInfo("Admin {} accessed user {}'s user data", admin.getUserName().getName(),
				userName.getName());
		return user;
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
		requireNonNull(userNames, "userNames");
		noNulls(userNames, "Null name in userNames");
		// just check the token is valid
		getTokenSuppressUnauthorized(token, "get user display names");
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
		requireNonNull(spec, "spec");
		if (spec.hasSearchRegex()) {
			throw new UnauthorizedException("Regex search is currently for internal use only");
		}
		final AuthUser user = getUser(token, new OpReqs("search users"));
		if (!Role.isAdmin(user.getRoles())) {
			if (spec.isCustomRoleSearch() || spec.isRoleSearch()) {
				throw new UnauthorizedException("Only admins may search on roles");
			}
			if (!spec.hasSearchPrefixes()) {
				throw new UnauthorizedException("Only admins may search without a prefix");
			}
			if (spec.isRootIncluded() || spec.isDisabledIncluded()) {
				throw new UnauthorizedException(
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
		requireNonNull(suggestedUserName, "suggestedUserName");
		final Optional<UserName> target = UserName.sanitizeName(suggestedUserName);
		Optional<UserName> availableUserName = Optional.empty();
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
		// based on the only method that calls this method, if forceNumericSuffix is true,
		// the suggestedUserName will not hasNumSuffix
		if (!match && (!forceNumericSuffix || hasNumSuffix)) {
			return Optional.of(suggestedUserName);
		}
		final Set<String> names = users.keySet().stream().map(u -> u.getName())
				.collect(Collectors.toSet());
		final long start = startAt2 ? 2 : 1;
		for (long i = start; i < Long.MAX_VALUE; i++) {
			final String potential = sugStrip + i;
			if (potential.length() > UserName.MAX_NAME_LENGTH) {
				return Optional.empty();
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
		return Optional.empty();
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
		requireNonNull(tokenID, "tokenID");
		final StoredToken ht = getToken(token, new OpReqs("revoke token {}", tokenID)
				.types(TokenType.LOGIN));
		storage.deleteToken(ht.getUserName(), tokenID);
		logInfo("User {} revoked token {}", ht.getUserName().getName(), ht.getId());
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
		requireNonNull(userName, "userName");
		requireNonNull(tokenID, "tokenID");
		final AuthUser admin = getUser(token,
				new OpReqs("revoke token {} for user {}", tokenID, userName.getName())
				.types(TokenType.LOGIN).roles(Role.ADMIN));
		storage.deleteToken(userName, tokenID);
		logInfo("Admin {} revoked user {}'s token {}", admin.getUserName().getName(),
				userName.getName(), tokenID);
		
	}
	
	/** Revoke the current token. Returns an empty Optional if the token does not exist in the
	 * database, and thus there is nothing to revoke.
	 * @param token the token to be revoked.
	 * @return the revoked token, or an empty Optional.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 */
	public Optional<StoredToken> revokeToken(final IncomingToken token)
			throws AuthStorageException {
		requireNonNull(token, "token");
		StoredToken t = null;
		try {
			t = storage.getToken(token.getHashedToken());
			storage.deleteToken(t.getUserName(), t.getId());
			logInfo("User {} revoked token {}", t.getUserName().getName(), t.getId());
			return Optional.of(t);
		} catch (NoSuchTokenException e) {
			// no problem, continue
		}
		return Optional.empty();
	}
	
	/** Revoke the current token and deletes all temporary session data associated with the user.
	 * Returns an empty Optional if the token does not exist in the
	 * database, and thus there is nothing to revoke.
	 * @param token the user's token.
	 * @return the revoked token, or an empty Optional.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 */
	public Optional<StoredToken> logout(final IncomingToken token)
			throws AuthStorageException {
		/* Could assign temp data to the login token, and then just delete that temp data, but
		 * why bother. Only matters if a user is logging out and linking an account at the
		 * same time.
		 */
		requireNonNull(token, "token");
		StoredToken t = null;
		try {
			t = storage.getToken(token.getHashedToken());
			final long deleted = storage.deleteTemporarySessionData(t.getUserName());
			storage.deleteToken(t.getUserName(), t.getId());
			logInfo("User {} revoked token {} and {} temporary session instances",
					t.getUserName().getName(), t.getId(), deleted);
			return Optional.of(t);
		} catch (NoSuchTokenException e) {
			// no problem, continue
		}
		return Optional.empty();
	}

	/** Revokes all of a user's tokens.
	 * @param token the token for the user.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws UnauthorizedException if the token is not a login token.
	 */
	public void revokeTokens(final IncomingToken token)
			throws AuthStorageException, InvalidTokenException, UnauthorizedException {
		final StoredToken ht = getToken(token, new OpReqs("revoke owned tokens")
				.types(TokenType.LOGIN));
		storage.deleteTokens(ht.getUserName());
		logInfo("User {} revoked all their tokens", ht.getUserName().getName());
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
		final AuthUser admin = getUser(token, new OpReqs("revoke all tokens")
				.types(TokenType.LOGIN).roles(Role.ADMIN));
		storage.deleteTokens();
		logInfo("Admin {} revoked all tokens system wide", admin.getUserName().getName());
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
		requireNonNull(userName, "userName");
		final AuthUser admin = getUser(token,
				new OpReqs("revoke all tokens for user {}", userName.getName())
				.types(TokenType.LOGIN).roles(Role.ADMIN));
		storage.deleteTokens(userName);
		logInfo("Admin {} revoked all tokens for user {}",
				admin.getUserName().getName(), userName.getName());
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
		final StoredToken ht = getToken(token, new OpReqs("remove roles").types(TokenType.LOGIN));
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
		requireNonNull(userName, "userName");
		requireNonNull(addRoles, "addRoles");
		requireNonNull(removeRoles, "removeRoles");
		noNulls(addRoles, "Null role in addRoles");
		noNulls(removeRoles, "Null role in removeRoles");
		
		final Set<Role> intersect = new HashSet<>(addRoles);
		intersect.retainAll(removeRoles);
		if (!intersect.isEmpty()) {
			throw new IllegalParameterException(
					"One or more roles is to be both removed and added: " +
							rolesToString(intersect, r -> r.getDescription()));
		}
		if (userName.isRoot()) {
			throw new UnauthorizedException("Cannot change ROOT roles");
		}
		final AuthUser actinguser = getUser(userToken,
				new OpReqs("update roles for user {}", userName.getName()).types(TokenType.LOGIN));
		
		final Set<Role> add = new HashSet<>(addRoles);
		add.removeAll(actinguser.getGrantableRoles());
		final Set<Role> sub = new HashSet<>(removeRoles);
		sub.removeAll(actinguser.getGrantableRoles());
		
		if (!add.isEmpty()) {
			throwUnauthorizedToManageRoles(actinguser, "grant", add);
		}
		if (!sub.isEmpty() && !userName.equals(actinguser.getUserName())) {
			throwUnauthorizedToManageRoles(actinguser, "remove", sub);
		}
		storage.updateRoles(userName, addRoles, removeRoles);
		logRoleUpdate(actinguser.getUserName(), userName, addRoles, removeRoles);
	}

	private void logRoleUpdate(
			final UserName actingUser,
			final UserName user,
			final Set<Role> addRoles,
			final Set<Role> removeRoles) {
		if (!addRoles.isEmpty()) {
			logInfo("User {} added roles to user {}: {}", actingUser.getName(),
					user.getName(), rolesToString(addRoles, r -> r.getID()));
		}
		if (!removeRoles.isEmpty()) {
			logInfo("User {} removed roles from user {}: {}", actingUser.getName(),
					user.getName(), rolesToString(removeRoles, r -> r.getID()));
		}
	}

	private void throwUnauthorizedToManageRoles(
			final AuthUser actingUser,
			final String action,
			final Set<Role> roles)
			throws UnauthorizedException {
		throw new UnauthorizedException(
				String.format("User %s is not authorized to %s role(s): %s",
						actingUser.getUserName().getName(), action,
						rolesToString(roles, r -> r.getDescription())));
	}

	private String rolesToString(
			final Set<Role> roles,
			final Function<? super Role, ? extends String> mapper) {
		return String.join(", ", roles.stream().sorted().map(mapper).collect(Collectors.toList()));
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
		requireNonNull(role, "role");
		final AuthUser admin = getUser(token, new OpReqs("set custom role {}", role.getID())
				.types(TokenType.LOGIN).roles(Role.ADMIN));
		storage.setCustomRole(role);
		logInfo("Admin {} set custom role {}", admin.getUserName().getName(), role.getID());
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
		final AuthUser admin = getUser(token, new OpReqs("delete custom role {}", roleId)
				.types(TokenType.LOGIN).roles(Role.ADMIN));
		storage.deleteCustomRole(roleId);
		logInfo("Admin {} deleted custom role {}", admin.getUserName().getName(), roleId);
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
		final UserName name;
		if (forceAdmin) {
			name = getUser(token, new OpReqs("get custom roles as admin")
					.types(TokenType.LOGIN).roles(Role.ROOT, Role.CREATE_ADMIN, Role.ADMIN))
					.getUserName();
		} else {
			// check for valid token
			name = getToken(token, new OpReqs("get custom roles").types(TokenType.LOGIN))
					.getUserName();
		}
		final Set<CustomRole> customRoles = storage.getCustomRoles();
		logInfo("User {} accessed all custom roles", name.getName());
		return customRoles;
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
		requireNonNull(userName, "userName");
		requireNonNull(addRoles, "addRoles");
		requireNonNull(removeRoles, "removeRoles");
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
		final AuthUser admin = getUser(userToken,
				new OpReqs("update custom roles for user {}", userName.getName())
				.types(TokenType.LOGIN).roles(Role.ADMIN));
		storage.updateCustomRoles(userName, addRoles, removeRoles);
		logCustomRoleUpdate(admin.getUserName(), userName, addRoles, removeRoles);
	}
	
	private void logCustomRoleUpdate(
			final UserName actingUser,
			final UserName user,
			final Set<String> addRoles,
			final Set<String> removeRoles) {
		if (!addRoles.isEmpty()) {
			logInfo("Admin {} added custom roles to user {}: {}", actingUser.getName(),
					user.getName(), customRolesToString(addRoles));
		}
		if (!removeRoles.isEmpty()) {
			logInfo("Admin {} removed custom roles from user {}: {}", actingUser.getName(),
					user.getName(), customRolesToString(removeRoles));
		}
	}
	
	private String customRolesToString(final Set<String> roles) {
		return String.join(", ", roles.stream().sorted().collect(Collectors.toList()));
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
	
	
	/** Get any alternative environments that are configured for the identity providers. This
	 * method will return the list even if no identity providers are enabled.
	 * @return the alternative environment names.
	 */
	public Set<String> getEnvironments() {
		if (idProviderSet.isEmpty()) {
			return Collections.emptySet();
		}
		return idProviderSet.values().iterator().next().getEnvironments();
	}
	
	// looks up the provider, case insensitive 
	private IdentityProvider getIdentityProvider(final String provider)
			throws NoSuchIdentityProviderException, AuthStorageException,
				MissingParameterException {
		checkString(provider, "provider");
		final IdentityProvider idp = idProviderSet.get(provider);
		if (idp == null) {
			throw new NoSuchIdentityProviderException(provider);
		}
		if (!cfg.getAppConfig().getProviderConfig(idp.getProviderName()).isEnabled()) {
			throw new NoSuchIdentityProviderException(provider);
		}
		return idp;
	}
	
	/** Start the OAuth2 login process.
	 * @param lifetimeSec the lifetime of the temporary token to be returned.
	 * @param provider the name of the 3rd party identity provider to login with.
	 * @param string the auth environment in which the login is taking place, or null for the
	 * default environment.
	 * @return data to start the login process.
	 * @throws AuthStorageException if an error occurs accessing the storage system.
	 * @throws NoSuchEnvironmentException if there is no such configured environment.
	 * @throws NoSuchIdentityProviderException if there is no such configured identify provider.
	 * @throws MissingParameterException if the provider is null or whitespace only.
	 */
	public OAuth2StartData loginStart(
			final int lifetimeSec,
			final String provider,
			final String environment)
			throws NoSuchIdentityProviderException, NoSuchEnvironmentException,
				AuthStorageException, MissingParameterException {
		checkLifeTimeSec(lifetimeSec);
		final String state = randGen.getToken();
		// May want to make classes for the verifier & challenge to prevent them being swapped.
		// Since it's all in the internal logic YAGNI for now
		final String pkceVerifier = generatePKCECodeVerifier();
		final String pkceChallenge = generatePKCECodeChallenge(pkceVerifier);
		final URI target = getIdentityProvider(provider).getLoginURI(
				state, pkceChallenge, false, environment);
		final TemporarySessionData data = TemporarySessionData.create(
				randGen.randomUUID(), clock.instant(), lifetimeSec * 1000L)
				.login(state, pkceVerifier);
		final TemporaryToken tt = storeTemporarySessionData(data);
		logInfo("Created temporary login token {}", tt.getId());
		return OAuth2StartData.build(target, tt);
	}
	
	private void checkLifeTimeSec(final int lifetimeSec) {
		if (lifetimeSec < 60) {
			throw new IllegalArgumentException("lifetimeSec must be at least 60");
		}
	}
	
	private String generatePKCECodeVerifier() {
		// https://www.oauth.com/oauth2-servers/pkce/authorization-request/
		// size of 6 = 30 bytes = 240 bits = 48 chars which is > 43 required.
		// 240 bits of info seems like plenty for a random key
		return randGen.getToken(6); 
	}
	
	private String generatePKCECodeChallenge(final String codeVerifier) {
		// https://www.oauth.com/oauth2-servers/pkce/authorization-request/
		// SHA-256 hash, then Base64 URL encoded
		final String hashed = IncomingToken.hash(codeVerifier, true);
		// = is only used for padding, so safe to do a global replace
		// performance wise, right strip vs. global replace would be faster, but trivial
		// speed increase vs the oauth2 flow, db access, etc. so YAGNI
		return hashed.replace("=", "");
	}
	
	/** Continue the local portion of an OAuth2 login flow after redirection from a 3rd party
	 * identity provider in the case that the provider returned an error.
	 * @param providerError the error returned by the provider.
	 * @return A login token. In this case the token will always be a temporary token so the
	 * control flow can be returned to the UI before returning an error.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @see #login(String, String, String, TokenCreationContext)
	 */
	public LoginToken loginProviderError(final String providerError) throws AuthStorageException {
		checkStringNoCheckedException(providerError, "providerError");
		final TemporaryToken tt = storeErrorTemporarily(
				providerError, ErrorType.ID_PROVIDER_ERROR, LOGIN_TOKEN_LIFETIME_MS);
		logErr("Stored temporary token {} with login identity provider error {}",
				tt.getId(), providerError);
		return new LoginToken(tt);
	}

	/** Continue the local portion of an OAuth2 login flow after redirection from a 3rd party
	 * identity provider.
	 * If the information returned from the identity provider allows the login to occur
	 * immediately, a login token is returned.
	 * If user interaction is required, a temporary token is returned that is associated with the
	 * state of the login request. This token can be used to retrieve the login state via
	 * {@link #getLoginState(IncomingToken)}.
	 * 
	 * In most cases, this method will have
	 * been called after a redirect from a 3rd party identity provider, and as such, the login
	 * flow is not under the control of any UI elements at that point. Hence, if the login cannot
	 * proceed immediately, the state is stored so the user can be redirected to the appropriate
	 * UI element, which can then retrieve the login state and continue. A secondary point is that
	 * the URL will contain the identity provider authcode, and so the user should be redirected
	 * to a new URL that does not contain said authcode as soon as possible.
	 * 
	 * @param token the temporary token returned by the {@link #loginStart(int, String, String)}
	 * method.
	 * @param provider the name of the identity provider that is servicing the login request.
	 * @param authcode the authcode provided by the provider.
	 * @param environment the environment in which the login request is occurring. Null for the
	 * default environment.
	 * @param tokenCtx the context under which the token will be created.
	 * @param oauth2State the state value returned by the 3rd party identity provider.
	 * @return either a login token or temporary token.
	 * @throws MissingParameterException if the authcode is missing.
	 * @throws IdentityRetrievalException if an error occurred when trying to retrieve identities
	 * from the provider.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws NoSuchIdentityProviderException if there is no provider by the given name.
	 * @throws NoSuchEnvironmentException if no such environment is configured.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws AuthenticationException if the state doesn't match the expected state.
	 */
	public LoginToken login( // enough args here to start considering a builder
			final IncomingToken token,
			final String provider,
			final String authcode,
			final String environment,
			final TokenCreationContext tokenCtx,
			final String oauth2State)
			throws MissingParameterException, IdentityRetrievalException,
				AuthStorageException, NoSuchIdentityProviderException, NoSuchEnvironmentException,
				InvalidTokenException, AuthenticationException {
		requireNonNull(tokenCtx, "tokenCtx");
		checkString(authcode, "authorization code");
		final IdentityProvider idp = getIdentityProvider(provider);
		final TemporarySessionData tids = getTemporarySessionData(
				Optional.empty(), Operation.LOGINSTART, token);
		checkState(tids, oauth2State);
		storage.deleteTemporarySessionData(token.getHashedToken());
		final Set<RemoteIdentity> ris = idp.getIdentities(
				authcode, tids.getPKCECodeVerifier().get(), false, environment);
		final LoginState lstate = getLoginState(ris, Instant.MIN);
		final ProviderConfig pc = cfg.getAppConfig().getProviderConfig(idp.getProviderName());
		final LoginToken loginToken;
		if (lstate.getUsers().size() == 1 &&
				lstate.getIdentities().isEmpty() &&
				!pc.isForceLoginChoice()) {
			final UserName userName = lstate.getUsers().iterator().next();
			final AuthUser user = lstate.getUser(userName);
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
				loginToken = storeIdentitiesTemporarily(lstate);
			} else if (user.isDisabled()) {
				loginToken = storeIdentitiesTemporarily(lstate);
			} else {
				loginToken = new LoginToken(login(user.getUserName(), tokenCtx));
			}
		} else {
			// store the identities so the user can create an account or choose from more than one
			// account
			loginToken = storeIdentitiesTemporarily(lstate);
		}
		return loginToken;
	}
	
	private void checkState(final TemporarySessionData tids, final String state)
			throws AuthenticationException {
		if (!tids.getOAuth2State().get().equals(state)) {
			throw new AuthenticationException(ErrorType.AUTHENTICATION_FAILED,
					"State values do not match, this may be a CSRF attack");
		}
	}

	// ignores expiration date of login state
	private LoginToken storeIdentitiesTemporarily(final LoginState ls)
			throws AuthStorageException {
		final Set<RemoteIdentity> store = new HashSet<>(ls.getIdentities());
		ls.getUsers().stream().forEach(u -> store.addAll(ls.getIdentities(u)));
		final TemporarySessionData data = TemporarySessionData.create(
				randGen.randomUUID(), clock.instant(), LOGIN_TOKEN_LIFETIME_MS)
				.login(store);
		final TemporaryToken tt = storeTemporarySessionData(data);
		logInfo("Stored temporary token {} with {} login identities", tt.getId(), store.size());
		return new LoginToken(tt);
	}

	private TemporaryToken storeTemporarySessionData(final TemporarySessionData data)
			throws AuthStorageException {
		final String token = randGen.getToken();
		storage.storeTemporarySessionData(data, IncomingToken.hash(token));
		return new TemporaryToken(data, token);
	}

	/** Get the current state of a login process associated with a temporary token.
	 * This method is expected to be called after
	 * {@link #login(String, String, String, TokenCreationContext)}.
	 * After user interaction is completed, a new user can be created via
	 * {@link #createUser(IncomingToken, String, UserName, DisplayName, EmailAddress, Set, TokenCreationContext, boolean)}
	 * or the login can complete via
	 * {@link #login(IncomingToken, String, Set, TokenCreationContext, boolean)}.
	 * @param token the temporary token.
	 * @return the state of the login process.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws IdentityProviderErrorException if the provider reported an error when returning
	 * from the OAuth2 flow.
	 * @throws UnauthorizedException if the temporary token is not associated with any identities.
	 */
	public LoginState getLoginState(final IncomingToken token)
			throws AuthStorageException, InvalidTokenException, IdentityProviderErrorException,
				UnauthorizedException {
		final TemporarySessionData ids = getTemporarySessionData(
				Optional.empty(), Operation.LOGINIDENTS, token);
		logInfo("Accessed temporary login token {} with {} identities", ids.getId(),
				ids.getIdentities().get().size());
		return getLoginState(ids.getIdentities().get(), ids.getExpires());
	}

	private LoginState getLoginState(final Set<RemoteIdentity> ids, final Instant expires)
			throws AuthStorageException {
		final String provider = ids.iterator().next().getRemoteID().getProviderName();
		final LoginState.Builder builder = LoginState.getBuilder(provider,
				cfg.getAppConfig().isLoginAllowed(), expires);
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

	private TemporarySessionData getTemporarySessionData(
			Optional<UserName> user,
			final Operation expectedOperation,
			final IncomingToken token)
			throws AuthStorageException, IdentityProviderErrorException, InvalidTokenException {
		requireNonNull(token, "Temporary token");
		try {
			final TemporarySessionData tis = storage.getTemporarySessionData(
					token.getHashedToken());
			if (tis.hasError()) {
				final ErrorType et = tis.getErrorType().get();
				if (ErrorType.ID_PROVIDER_ERROR.equals(et)) {
					throw new IdentityProviderErrorException(tis.getError().get());
				} else {
					throw new RuntimeException("Unexpected error type " + et);
				}
			}
			if (!expectedOperation.equals(tis.getOperation())) {
				if (!user.isPresent() && tis.getUser().isPresent()) {
					user = tis.getUser();
				}
				final String err;
				final List<Object> args = new LinkedList<>();
				if (user.isPresent()) {
					err = "User {} attempted operation {} with a {} temporary token {}";
					args.add(user.get().getName());
				} else {
					err = "Operation {} was attempted with a {} temporary token {}"; 
				}
				args.addAll(Arrays.asList(expectedOperation, tis.getOperation(), tis.getId()));
				logErr(err, args.toArray());
				throw new InvalidTokenException(
						"Temporary token operation type does not match expected operation");
			}
			return tis;
		} catch (NoSuchTokenException e) {
			throw new InvalidTokenException("Temporary token");
		}
	}

	// probably need a builder for this.
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
	 * @param tokenCtx the context under which the token will be created.
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
	 * @throws IdentityProviderErrorException if the provider reported an error when returning
	 * from the OAuth2 flow.
	 */
	public NewToken createUser(
			final IncomingToken token,
			final String identityID,
			final UserName userName,
			final DisplayName displayName,
			final EmailAddress email,
			final Set<PolicyID> policyIDs,
			final TokenCreationContext tokenCtx,
			final boolean linkAll)
			throws AuthStorageException, InvalidTokenException, UserExistsException,
				UnauthorizedException, IdentityLinkedException, MissingParameterException,
				IdentityProviderErrorException {
		requireNonNull(userName, "userName");
		requireNonNull(displayName, "displayName");
		requireNonNull(email, "email");
		requireNonNull(policyIDs, "policyIDs");
		noNulls(policyIDs, "null item in policyIDs");
		requireNonNull(tokenCtx, "tokenCtx");
		if (userName.isRoot()) {
			throw new UnauthorizedException("Cannot create ROOT user");
		}
		if (!cfg.getAppConfig().isLoginAllowed()) {
			throw new UnauthorizedException("Account creation is disabled");
		}
		// allow mutation of the identity set
		final Set<RemoteIdentity> ids = new HashSet<>(
				getTemporarySessionData(Optional.empty(), Operation.LOGINIDENTS, token)
				.getIdentities().get());
		storage.deleteTemporarySessionData(token.getHashedToken());
		final Optional<RemoteIdentity> match = getIdentity(identityID, ids);
		if (!match.isPresent()) {
			throw new UnauthorizedException(String.format(
					"Not authorized to create user with remote identity %s", identityID));
		}
		final Instant now = clock.instant();
		final NewUser.Builder b = NewUser.getBuilder(
				userName, randGen.randomUUID(), displayName, now, match.get())
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
		final RemoteIdentityID rid = match.get().getRemoteID();
		logInfo("Created user {} linked to remote identity {} {} {} {}", userName.getName(),
				rid.getID(), rid.getProviderName(), rid.getProviderIdentityId(),
				match.get().getDetails().getUsername());
		if (linkAll) {
			ids.remove(match.get());
			filterLinkCandidates(ids);
			final int linked = link(userName, ids);
			if (linked > 0) {
				logInfo("Linked all {} remaining identities to user {}",
						linked, userName.getName());
			}
		}
		return login(userName, tokenCtx);
	}
	
	/** Create a test token. The token is entirely separate from standard tokens and is
	 * inaccessible by non-test mode methods. The token expires from the system in one hour.
	 * @param userName the name of the user who will own the token.
	 * @param tokenName the name of the token, or null for no name.
	 * @param tokenType the type of the token.
	 * @return the new token.
	 * @throws TestModeException if test mode is not enabled.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws NoSuchUserException if there is no user by the given name.
	 */
	public NewToken testModeCreateToken(
			final UserName userName,
			final TokenName tokenName,
			final TokenType tokenType)
			throws TestModeException, AuthStorageException, NoSuchUserException {
		ensureTestMode();
		requireNonNull(userName, "userName");
		requireNonNull(tokenType, "tokenType");
		storage.testModeGetUser(userName); // ensure user exists
		final UUID id = randGen.randomUUID();
		final NewToken nt = new NewToken(StoredToken.getBuilder(tokenType, id, userName)
				.withLifeTime(clock.instant(), TEST_MODE_DATA_LIFETIME_MS)
				.withNullableTokenName(tokenName)
				.build(),
				randGen.getToken());
		storage.testModeStoreToken(nt.getStoredToken(), nt.getTokenHash());
		logInfo("Created test mode {} token {} for user {}", tokenType, id, userName.getName());
		return nt;
	}
	
	/** Get details about a test token.
	 * @param token the token in question.
	 * @return the token's details.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws TestModeException if test mode is not enabled.
	 */
	public StoredToken testModeGetToken(final IncomingToken token)
			throws AuthStorageException, InvalidTokenException, TestModeException {
		ensureTestMode();
		requireNonNull(token, "token");
		final StoredToken st;
		try {
			st = storage.testModeGetToken(token.getHashedToken());
		} catch (NoSuchTokenException e) {
			throw new InvalidTokenException();
		}
		logInfo("User {} accessed {} test token {}",
				st.getUserName().getName(), st.getTokenType(), st.getId());
		return st;
	}
	
	/** Create a test mode user. This user is entirely separate from standard users and is
	 * inaccessible and unmodifiable by non-test mode methods. The user expires from the system
	 * in one hour.
	 * @param userName the user's username.
	 * @param displayName the user's display name.
	 * @throws UserExistsException if a test user with the same name already exists.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws UnauthorizedException the user name is the root user name.
	 * @throws TestModeException if test mode is not enabled.
	 */
	public void testModeCreateUser(final UserName userName, final DisplayName displayName)
			throws UserExistsException, AuthStorageException, UnauthorizedException,
			TestModeException {
		ensureTestMode();
		requireNonNull(userName, "userName");
		requireNonNull(displayName, "displayName");
		if (userName.isRoot()) {
			throw new UnauthorizedException("Cannot create root user");
		}
		final Instant now = clock.instant();
		storage.testModeCreateUser(
				userName,
				randGen.randomUUID(),
				displayName,
				now,
				now.plusMillis(TEST_MODE_DATA_LIFETIME_MS));
		logInfo("Created test mode user {}", userName.getName());
	}
	
	// tried reusing code from the regular function and it turned into a disaster
	/** Look up test mode display names for a set of user names. A maximum of 10000 users may be
	 * looked up at once.
	 * @param token a token for the user requesting the lookup.
	 * @param userNames the user names to look up.
	 * @return the display names for each user name. Any non-existent user names will be missing.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws IllegalParameterException if the number of requested user names is greater than the
	 * limit.
	 * @throws TestModeException if testmode is not enabled.
	 */
	public Map<UserName, DisplayName> testModeGetUserDisplayNames(
			final IncomingToken token,
			final Set<UserName> userNames)
			throws InvalidTokenException, AuthStorageException, IllegalParameterException,
				TestModeException {
		requireNonNull(userNames, "userNames");
		noNulls(userNames, "Null name in userNames");
		// just check the token is valid
		final StoredToken stoken = testModeGetToken(token);
		if (userNames.isEmpty()) {
			return new HashMap<>();
		}
		if (userNames.size() > MAX_RETURNED_USERS) {
			throw new IllegalParameterException(
					"User count exceeds maximum of " + MAX_RETURNED_USERS);
		}
		
		final Map<UserName, DisplayName> displayNames =
				storage.testModeGetUserDisplayNames(userNames);
		// there can't be a root user name in test mode, so we don't remove it
		logInfo("Test mode user {} looked up display names", stoken.getUserName().getName());
		return displayNames;
	}
	
	/** Get a test mode user's data.
	 * @param userName the user name of the user.
	 * @return the user.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws NoSuchUserException if there is no such user.
	 * @throws TestModeException if test mode is not enabled.
	 */
	public AuthUser testModeGetUser(final UserName userName)
			throws AuthStorageException, NoSuchUserException, TestModeException {
		ensureTestMode();
		requireNonNull(userName, "userName");
		final AuthUser u = storage.testModeGetUser(userName);
		logInfo("Accessed user data for test mode user {} by user name", userName.getName());
		return u;
	}
	
	/** Get the user data for the user associated with a test token.
	 * @param token the user's token.
	 * @return the user.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws NoSuchUserException if the token is valid but the user has expired from the system.
	 * @throws TestModeException if test mode is not enabled.
	 */
	public AuthUser testModeGetUser(final IncomingToken token)
			throws AuthStorageException, InvalidTokenException, NoSuchUserException,
				TestModeException {
		final AuthUser u = testModeGetUserInternal(token);
		logInfo("Test mode user {} accessed their user data", u.getUserName().getName());
		return u;
	}

	private AuthUser testModeGetUserInternal(final IncomingToken token)
			throws TestModeException, AuthStorageException, InvalidTokenException,
				NoSuchUserException {
		ensureTestMode();
		requireNonNull(token, "token");
		final StoredToken st;
		try {
			st = storage.testModeGetToken(token.getHashedToken());
		} catch (NoSuchTokenException e) {
			throw new InvalidTokenException();
		}
		return storage.testModeGetUser(st.getUserName());
	}
	
	/** Get a restricted view of a test user. Typically used for one user viewing another.
	 * @param token the token of the user requesting the view.
	 * @param user the username of the user to view.
	 * @return a view of the user.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws NoSuchUserException if there is no user corresponding to the given user name or the
	 * token's username.
	 * @throws TestModeException if test mode is not enabled.
	 */
	public ViewableUser testModeGetUser(final IncomingToken token, final UserName user)
			throws InvalidTokenException, NoSuchUserException, TestModeException,
				AuthStorageException {
		requireNonNull(user, "userName");
		final AuthUser requestingUser = testModeGetUserInternal(token);
		final AuthUser otherUser = storage.testModeGetUser(user);
		final boolean sameUser = requestingUser.getUserName().equals(otherUser.getUserName());
		logInfo("Test user {} accessed test user {}'s user data",
				requestingUser.getUserName().getName(), otherUser.getUserName().getName());
		return new ViewableUser(otherUser, sameUser);
	}
	
	/** Create or update a test custom role.
	 * @param role the role to create or update.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws TestModeException if test mode is not enabled.
	 */
	public void testModeSetCustomRole(final CustomRole role)
			throws AuthStorageException, TestModeException {
		ensureTestMode();
		requireNonNull(role, "role");
		storage.testModeSetCustomRole(
				role, clock.instant().plusMillis(TEST_MODE_DATA_LIFETIME_MS));
		logInfo("Created test custom role {}", role.getID());
	}
	
	/** Get all test custom roles.
	 * @return the custom roles.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws TestModeException if test mode is not enabled.
	 */
	public Set<CustomRole> testModeGetCustomRoles()
			throws AuthStorageException, TestModeException {
		ensureTestMode();
		final Set<CustomRole> roles = storage.testModeGetCustomRoles();
		logInfo("Accessed test mode custom roles");
		return roles;
	}
	
	/** Set standard and custom roles for a test user. This method overwrites previous roles -
	 * pass in empty sets to remove all roles.
	 * @param userName the name of the user to modify.
	 * @param roles the standard roles to bequeath to the user.
	 * @param customRoles the custom roles to bequeath to the user.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws NoSuchUserException if there is no user account with the given name.
	 * @throws NoSuchRoleException if one of the roles does not exist in the database.
	 * @throws TestModeException if test mode is not enabled.
	 */
	public void testModeSetRoles(
			final UserName userName,
			final Set<Role> roles,
			final Set<String> customRoles)
			throws NoSuchUserException, NoSuchRoleException, AuthStorageException,
				TestModeException {
		ensureTestMode();
		requireNonNull(userName, "userName");
		requireNonNull(roles, "roles");
		requireNonNull(customRoles, "customRoles");
		noNulls(roles, "Null role in roles");
		noNulls(customRoles, "Null role in customRoles");
		storage.testModeSetRoles(userName, roles, customRoles);
		logInfo("Set roles / custom roles on test user {}: {} / {}", userName.getName(),
				rolesToString(roles, r -> r.getID()), customRolesToString(customRoles));
	}
	
	/** Clear all test data from the system.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 */
	public void testModeClear() throws AuthStorageException {
		// don't ensureTestMode() because it's always ok to clear the data
		storage.testModeClear();
	}
	
	private void ensureTestMode() throws TestModeException {
		if (!testMode) {
			throw new TestModeException(ErrorType.UNSUPPORTED_OP, "Test mode is not enabled");
		}
	}

	/** Complete the OAuth2 login process.
	 * 
	 * This method is expected to be called after {@link #getLoginState(IncomingToken)}.
	 * @param token a temporary token associated with the login process state.
	 * @param identityID the id of the identity associated with the user account that is the login
	 * target. This identity must be included in the login state associated with the temporary
	 * token. 
	 * @param policyIDs the policy IDs to add to the user account.
	 * @param tokenCtx the context under which the token will be created.
	 * @param linkAll link all other available identities associated with the temporary token to
	 * this account.
	 * @return a new login token.
	 * @throws AuthenticationException if the id is not included in the login state associated with
	 * the token or there is no user associated with the remote identity.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws UnauthorizedException if the user is not an administrator and non-admin login
	 * is not allowed or the user account is disabled.
	 * @throws MissingParameterException  if the identity ID is null or the empty string.
	 * @throws IdentityProviderErrorException if the provider reported an error when returning
	 * from the OAuth2 flow.
	 */
	public NewToken login(
			final IncomingToken token,
			final String identityID,
			final Set<PolicyID> policyIDs,
			final TokenCreationContext tokenCtx,
			final boolean linkAll)
			throws AuthenticationException, AuthStorageException, UnauthorizedException,
				MissingParameterException, IdentityProviderErrorException {
		requireNonNull(policyIDs, "policyIDs");
		requireNonNull(tokenCtx, "tokenCtx");
		noNulls(policyIDs, "null item in policyIDs");
		// allow mutation of the identity set
		final Set<RemoteIdentity> ids = new HashSet<>(
				getTemporarySessionData(Optional.empty(), Operation.LOGINIDENTS, token)
				.getIdentities().get());
		storage.deleteTemporarySessionData(token.getHashedToken());
		final Optional<RemoteIdentity> ri = getIdentity(identityID, ids);
		if (!ri.isPresent()) {
			throw new UnauthorizedException(String.format(
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
			throw new UnauthorizedException("User " + u.get().getUserName().getName() +
					" cannot log in because non-admin login is disabled");
		}
		if (u.get().isDisabled()) {
			throw new DisabledUserException(u.get().getUserName().getName());
		}
		addPolicyIDs(u.get().getUserName(), policyIDs);
		if (linkAll) {
			ids.remove(ri.get());
			filterLinkCandidates(ids);
			final int linked = link(u.get().getUserName(), ids);
			if (linked > 0) {
				logInfo("Linked all {} remaining identities to user {}",
						linked, u.get().getUserName().getName());
			}
		}
		return login(u.get().getUserName(), tokenCtx);
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
		return Optional.empty();
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
	 * @param token the user's token.
	 * @param policyID the policyID to remove.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws UnauthorizedException if the user is not authorized to remove policy IDs or the
	 * token is not a login token.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 */
	public void removePolicyID(final IncomingToken token, final PolicyID policyID)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException {
		requireNonNull(policyID, "policyID");
		final AuthUser admin = getUser(token, new OpReqs("remove policy ID {}", policyID.getName())
				.types(TokenType.LOGIN).roles(Role.ADMIN));
		storage.removePolicyID(policyID);
		logInfo("Admin {} removed policy ID {} from the system", admin.getUserName().getName(),
				policyID.getName());
	}
	
	/** Start the account linking process.
	 * @param token the user's token.
	 * @param lifetimeSec the lifetime of the temporary token to be returned.
	 * @param provider the name of the 3rd party identity provider to link with.
	 * @param environment the auth environment in which the link is taking place, or null for the
	 * default environment.
	 * @return data to start the linking process.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws UnauthorizedException if the token is not a login token.
	 * @throws AuthStorageException if an error occurs accessing the storage system.
	 * @throws LinkFailedException if the user is a local user 
	 * @throws NoSuchEnvironmentException if there is no such configured environment.
	 * @throws NoSuchIdentityProviderException if there is no such configured identify provider.
	 * @throws MissingParameterException if the provider is null or whitespace only
	 */
	public OAuth2StartData linkStart(
			final IncomingToken token,
			final int lifetimeSec,
			final String provider,
			final String environment)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException,
				LinkFailedException, NoSuchIdentityProviderException, NoSuchEnvironmentException,
				MissingParameterException {
		requireNonNull(token, "token");
		checkLifeTimeSec(lifetimeSec);
		final String state = randGen.getToken();
		final String pkceVerifier = generatePKCECodeVerifier();
		final String pkceChallenge = generatePKCECodeChallenge(pkceVerifier);
		// check provider & env before pulling user from DB
		final URI target = getIdentityProvider(provider).getLoginURI(
				state, pkceChallenge, true, environment);
		final AuthUser user = getUser(token, new OpReqs("start link").types(TokenType.LOGIN));
		if (user.isLocal()) {
			// the ui shouldn't allow local users to link accounts, so ok to throw this
			throw new LinkFailedException("Cannot link identities to local account " +
					user.getUserName().getName());
		}
		final TemporarySessionData data = TemporarySessionData.create(
				randGen.randomUUID(), clock.instant(), lifetimeSec * 1000L)
				.link(state, pkceVerifier, user.getUserName());
		final TemporaryToken tt = storeTemporarySessionData(data);
		logInfo("Created temporary link token {} associated with user {}",
				tt.getId(), user.getUserName().getName());
		return OAuth2StartData.build(target, tt);
	}
	
	/** Continue the local portion of an OAuth2 link flow after redirection from a 3rd party
	 * identity provider in the case that the provider returned an error.
	 * @param providerError the error returned by the provider.
	 * @return A temporary token.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @see #linkStart(IncomingToken, int)
	 */
	public TemporaryToken linkProviderError(final String providerError)
			throws AuthStorageException {
		checkStringNoCheckedException(providerError, "providerError");
		final TemporaryToken tt = storeErrorTemporarily(
				providerError, ErrorType.ID_PROVIDER_ERROR, LINK_TOKEN_LIFETIME_MS);
		logErr("Stored temporary token {} with link identity provider error {}",
				tt.getId(), providerError);
		return tt;
	}
	
	private TemporaryToken storeErrorTemporarily(
			final String errorMessage,
			final ErrorType errorType,
			final int tokenLifeTimeMS)
			throws AuthStorageException {
		checkStringNoCheckedException(errorMessage, "errorMessage");
		requireNonNull(errorType, "errorType");
		final TemporarySessionData data = TemporarySessionData.create(
				randGen.randomUUID(), clock.instant(), tokenLifeTimeMS)
				.error(errorMessage, errorType);
		return storeTemporarySessionData(data);
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
	 * @param token the user's temporary token acquired from
	 * {@link #linkStart(IncomingToken, int)}.
	 * @param provider the name of the identity provider that is servicing the link request.
	 * @param authcode the authcode provided by the provider.
	 * @param environment the environment in which the link request is proceeding. Null for the
	 * default environment.
	 * @param oauth2State the OAuth2 state value.
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
	 * @throws IdentityProviderErrorException if the incoming token is associated with an
	 * identity provider error.
	 * @throws NoSuchEnvironmentException if no such environment is configured for the provider.
	 * @throws AuthenticationException if the state value doesn't match the expected value.
	 */
	public LinkToken link(  // enough args here to start considering a builder
			final IncomingToken token,
			final String provider,
			final String authcode,
			final String environment,
			final String oauth2State)
			throws InvalidTokenException, AuthStorageException, AuthenticationException,
				MissingParameterException, IdentityRetrievalException,
				LinkFailedException, NoSuchIdentityProviderException, DisabledUserException,
				UnauthorizedException, IdentityProviderErrorException, NoSuchEnvironmentException {
		checkString(authcode, "authorization code");
		final IdentityProvider idp = getIdentityProvider(provider);
		final TemporarySessionData tids = getTemporarySessionData(
				Optional.empty(), Operation.LINKSTART, token);
		checkState(tids, oauth2State);
		storage.deleteTemporarySessionData(token.getHashedToken());
		// UI shouldn't allow disabled users to link
		final AuthUser u = getUser(tids.getUser().get());
		if (u.isLocal()) {
			// the ui shouldn't allow local users to link accounts, so ok to throw this
			throw new LinkFailedException("Cannot link identities to local account " +
					u.getUserName().getName());
		}
		final Set<RemoteIdentity> ids = idp.getIdentities(
				authcode, tids.getPKCECodeVerifier().get(), true, environment);
		final Set<RemoteIdentity> filtered = new HashSet<>(ids);
		filterLinkCandidates(filtered);
		/* Don't throw an error if ids are empty since an auth UI is not controlling the call in
		 * some cases - this call is almost certainly the result of a redirect from a 3rd party
		 * provider. Any controllable error should be thrown when the process flow is back
		 * under the control of the primary auth UI.
		 */
		final LinkToken lt;
		final ProviderConfig pc = cfg.getAppConfig().getProviderConfig(idp.getProviderName());
		// reuse token in either case if necessary
		if (filtered.size() == 1 && !pc.isForceLinkChoice()) {
			lt = getLinkToken(u.getUserName(), filtered.iterator().next(), ids, token);
		} else {
			final TemporarySessionData data = TemporarySessionData.create(
					randGen.randomUUID(), clock.instant(), LINK_TOKEN_LIFETIME_MS)
					.link(u.getUserName(), ids);
			final TemporaryToken tt = new TemporaryToken(data, token.getToken());
			storage.storeTemporarySessionData(data, IncomingToken.hash(token.getToken()));
			logInfo("Stored temporary token {} with {} link identities", tt.getId(), ids.size());
			lt = new LinkToken(tt);
		}
		return lt;
	}

	// expects that user is not a local user. Will throw link failed if so.
	private LinkToken getLinkToken(
			final UserName userName,
			final RemoteIdentity remoteIdentity,
			final Set<RemoteIdentity> allIds,
			final IncomingToken token)
			throws AuthStorageException, LinkFailedException {
		try {
			final boolean linked = storage.link(userName, remoteIdentity);
			logSingleLinkResult(userName, remoteIdentity, linked);
			return new LinkToken();
		} catch (NoSuchUserException e) {
			throw new AuthStorageException(
					"User unexpectedly disappeared from the database", e);
		} catch (IdentityLinkedException e) {
			// well, crap. race condition and now there are no link candidates left.
			final TemporarySessionData data = TemporarySessionData.create(
					randGen.randomUUID(), clock.instant(), LINK_TOKEN_LIFETIME_MS)
					.link(userName, allIds);
			final TemporaryToken tt = new TemporaryToken(data, token.getToken());
			storage.storeTemporarySessionData(data, IncomingToken.hash(token.getToken()));
			logInfo("A race condition means that the identity {} is already linked to a user " +
					"other than {}. Stored identity set with {} linked identities with " +
					"temporary token {}",
					remoteIdentity.getRemoteID().getID(), userName.getName(), allIds.size(),
					tt.getId());
			return new LinkToken(tt);
		}
	}

	private void logSingleLinkResult(
			final UserName userName,
			final RemoteIdentity remoteIdentity,
			final boolean linked) {
		final RemoteIdentityID id = remoteIdentity.getRemoteID();
		if (linked) {
			logInfo("Linked identity {} {} {} {} to user {}", id.getID(), id.getProviderName(),
					id.getProviderIdentityId(), remoteIdentity.getDetails().getUsername(),
					userName.getName());
		} else {
			logInfo("Identity {} {} {} {} is already linked to user {}", id.getID(),
					id.getProviderName(), id.getProviderIdentityId(),
					remoteIdentity.getDetails().getUsername(), userName.getName());
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
	 * This method is expected to be called after
	 * {@link #link(IncomingToken, String, String, String)}.
	 * After user interaction is completed, the link can be completed by calling
	 * {@link #link(IncomingToken, IncomingToken, String)} or
	 * {@link #linkAll(IncomingToken, IncomingToken)}.
	 * 
	 * @param token the user's token.
	 * @param linkToken the temporary token associated with the link state.
	 * @return the state of the linking process.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws InvalidTokenException if either token is invalid.
	 * @throws LinkFailedException if the user is a local user or there are no available identities
	 * to link.
	 * @throws DisabledUserException if the user is disabled.
	 * @throws UnauthorizedException if the token is not a login token.
	 * @throws IdentityProviderErrorException if the provider reported an error when returning
	 * from the OAuth2 flow.
	 */
	public LinkIdentities getLinkState(
			final IncomingToken token,
			final IncomingToken linkToken)
			throws InvalidTokenException, AuthStorageException, LinkFailedException,
				DisabledUserException, UnauthorizedException, IdentityProviderErrorException {
		final AuthUser u = getUser(token, new OpReqs("get link state").types(TokenType.LOGIN));
		if (u.isLocal()) {
			throw new LinkFailedException("Cannot link identities to local account " +
					u.getUserName().getName());
		}
		final TemporarySessionData tids = getTemporarySessionData(
				Optional.of(u.getUserName()), Operation.LINKIDENTS, linkToken);
		checkIdentityAccess(u.getUserName(), tids);
		final LinkIdentities linkIdentities = getLinkIdentities(u, tids);
		logInfo("User {} accessed temporary link token {} with {} identities",
				u.getUserName().getName(), tids.getId(), tids.getIdentities().get().size());
		return linkIdentities;
	}
	
	// assumes tids is a LINKIDENT operation and therefore has a user
	private void checkIdentityAccess(final UserName name, final TemporarySessionData tids)
			throws UnauthorizedException {
		if (Optional.of(name).equals(tids.getUser())) {
			return; // all good
		} else {
			logErr("During the account linking process user {} attempted to access temporary " +
					"token {} which is owned by user {}.",
					name.getName(), tids.getId(), tids.getUser().get().getName());
			throw new UnauthorizedException(String.format(
					"User %s may not access this identity set", name.getName()));
		}
	}

	private LinkIdentities getLinkIdentities(final AuthUser u, final TemporarySessionData tids)
			throws AuthStorageException {
		final Set<RemoteIdentity> ids = tids.getIdentities().get();
		final String provider = ids.iterator().next().getRemoteID().getProviderName();
		
		final LinkIdentities.Builder builder = LinkIdentities.getBuilder(
				u.getUserName(), provider, tids.getExpires());
		for (final RemoteIdentity ri: ids) {
			final Optional<AuthUser> linkeduser = storage.getUser(ri);
			if (!linkeduser.isPresent()) {
				builder.withIdentity(ri);
			} else {
				builder.withUser(linkeduser.get(), ri);
			}
		}
		return builder.build();
	}

	/** Complete the OAuth2 account linking process by linking one identity to the current user.
	 * 
	 * This method is expected to be called after
	 * {@link #getLinkState(IncomingToken, IncomingToken)}.
	 * 
	 * @param token the user's token.
	 * @param linkToken a temporary token associated with the link process state.
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
	 * @throws IdentityProviderErrorException if the provider reported an error when returning
	 * from the OAuth2 flow.
	 */
	public void link(
			final IncomingToken token,
			final IncomingToken linkToken,
			final String identityID)
			throws AuthStorageException, LinkFailedException, DisabledUserException,
				InvalidTokenException, IdentityLinkedException, UnauthorizedException,
				MissingParameterException, IdentityProviderErrorException {
		// checks user isn't disabled
		final AuthUser au = getUser(
				token, new OpReqs("link identity {}", identityID).types(TokenType.LOGIN));
		if (au.isLocal()) {
			throw new LinkFailedException("Cannot link identities to local account " +
					au.getUserName().getName());
		}
		final TemporarySessionData tids = getTemporarySessionData(
				Optional.of(au.getUserName()), Operation.LINKIDENTS, linkToken);
		storage.deleteTemporarySessionData(linkToken.getHashedToken());
		checkIdentityAccess(au.getUserName(), tids);
		final Set<RemoteIdentity> ids = tids.getIdentities().get();
		final Optional<RemoteIdentity> ri = getIdentity(identityID, ids);
		if (!ri.isPresent()) {
			throw new LinkFailedException(String.format(
					"User %s is not authorized to link identity %s", au.getUserName().getName(),
					identityID));
		}
		final boolean linked = link(au.getUserName(), ri.get());
		logSingleLinkResult(au.getUserName(), ri.get(), linked);
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
	 * @throws IdentityProviderErrorException if the provider reported an error when returning
	 * from the OAuth2 flow.
	 */
	public void linkAll(final IncomingToken token, final IncomingToken linkToken)
			throws InvalidTokenException, AuthStorageException, DisabledUserException,
			UnauthorizedException, LinkFailedException, IdentityProviderErrorException {
		// checks user isn't disabled
		final AuthUser au = getUser(
				token, new OpReqs("link all identities").types(TokenType.LOGIN));
		if (au.isLocal()) {
			throw new LinkFailedException("Cannot link identities to local account " +
					au.getUserName().getName());
		}
		final TemporarySessionData tids = getTemporarySessionData(
				Optional.of(au.getUserName()), Operation.LINKIDENTS, linkToken);
		storage.deleteTemporarySessionData(linkToken.getHashedToken());
		checkIdentityAccess(au.getUserName(), tids);
		final Set<RemoteIdentity> identities = new HashSet<>(tids.getIdentities().get());
		filterLinkCandidates(identities);
		final int linked = link(au.getUserName(), identities);
		if (linked > 0) {
			logInfo("Linked all {} available identities to user {}",
					linked, au.getUserName().getName());
		} else {
			logInfo("User {} had no available identities to link", au.getUserName().getName());
		}
	}
	
	private boolean link(final UserName userName, final RemoteIdentity id)
			throws AuthStorageException, IdentityLinkedException {
		return link(userName, new HashSet<>(Arrays.asList(id)), true) == 1;
	}

	private int link(final UserName userName, final Set<RemoteIdentity> identities)
			throws AuthStorageException {
		try {
			return link(userName, identities, false);
		} catch (IdentityLinkedException e) {
			throw new RuntimeException("explicitly said not to throw an exception for this", e);
		}
	}
	
	// assumes user is not local, and that the user exists
	private int link(
			final UserName userName,
			final Set<RemoteIdentity> identities,
			final boolean throwExceptionIfIdentityLinked)
			throws AuthStorageException, IdentityLinkedException {
		int linked = 0;
		for (final RemoteIdentity ri: identities) {
			// could make a bulk op, but probably not necessary. Wait for now.
			try {
				linked += storage.link(userName, ri) ? 1 : 0;
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
		return linked;
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
		final AuthUser au = getUser(
				token, new OpReqs("unlink identity {}", identityID).types(TokenType.LOGIN));
		if (au.isLocal()) {
			throw new UnLinkFailedException(String.format(
					"Local user %s doesn't have remote identities", au.getUserName().getName()));
		}
		try {
			// throws no such id exception if not already linked
			storage.unlink(au.getUserName(), identityID);
			// could get the identity from the AuthUser and log more info, but meh for now
			logInfo("Unlinked identity {} from user {}", identityID, au.getUserName().getName());
		} catch (NoSuchUserException e) {
			throw new AuthStorageException("User magically disappeared from database: " +
					au.getUserName().getName());
		}
		
	}
	
	/** Deletes any state associated with a link or login process, canceling the login or 
	 * link operation.
	 * @param token the token associated with the link or login operation.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 */
	public void deleteLinkOrLoginState(final IncomingToken token) throws AuthStorageException {
		requireNonNull(token, "token");
		final Optional<UUID> id = storage.deleteTemporarySessionData(token.getHashedToken());
		if (id.isPresent()) {
			logInfo("Deleted temporary token {}", id.get());
		} else {
			logInfo("Attempted to delete non-existant temporary token");
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
		requireNonNull(update, "update");
		// should check the token before returning even if there's no update
		final StoredToken ht = getToken(token, new OpReqs("update user").types(TokenType.LOGIN));
		if (!update.hasUpdates()) {
			return; //noop
		}
		try {
			storage.updateUser(ht.getUserName(), update);
			logUserUpdate(ht.getUserName(), update);
		} catch (NoSuchUserException e) {
			throw new RuntimeException("There seems to be an error in the " +
					"storage system. Token was valid, but no user", e);
		}
	}

	// assumes there's at least 1 update
	private void logUserUpdate(final UserName userName, final UserUpdate update) {
		final StringBuilder sb = new StringBuilder();
		final List<String> args = new LinkedList<>();
		sb.append("Updated user details for user {}.");
		args.add(userName.getName());
		if (update.getDisplayName().isPresent()) {
			sb.append(" Display name: {}");
			args.add(update.getDisplayName().get().getName());
		}
		if (update.getEmail().isPresent()) {
			sb.append(" Email: {}");
			args.add(update.getEmail().get().getAddress());
		}
		logInfo(sb.toString(), args.toArray());
		
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
		requireNonNull(userName, "userName");
		checkString(reason, "reason", 1000);
		final AuthUser admin = getUser(token, new OpReqs("disable account {}", userName.getName())
				.types(TokenType.LOGIN).roles(Role.ROOT, Role.CREATE_ADMIN, Role.ADMIN));
		if (userName.isRoot() && !admin.isRoot()) {
			throw new UnauthorizedException(String.format(
					"User %s cannot disable the root account", admin.getUserName().getName()));
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
		logInfo("Admin {} disabled account {}", admin.getUserName().getName(), userName.getName());
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
		requireNonNull(userName, "userName");
		final AuthUser admin = getUser(token, new OpReqs("enable account {}", userName.getName())
				.types(TokenType.LOGIN).roles(Role.ROOT, Role.CREATE_ADMIN, Role.ADMIN));
		if (userName.isRoot()) {
			throw new UnauthorizedException(String.format(
					"User %s cannot enable the root user via this method",
					admin.getUserName().getName()));
		}
		storage.enableAccount(userName, admin.getUserName());
		logInfo("Admin {} enabled account {}", admin.getUserName().getName(), userName.getName());
	}
	
	/** Update the server configuration.
	 * @param <T> the type of the the ExternalConfig in the update.
	 * @param token a token for a user with the administrator role.
	 * @param update the new server configuration.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws UnauthorizedException if the user account associated with the token doesn't have
	 * the appropriate role or the token is not a login token.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws NoSuchIdentityProviderException if a provider specified in the new configuration
	 * is not supported by this authentication instance.
	 */
	public <T extends ExternalConfig> void updateConfig(
			final IncomingToken token,
			final AuthConfigUpdate<T> update)
			throws InvalidTokenException, UnauthorizedException,
			AuthStorageException, NoSuchIdentityProviderException {
		requireNonNull(update, "update");
		final AuthUser admin = getUser(token, new OpReqs("update configuration")
				.types(TokenType.LOGIN).roles(Role.ADMIN));
		for (final String provider: update.getProviders().keySet()) {
			// since idProviderSet is case insensitive
			final IdentityProvider idp = idProviderSet.get(provider);
			if (idp == null || !idp.getProviderName().equals(provider)) {
				throw new NoSuchIdentityProviderException(provider);
			}
		}
		storage.updateConfig(update, true);
		cfg.updateConfig();
		logConfigurationUpdate(admin.getUserName(), update);
	}
	
	private <T extends ExternalConfig> void logConfigurationUpdate(
			final UserName userName,
			final AuthConfigUpdate<T> update) {
		final String name = userName.getName();
		
		if (update.getLoginAllowed().isPresent()) {
			logInfo("Admin {} set non-admin login allowed to {}",
					name, update.getLoginAllowed().get());
		}
		
		final List<TokenLifetimeType> lifesorted = update.getTokenLifetimeMS().keySet().stream()
				.sorted().collect(Collectors.toList());
		for (final TokenLifetimeType lifetype: lifesorted) {
			logInfo("Admin {} set lifetime for token type {} to {}",
					name, lifetype, update.getTokenLifetimeMS().get(lifetype));
		}
		
		final List<String> providersSorted = update.getProviders().keySet().stream().sorted()
				.collect(Collectors.toList());
		for (final String provider: providersSorted) {
			logConfigurationUpdateForProvider(name, provider, update.getProviders().get(provider));
		}
		
		logConfigurationUpdateExternal(name, update.getExternalConfig());
	}

	private <T extends ExternalConfig> void logConfigurationUpdateExternal(
			final String name,
			final Optional<T> externalConfig) {
		if (!externalConfig.isPresent()) {
			return;
		}
		final Map<String, ConfigItem<String, Action>> ext = externalConfig.get().toMap();
		final List<String> keys = ext.keySet().stream().sorted().collect(Collectors.toList());
		for (final String key: keys) {
			final ConfigItem<String, Action> item = ext.get(key);
			final Action action = item.getAction();
			if (action.isRemove()) {
				logInfo("Admin {} removed external config key {}", name, key);
			} else if (action.isSet()) {
				logInfo("Admin {} set external config key {} to {}", name, key, item.getItem());
			}
		}
	}

	private void logConfigurationUpdateForProvider(
			final String adminName,
			final String provider,
			final ProviderUpdate update) {
		if (!update.hasUpdate()) {
			return;
		}
		final StringBuilder sb = new StringBuilder();
		final List<Object> args = new LinkedList<>();
		sb.append("Admin {} set values for identity provider {}.");
		args.add(adminName);
		args.add(provider);
		if (update.getEnabled().isPresent()) {
			sb.append(" Enabled: {}");
			args.add(update.getEnabled().get());
		}
		if (update.getForceLoginChoice().isPresent()) {
			sb.append(" Force login choice: {}");
			args.add(update.getForceLoginChoice().get());
		}
		if (update.getForceLinkChoice().isPresent()) {
			sb.append(" Force link choice: {}");
			args.add(update.getForceLinkChoice().get());
		}
		logInfo(sb.toString(), args.toArray());
	}

	/** Reset the service configuration to the initial configuration supplied at startup.
	 * @param token a token for a user with the administrator role.
	 * @throws InvalidTokenException if the token is invalid.
	 * @throws UnauthorizedException if the user account associated with the token doesn't have
	 * the appropriate role or the token is not a login token.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 */
	public void resetConfigToDefault(final IncomingToken token)
			throws InvalidTokenException, UnauthorizedException, AuthStorageException {
		final AuthUser admin = getUser(token, new OpReqs("reset configuration")
				.types(TokenType.LOGIN).roles(Role.ADMIN));
		storage.updateConfig(buildDefaultConfig(), true);
		cfg.updateConfig();
		logInfo("Admin {} reset the configuration to defaults", admin.getUserName().getName());
	}

	private AuthConfigUpdate<ExternalConfig> buildDefaultConfig() {
		final Builder<ExternalConfig> acu = AuthConfigUpdate.getBuilder()
				.withLoginAllowed(AuthConfig.DEFAULT_LOGIN_ALLOWED)
				.withExternalConfig(defaultExternalConfig)
				.withDefaultTokenLifeTimes();
		for (final Entry<String, IdentityProvider> e: idProviderSet.entrySet()) {
			try {
				acu.withProviderUpdate(e.getKey(), AuthConfigUpdate.DEFAULT_PROVIDER_UPDATE);
			} catch (MissingParameterException ex) {
				throw new IllegalArgumentException("Bad provider name: " + e.getKey());
			}
		}
		return acu.build();
	}
	
	/** Gets the authentication configuration.
	 * @param <T> the type of the the ExternalConfig to which the authentication external
	 * configuration will be mapped.
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
	public <T extends ExternalConfig> AuthConfigSetWithUpdateTime<T> getConfig(
			final IncomingToken token,
			final ExternalConfigMapper<T> mapper)
			throws InvalidTokenException, UnauthorizedException,
			AuthStorageException, ExternalConfigMappingException {
		requireNonNull(mapper, "mapper");
		final AuthUser admin = getUser(token, new OpReqs("get configuration")
				.types(TokenType.LOGIN).roles(Role.ADMIN));
		final AuthConfigSet<CollectingExternalConfig> acs = cfg.getConfig();
		final AuthConfigSetWithUpdateTime<T> config = new AuthConfigSetWithUpdateTime<T>(
				acs.getCfg().filterProviders(idProviderSet.keySet()),
				mapper.fromMap(acs.getExtcfg().getMap()),
				cfgUpdateIntervalMillis);
		logInfo("Admin {} accessed the configuration", admin.getUserName().getName());
		return config;
	}
	
	/** Returns the suggested cache time for tokens in milliseconds.
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
	 * @param <T> the type of the the ExternalConfig to which the authentication external
	 * configuration will be mapped.
	 * @param mapper a mapper for the external configuration.
	 * @return the external configuration.
	 * @throws AuthStorageException if an error occurred accessing the storage system.
	 * @throws ExternalConfigMappingException if the mapper failed to map the external
	 * configuration into a class.
	 */
	public <T extends ExternalConfig> T getExternalConfig(
			final ExternalConfigMapper<T> mapper)
			throws AuthStorageException, ExternalConfigMappingException {
		requireNonNull(mapper, "mapper");
		final AuthConfigSet<CollectingExternalConfig> acs = cfg.getConfig();
		return mapper.fromMap(acs.getExtcfg().getMap());
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
		requireNonNull(userName, "userName");
		requireNonNull(remoteIdentity, "remoteIdentity");
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
			storage.createUser(NewUser.getBuilder(
					userName, randGen.randomUUID(), dn, clock.instant(), remoteIdentity)
					.withEmailAddress(email).build());
			logInfo("Imported user {}", userName.getName());
		} catch (NoSuchRoleException e) {
			throw new RuntimeException("didn't supply any roles", e);
		}
	}
}
