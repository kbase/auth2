package us.kbase.auth2.lib.storage.mongo;

import static us.kbase.auth2.lib.Utils.checkStringNoCheckedException;
import static us.kbase.auth2.lib.Utils.nonNull;
import static us.kbase.auth2.lib.Utils.noNulls;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.bson.Document;
import org.bson.types.ObjectId;

import com.google.common.base.Optional;
import com.mongodb.ErrorCategory;
import com.mongodb.MongoException;
import com.mongodb.MongoWriteException;
import com.mongodb.bulk.BulkWriteResult;
import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.FindOneAndDeleteOptions;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.model.UpdateOneModel;
import com.mongodb.client.model.UpdateOptions;
import com.mongodb.client.result.DeleteResult;
import com.mongodb.client.result.UpdateResult;

import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.PasswordHashAndSalt;
import us.kbase.auth2.lib.PolicyID;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.TemporarySessionData;
import us.kbase.auth2.lib.TemporarySessionData.Builder;
import us.kbase.auth2.lib.TemporarySessionData.Operation;
import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.UserSearchSpec;
import us.kbase.auth2.lib.UserUpdate;
import us.kbase.auth2.lib.Utils;
import us.kbase.auth2.lib.config.AuthConfig;
import us.kbase.auth2.lib.config.AuthConfigSet;
import us.kbase.auth2.lib.config.AuthConfigUpdate;
import us.kbase.auth2.lib.config.AuthConfigUpdate.ProviderUpdate;
import us.kbase.auth2.lib.config.ConfigAction.Action;
import us.kbase.auth2.lib.config.ConfigAction.State;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.config.ExternalConfig;
import us.kbase.auth2.lib.config.ExternalConfigMapper;
import us.kbase.auth2.lib.config.AuthConfig.ProviderConfig;
import us.kbase.auth2.lib.config.AuthConfig.TokenLifetimeType;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.IdentityLinkedException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.LinkFailedException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityException;
import us.kbase.auth2.lib.exceptions.NoSuchLocalUserException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UnLinkFailedException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.storage.exceptions.StorageInitException;
import us.kbase.auth2.lib.token.IncomingHashedToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenName;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.lib.user.LocalUser;
import us.kbase.auth2.lib.user.NewUser;

/** A MongoDB based implementation of the authentication storage system.
 * 
 * @see AuthStorage
 * @author gaprice@lbl.gov
 *
 */
public class MongoStorage implements AuthStorage {

	/* Don't use mongo built in object mapping to create the returned objects
	 * since that tightly couples the classes to the storage implementation.
	 * Instead, if needed, create classes specific to the implementation for
	 * mapping purposes that produce the returned classes.
	 */
	
	/* Testing the (many) catch blocks for the general mongo exception is pretty hard, since it
	 * appears as though the mongo clients have a heartbeat, so just stopping mongo might trigger
	 * the heartbeat exception rather than the exception you're going for.
	 * 
	 * Mocking the mongo client is probably not the answer:
	 * http://stackoverflow.com/questions/7413985/unit-testing-with-mongodb
	 * https://github.com/mockito/mockito/wiki/How-to-write-good-tests
	 */
	
	private static final int SCHEMA_VERSION = 1;
	
	private static final String COL_CONFIG = "config";
	private static final String COL_CONFIG_APPLICATION = "config_app";
	private static final String COL_CONFIG_PROVIDERS = "config_prov";
	private static final String COL_CONFIG_EXTERNAL = "config_ext";
	private static final String COL_USERS = "users";
	private static final String COL_TOKEN = "tokens";
	private static final String COL_TEMP_DATA = "tempdata";
	private static final String COL_CUST_ROLES = "cust_roles";
	
	private static final String COL_TEST_TOKEN = "test_tokens";
	
	private static final Map<TokenLifetimeType, String>
			TOKEN_LIFETIME_FIELD_MAP;
	static {
		final Map<TokenLifetimeType, String> m = new HashMap<>();
		m.put(TokenLifetimeType.EXT_CACHE, Fields.CONFIG_APP_TOKEN_LIFE_CACHE);
		m.put(TokenLifetimeType.LOGIN, Fields.CONFIG_APP_TOKEN_LIFE_LOGIN);
		m.put(TokenLifetimeType.AGENT, Fields.CONFIG_APP_TOKEN_LIFE_AGENT);
		m.put(TokenLifetimeType.DEV, Fields.CONFIG_APP_TOKEN_LIFE_DEV);
		m.put(TokenLifetimeType.SERV, Fields.CONFIG_APP_TOKEN_LIFE_SERV);
		TOKEN_LIFETIME_FIELD_MAP = Collections.unmodifiableMap(m);
	}
	
	private static final Map<String, Map<List<String>, IndexOptions>> INDEXES;
	private static final IndexOptions IDX_UNIQ = new IndexOptions().unique(true);
	private static final IndexOptions IDX_SPARSE = new IndexOptions().sparse(true);
	private static final IndexOptions IDX_UNIQ_SPARSE =
			new IndexOptions().unique(true).sparse(true);
	static {
		//hardcoded indexes
		INDEXES = new HashMap<String, Map<List<String>, IndexOptions>>();
		
		//user indexes
		final Map<List<String>, IndexOptions> users = new HashMap<>();
		//find users and ensure user names are unique
		users.put(Arrays.asList(Fields.USER_NAME), IDX_UNIQ);
		//find user by identity id and ensure identities only possessed by one user
		users.put(Arrays.asList(Fields.USER_IDENTITIES + Fields.FIELD_SEP +
				Fields.IDENTITIES_ID), IDX_UNIQ_SPARSE);
		//find users by display name
		users.put(Arrays.asList(Fields.USER_DISPLAY_NAME_CANONICAL), null);
		//find users by roles
		users.put(Arrays.asList(Fields.USER_ROLES), IDX_SPARSE);
		//find users by custom roles
		users.put(Arrays.asList(Fields.USER_CUSTOM_ROLES), IDX_SPARSE);
		INDEXES.put(COL_USERS, users);
		
		//custom roles indexes
		final Map<List<String>, IndexOptions> roles = new HashMap<>();
		roles.put(Arrays.asList(Fields.ROLES_ID), IDX_UNIQ);
		INDEXES.put(COL_CUST_ROLES, roles);
		
		//token indexes
		final Map<List<String>, IndexOptions> token = new HashMap<>();
		token.put(Arrays.asList(Fields.TOKEN_USER_NAME), null);
		token.put(Arrays.asList(Fields.TOKEN_TOKEN), IDX_UNIQ);
		token.put(Arrays.asList(Fields.TOKEN_ID), IDX_UNIQ);
		token.put(Arrays.asList(Fields.TOKEN_EXPIRY),
				/* this causes the tokens to be deleted at their expiration date
				 * Difficult to write a test for since ttl thread runs 1/min and seems to be no
				 * way to trigger a run, so tested manually
				 */
				new IndexOptions().expireAfter(0L, TimeUnit.SECONDS));
		INDEXES.put(COL_TOKEN, token);
		
		//temporary token indexes
		final Map<List<String>, IndexOptions> temptoken = new HashMap<>();
		temptoken.put(Arrays.asList(Fields.TEMP_SESSION_TOKEN), IDX_UNIQ);
		temptoken.put(Arrays.asList(Fields.TEMP_SESSION_ID), IDX_UNIQ);
		temptoken.put(Arrays.asList(Fields.TEMP_SESSION_USER), IDX_SPARSE);
		temptoken.put(Arrays.asList(Fields.TEMP_SESSION_EXPIRY),
				// this causes the tokens to expire at their expiration date
				/* this causes the tokens to be deleted at their expiration date
				 * Difficult to write a test for since ttl thread runs 1/min and seems to be no
				 * way to trigger a run, so tested manually
				 */
				new IndexOptions().expireAfter(0L, TimeUnit.SECONDS));
		INDEXES.put(COL_TEMP_DATA, temptoken);
		
		//config indexes
		final Map<List<String>, IndexOptions> cfg = new HashMap<>();
		//ensure only one config object
		cfg.put(Arrays.asList(Fields.DB_SCHEMA_KEY), IDX_UNIQ);
		INDEXES.put(COL_CONFIG, cfg);
		
		// application config indexes
		final Map<List<String>, IndexOptions> appcfg = new HashMap<>();
		appcfg.put(Arrays.asList(Fields.CONFIG_KEY), IDX_UNIQ);
		INDEXES.put(COL_CONFIG_APPLICATION, appcfg);
		
		// provider config indexes
		final Map<List<String>, IndexOptions> provcfg = new HashMap<>();
		provcfg.put(Arrays.asList(Fields.CONFIG_PROVIDER, Fields.CONFIG_KEY),
				IDX_UNIQ);
		INDEXES.put(COL_CONFIG_PROVIDERS, provcfg);
		
		// external config indexes
		final Map<List<String>, IndexOptions> extcfg = new HashMap<>();
		extcfg.put(Arrays.asList(Fields.CONFIG_KEY), IDX_UNIQ);
		INDEXES.put(COL_CONFIG_EXTERNAL, extcfg);
		
		// *** test collection indexes ***
		//token indexes
		final Map<List<String>, IndexOptions> testToken = new HashMap<>();
		testToken.put(Arrays.asList(Fields.TOKEN_USER_NAME), null);
		testToken.put(Arrays.asList(Fields.TOKEN_TOKEN), IDX_UNIQ);
		testToken.put(Arrays.asList(Fields.TOKEN_ID), IDX_UNIQ);
		testToken.put(Arrays.asList(Fields.TOKEN_EXPIRY),
				/* this causes the tokens to be deleted at their expiration date
				 * Difficult to write a test for since ttl thread runs 1/min and seems to be no
				 * way to trigger a run, so tested manually
				 */
				new IndexOptions().expireAfter(0L, TimeUnit.SECONDS));
		INDEXES.put(COL_TEST_TOKEN, testToken);
	}
	
	private final MongoDatabase db;
	private final Clock clock;
	
	/** Create a new MongoDB authentication storage system.
	 * @param db the MongoDB database to use for storage.
	 * @throws StorageInitException if the storage system could not be initialized.
	 */
	public MongoStorage(final MongoDatabase db) throws StorageInitException {
		this(db, Clock.systemDefaultZone()); //don't use timezone
	}
	
	// this should only be used for tests
	private MongoStorage(final MongoDatabase db, final Clock clock) throws StorageInitException {
		nonNull(db, "db");
		this.db = db;
		this.clock = clock;
		
		//TODO MISC port over schemamanager from UJS (will need changes for schema key & mdb ver)
		ensureIndexes(); // MUST come before checkConfig();
		checkConfig();
	}
	
	private void checkConfig() throws StorageInitException  {
		final MongoCollection<Document> col = db.getCollection(COL_CONFIG);
		final Document cfg = new Document(Fields.DB_SCHEMA_KEY, Fields.DB_SCHEMA_VALUE);
		cfg.put(Fields.DB_SCHEMA_UPDATE, false);
		cfg.put(Fields.DB_SCHEMA_VERSION, SCHEMA_VERSION);
		try {
			col.insertOne(cfg);
		} catch (MongoWriteException dk) {
			if (!DuplicateKeyExceptionChecker.isDuplicate(dk)) {
				throw new StorageInitException("There was a problem communicating with the " +
						"database: " + dk.getMessage(), dk);
			}
			// ok, duplicate key means the version doc is already there, this isn't the first
			// startup
			if (col.count() != 1) {
				// if this occurs the indexes are broken, so there's no way to test without
				// altering ensureIndexes()
				throw new StorageInitException(
						"Multiple config objects found in the database. " +
						"This should not happen, something is very wrong.");
			}
			final FindIterable<Document> cur = db.getCollection(COL_CONFIG)
					.find(Filters.eq(Fields.DB_SCHEMA_KEY, Fields.DB_SCHEMA_VALUE));
			final Document doc = cur.first();
			if ((Integer) doc.get(Fields.DB_SCHEMA_VERSION) != SCHEMA_VERSION) {
				throw new StorageInitException(String.format(
						"Incompatible database schema. Server is v%s, DB is v%s",
						SCHEMA_VERSION, doc.get(Fields.DB_SCHEMA_VERSION)));
			}
			if ((Boolean) doc.get(Fields.DB_SCHEMA_UPDATE)) {
				throw new StorageInitException(String.format(
						"The database is in the middle of an update from " +
								"v%s of the schema. Aborting startup.", 
								doc.get(Fields.DB_SCHEMA_VERSION)));
			}
		} catch (MongoException me) {
			throw new StorageInitException(
					"There was a problem communicating with the database: " + me.getMessage(), me);
		}
	}

	private void ensureIndexes() throws StorageInitException {
		for (String col: INDEXES.keySet()) {
			for (List<String> idx: INDEXES.get(col).keySet()) {
				final Document index = new Document();
				final IndexOptions opts = INDEXES.get(col).get(idx);
				for (String field: idx) {
					index.put(field, 1);
				}
				final MongoCollection<Document> dbcol = db.getCollection(col);
				try {
					if (opts == null) {
						dbcol.createIndex(index);
					} else {
						dbcol.createIndex(index, opts);
					}
				} catch (MongoException me) {
					throw new StorageInitException(
							"Failed to create index: " + me.getMessage(), me);
				}
			}
		}
	}

	@Override
	public void createLocalUser(final LocalUser local, final PasswordHashAndSalt creds)
			throws UserExistsException, AuthStorageException, NoSuchRoleException {
		nonNull(local, "local");
		nonNull(creds, "creds");
		final String encpwdhsh = Base64.getEncoder().encodeToString(creds.getPasswordHash());
		final String encsalt = Base64.getEncoder().encodeToString(creds.getSalt());
		final Set<String> roles = local.getRoles().stream().map(r -> r.getID())
				.collect(Collectors.toSet());
		final Collection<ObjectId> customRoles = getCustomRoleIds(local.getCustomRoles()).values();
		final Optional<UserName> admin = local.getAdminThatToggledEnabledState();
		final Optional<Instant> time = local.getEnableToggleDate();
		final Optional<String> reason = local.getReasonForDisabled();
		final Optional<Instant> reset = local.getLastPwdReset();
		final Document u = new Document(
				Fields.USER_NAME, local.getUserName().getName())
				.append(Fields.USER_LOCAL, true)
				.append(Fields.USER_EMAIL, local.getEmail().getAddress())
				.append(Fields.USER_DISPLAY_NAME, local.getDisplayName().getName())
				.append(Fields.USER_DISPLAY_NAME_CANONICAL, local.getDisplayName()
						.getCanonicalDisplayName())
				.append(Fields.USER_ROLES, roles)
				.append(Fields.USER_CUSTOM_ROLES, customRoles)
				.append(Fields.USER_IDENTITIES, local.getIdentities()) // better be empty
				.append(Fields.USER_POLICY_IDS, toDocument(local.getPolicyIDs()))
				.append(Fields.USER_CREATED, Date.from(local.getCreated()))
				.append(Fields.USER_LAST_LOGIN, local.getLastLogin().isPresent() ?
						Date.from(local.getLastLogin().get()) : null)
				.append(Fields.USER_DISABLED_ADMIN,
						admin.isPresent() ? admin.get().getName() : null)
				.append(Fields.USER_DISABLED_DATE, time.isPresent() ? Date.from(time.get()) : null)
				.append(Fields.USER_DISABLED_REASON, reason.isPresent() ? reason.get() : null)
				.append(Fields.USER_RESET_PWD, local.isPwdResetRequired())
				.append(Fields.USER_RESET_PWD_LAST, reset.isPresent() ?
						Date.from(reset.get()) : null)
				.append(Fields.USER_PWD_HSH, encpwdhsh)
				.append(Fields.USER_SALT, encsalt);
		try {
			db.getCollection(COL_USERS).insertOne(u);
		} catch (MongoWriteException mwe) {
			if (DuplicateKeyExceptionChecker.isDuplicate(mwe)) {
				throw new UserExistsException(local.getUserName().getName());
			} else {
				throw new AuthStorageException("Database write failed", mwe);
			}
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}
	
	@Override
	public LocalUser getLocalUser(final UserName userName)
			throws AuthStorageException, NoSuchLocalUserException {
		final Document user;
		try {
			user = getUserDoc(userName, true);
		} catch (NoSuchUserException e) {
			throw new NoSuchLocalUserException(userName.getName());
		}
		
		final LocalUser.Builder b = LocalUser.getLocalUserBuilder(
				getUserName(user.getString(Fields.USER_NAME)),
				getDisplayName(user.getString(Fields.USER_DISPLAY_NAME)),
				user.getDate(Fields.USER_CREATED).toInstant())
				.withEmailAddress(getEmail(user.getString(Fields.USER_EMAIL)))
				.withUserDisabledState(getUserDisabledState(user))
				.withForceReset(user.getBoolean(Fields.USER_RESET_PWD));
		addRoles(b, user);
		addCustomRoles(b, user);
		addPolicyIDs(b, user);
		addLastLogin(b, user);
		final Optional<Instant> pwdreset = getOptionalDate(user, Fields.USER_RESET_PWD_LAST);
		if (pwdreset.isPresent()) {
			b.withLastReset(pwdreset.get());
		}
		return b.build();
	}
	
	@Override
	public PasswordHashAndSalt getPasswordHashAndSalt(final UserName userName)
			throws AuthStorageException, NoSuchLocalUserException {
		nonNull(userName, "userName");
		final Document d = findOne(COL_USERS,
				new Document(Fields.USER_NAME, userName.getName())
						.append(Fields.USER_LOCAL, true),
				new Document(Fields.USER_SALT, 1)
						.append(Fields.USER_PWD_HSH, 1));
		if (d == null) {
			throw new NoSuchLocalUserException(userName.getName());
		}
		return new PasswordHashAndSalt(
				Base64.getDecoder().decode(d.getString(Fields.USER_PWD_HSH)),
				Base64.getDecoder().decode(d.getString(Fields.USER_SALT)));
	}
	
	private void addRoles(final AuthUser.AbstractBuilder<?> b, final Document user) {
		@SuppressWarnings("unchecked")
		final List<String> rolestr = (List<String>) user.get(Fields.USER_ROLES);
		final List<Role> roles = rolestr.stream().map(s -> Role.getRole(s))
				.collect(Collectors.toList());
		for (final Role r: roles) {
			b.withRole(r);
		}
	}

	private void addCustomRoles(final AuthUser.AbstractBuilder<?> b, final Document user)
			throws AuthStorageException {
		final UserName userName = getUserName(user.getString(Fields.USER_NAME));
		@SuppressWarnings("unchecked")
		final List<ObjectId> custroles = (List<ObjectId>) user.get(Fields.USER_CUSTOM_ROLES);
		for (final String cr: getCustomRoles(userName, new HashSet<>(custroles))) {
			b.withCustomRole(cr);
		}
	}
	
	private void addPolicyIDs(final AuthUser.AbstractBuilder<?> b, final Document user)
			throws AuthStorageException {
		try {
			@SuppressWarnings("unchecked")
			final List<Document> policies = (List<Document>) user.get(Fields.USER_POLICY_IDS);
			for (final Document policy: policies) {
				b.withPolicyID(new PolicyID(policy.getString(Fields.POLICY_ID)),
						policy.getDate(Fields.POLICY_AGREED_ON).toInstant());
			}
		} catch (IllegalParameterException | MissingParameterException e) {
			throw new AuthStorageException("Illegal value stored in db: " + e.getMessage(), e);
		}
	}
	
	private void addLastLogin(final AuthUser.AbstractBuilder<?> b, final Document user) {
		final Optional<Instant> ll = getOptionalDate(user, Fields.USER_LAST_LOGIN);
		if (ll.isPresent()) {
			b.withLastLogin(ll.get());
		}
	}

	private UserDisabledState getUserDisabledState(final Document user)
			throws AuthStorageException {
		try {
			return UserDisabledState.create(
					Optional.fromNullable(user.getString(Fields.USER_DISABLED_REASON)),
					Optional.fromNullable(getUserNameAllowNull(
							user.getString(Fields.USER_DISABLED_ADMIN))),
					getOptionalDate(user, Fields.USER_DISABLED_DATE));
		} catch (IllegalParameterException | MissingParameterException | IllegalStateException e) {
			throw new AuthStorageException("Illegal value stored in db: " + e.getMessage(), e);
		}
	}

	private UserName getUserNameAllowNull(final String namestr) throws AuthStorageException {
		if (namestr == null) {
			return null;
		}
		return getUserName(namestr);
	}

	private UserName getUserName(final String namestr) throws AuthStorageException {
		try {
			return new UserName(namestr);
		} catch (MissingParameterException | IllegalParameterException e) {
			throw new AuthStorageException("Illegal value stored in db: " + e.getMessage(), e);
		}
	}
	
	private DisplayName getDisplayName(final String displayName) throws AuthStorageException {
		try {
			return new DisplayName(displayName);
		} catch (IllegalParameterException | MissingParameterException e) {
			throw new AuthStorageException("Illegal value stored in db: " + e.getMessage() , e);
		}
	}
	
	private EmailAddress getEmail(final String email) throws AuthStorageException {
		if (email == null) {
			return EmailAddress.UNKNOWN;
		}
		try {
			return new EmailAddress(email);
		} catch (IllegalParameterException | MissingParameterException e) {
			throw new AuthStorageException("Illegal value stored in db: " + e.getMessage() , e);
		}
	}
	
	private InetAddress getIPAddress(final String ipAddress) throws AuthStorageException {
		if (ipAddress == null) {
			return null;
		}
		try {
			return InetAddress.getByName(ipAddress);
		} catch (UnknownHostException e) {
			throw new AuthStorageException("Illegal value stored in db: " + e.getMessage(), e);
		}
	}
	
	private TokenName getTokenName(final String tokenName) throws AuthStorageException {
		if (tokenName == null) {
			return null;
		}
		try {
			return new TokenName(tokenName);
		} catch (MissingParameterException | IllegalParameterException e) {
			throw new AuthStorageException("Illegal value stored in db: " + e.getMessage(), e);
		}
	}
	
	@Override
	public void changePassword(
			final UserName name,
			final PasswordHashAndSalt creds,
			final boolean forceReset)
			throws NoSuchUserException, AuthStorageException {
		nonNull(creds, "creds");
		getUserDoc(name, true); //check the user actually is local
		final String pwdhsh = Base64.getEncoder().encodeToString(creds.getPasswordHash());
		final String encsalt = Base64.getEncoder().encodeToString(creds.getSalt());
		final Document set = new Document(Fields.USER_RESET_PWD, forceReset)
				.append(Fields.USER_RESET_PWD_LAST, Date.from(clock.instant()))
				.append(Fields.USER_PWD_HSH, pwdhsh)
				.append(Fields.USER_SALT, encsalt);
		updateUser(name, set);
	}
	
	@Override
	public void forcePasswordReset(final UserName name)
			throws NoSuchUserException, AuthStorageException {
		getUserDoc(name, true); //check user is local. Could do this in one step but meh
		updateUser(name, new Document(Fields.USER_RESET_PWD, true));
	}
	
	@Override
	public void forcePasswordReset() throws AuthStorageException {
		try {
			db.getCollection(COL_USERS).updateMany(new Document(Fields.USER_LOCAL, true),
					new Document("$set", new Document(Fields.USER_RESET_PWD, true)));
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}
	
	@Override
	public void createUser(final NewUser newUser)
			throws UserExistsException, AuthStorageException, IdentityLinkedException,
			NoSuchRoleException {
		nonNull(newUser, "newUser");
		final Optional<UserName> admin = newUser.getAdminThatToggledEnabledState();
		final Optional<Instant> time = newUser.getEnableToggleDate();
		final Optional<String> reason = newUser.getReasonForDisabled();
		final Set<String> roles = newUser.getRoles().stream().map(r -> r.getID())
				.collect(Collectors.toSet());
		final Collection<ObjectId> customRoles = getCustomRoleIds(
				newUser.getCustomRoles()).values();
		final Document u = new Document(
				Fields.USER_NAME, newUser.getUserName().getName())
				.append(Fields.USER_LOCAL, false)
				.append(Fields.USER_EMAIL, newUser.getEmail().getAddress())
				.append(Fields.USER_DISPLAY_NAME, newUser.getDisplayName().getName())
				.append(Fields.USER_DISPLAY_NAME_CANONICAL, newUser.getDisplayName()
						.getCanonicalDisplayName())
				.append(Fields.USER_ROLES, roles)
				.append(Fields.USER_CUSTOM_ROLES, customRoles)
				.append(Fields.USER_IDENTITIES, Arrays.asList(toDocument(newUser.getIdentity())))
				.append(Fields.USER_POLICY_IDS, toDocument(newUser.getPolicyIDs()))
				.append(Fields.USER_CREATED, Date.from(newUser.getCreated()))
				.append(Fields.USER_LAST_LOGIN, newUser.getLastLogin().isPresent() ?
						Date.from(newUser.getLastLogin().get()) : null)
				.append(Fields.USER_DISABLED_ADMIN,
						admin.isPresent() ? admin.get().getName() : null)
				.append(Fields.USER_DISABLED_DATE, time.isPresent() ? Date.from(time.get()) : null)
				.append(Fields.USER_DISABLED_REASON, reason.isPresent() ? reason.get() : null);
		try {
			db.getCollection(COL_USERS).insertOne(u);
		} catch (MongoWriteException mwe) {
			// not happy about this, but getDetails() returns an empty map
			final DuplicateKeyExceptionChecker dk = new DuplicateKeyExceptionChecker(mwe);
			if (dk.isDuplicate() && COL_USERS.equals(dk.getCollection().get())) {
				if ((Fields.USER_NAME + "_1").equals(dk.getIndex().get())) {
					throw new UserExistsException(newUser.getUserName().getName());
				} else if (dk.getIndex().get().startsWith(Fields.USER_IDENTITIES + 
						Fields.FIELD_SEP)) {
					// either the provider / prov id combo or the local identity uuid are already
					// in the db
					throw new IdentityLinkedException(newUser.getIdentity().getRemoteID().getID());
				} // otherwise throw next exception
			}
			throw new AuthStorageException("Database write failed", mwe);
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}

	private List<Document> toDocument(final Map<PolicyID, Instant> policyIDs) {
		final List<Document> ret = new LinkedList<>();
		for (final Entry<PolicyID, Instant> policy: policyIDs.entrySet())
			ret.add(new Document(Fields.POLICY_ID, policy.getKey().getName())
					.append(Fields.POLICY_AGREED_ON, Date.from(policy.getValue())));
		return ret;
	}

	private Document getUserDoc(final UserName userName, final boolean local)
			throws AuthStorageException, NoSuchUserException {
		nonNull(userName, "userName");
		final Document projection = new Document(Fields.USER_PWD_HSH, 0)
				.append(Fields.USER_SALT, 0);
		final Document user = findOne(COL_USERS,
				new Document(Fields.USER_NAME, userName.getName()), projection);
		if (user == null) {
			throw new NoSuchUserException(userName.getName());
		}
		if (local && !user.getBoolean(Fields.USER_LOCAL)) {
			throw new NoSuchLocalUserException(userName.getName());
		}
		return user;
	}

	@Override
	public void disableAccount(final UserName user, final UserName admin, final String reason)
			throws NoSuchUserException, AuthStorageException {
		if (reason == null || reason.trim().isEmpty()) {
			throw new IllegalArgumentException("reason cannot be null or empty");
		}
		toggleAccount(user, admin, reason);
	}

	private void toggleAccount(final UserName user, final UserName admin, final String reason)
			throws NoSuchUserException, AuthStorageException {
		nonNull(admin, "admin");
		final Document update = new Document(Fields.USER_DISABLED_REASON, reason)
				.append(Fields.USER_DISABLED_ADMIN, admin.getName())
				.append(Fields.USER_DISABLED_DATE, Date.from(clock.instant()));
		updateUser(user, update);
	}
	
	@Override
	public void enableAccount(final UserName user, final UserName admin)
			throws NoSuchUserException, AuthStorageException {
		toggleAccount(user, admin, null);
	}

	@Override
	public void storeToken(final StoredToken token, final String hash)
			throws AuthStorageException {
		storeToken(COL_TOKEN, token, hash);
	}
	
	@Override
	public void testModeStoreToken(final StoredToken token, final String hash)
			throws AuthStorageException {
		storeToken(COL_TEST_TOKEN, token, hash);
	}

	private void storeToken(final String collection, final StoredToken token, final String hash)
			throws AuthStorageException {
		nonNull(token, "token");
		checkStringNoCheckedException(hash, "hash");
		final Optional<TokenName> tokenName = token.getTokenName();
		final TokenCreationContext ctx = token.getContext();
		final Document td = new Document(
				Fields.TOKEN_TYPE, token.getTokenType().getID())
				.append(Fields.TOKEN_USER_NAME, token.getUserName().getName())
				.append(Fields.TOKEN_ID, token.getId().toString())
				.append(Fields.TOKEN_NAME, tokenName.isPresent() ?
						tokenName.get().getName() : null)
				.append(Fields.TOKEN_TOKEN, hash)
				.append(Fields.TOKEN_EXPIRY, Date.from(token.getExpirationDate()))
				.append(Fields.TOKEN_CREATION, Date.from(token.getCreationDate()))
				.append(Fields.TOKEN_AGENT, ctx.getAgent().orNull())
				.append(Fields.TOKEN_AGENT_VER, ctx.getAgentVersion().orNull())
				.append(Fields.TOKEN_OS, ctx.getOS().orNull())
				.append(Fields.TOKEN_OS_VER, ctx.getOSVersion().orNull())
				.append(Fields.TOKEN_DEVICE, ctx.getDevice().orNull())
				.append(Fields.TOKEN_IP, ctx.getIpAddress().isPresent() ?
						ctx.getIpAddress().get().getHostAddress() : null)
				.append(Fields.TOKEN_CUSTOM_CONTEXT, toCustomContextList(ctx.getCustomContext()));
		try {
			db.getCollection(collection).insertOne(td);
		} catch (MongoWriteException mwe) {
			// not happy about this, but getDetails() returns an empty map
			final DuplicateKeyExceptionChecker dk = new DuplicateKeyExceptionChecker(mwe);
			if (dk.isDuplicate() && collection.equals(dk.getCollection().get())) {
				if ((Fields.TOKEN_ID + "_1").equals(dk.getIndex().get())) {
					throw new IllegalArgumentException(String.format(
							"Token ID %s already exists in the database", token.getId()));
				} else if ((Fields.TOKEN_TOKEN + "_1").equals(dk.getIndex().get())) {
					throw new IllegalArgumentException(String.format(
							"Token hash for token ID %s already exists in the database",
							token.getId()));
				} // otherwise throw next exception
			}
			throw new AuthStorageException("Database write failed", mwe);
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}

	private List<Document> toCustomContextList(
			final Map<String, String> customContext) {
		final List<Document> ret = new LinkedList<>();
		for (final Entry<String, String> e: customContext.entrySet()) {
			ret.add(new Document(Fields.TOKEN_CUSTOM_KEY, e.getKey())
					.append(Fields.TOKEN_CUSTOM_VALUE, e.getValue()));
		}
		return ret;
	}

	/* Use this for finding documents where indexes should force only a single
	 * document. Assumes the indexes are doing their job.
	 */
	private Document findOne(
			final String collection,
			final Document query)
			throws AuthStorageException {
		return findOne(collection, query, null);
	}
	
	/* Use this for finding documents where indexes should force only a single
	 * document. Assumes the indexes are doing their job.
	 */
	private Document findOne(
			final String collection,
			final Document query,
			final Document projection)
			throws AuthStorageException {
		try {
			return db.getCollection(collection).find(query).projection(projection).first();
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}

	@Override
	public StoredToken getToken(final IncomingHashedToken token)
			throws AuthStorageException, NoSuchTokenException {
		return getToken(COL_TOKEN, token);
	}
	
	@Override
	public StoredToken testModeGetToken(final IncomingHashedToken token)
			throws NoSuchTokenException, AuthStorageException {
		return getToken(COL_TEST_TOKEN, token);
	}

	private StoredToken getToken(final String collection, final IncomingHashedToken token)
			throws AuthStorageException, NoSuchTokenException {
		nonNull(token, "token");
		final Document t = findOne(collection,
				new Document(Fields.TOKEN_TOKEN, token.getTokenHash()),
				new Document(Fields.TOKEN_TOKEN, 0));
		if (t == null) {
			throw new NoSuchTokenException("Token not found");
		}
		final StoredToken htoken = getToken(t);
		/* although expired tokens are automatically deleted from the DB by mongo, the thread
		 * only runs ~1/min, so check here
		 */
		if (Instant.now().isAfter(htoken.getExpirationDate())) {
			throw new NoSuchTokenException("Token not found");
		}
		return htoken;
	}
	
	private StoredToken getToken(final Document t) throws AuthStorageException {
		return StoredToken.getBuilder(
					TokenType.getType(t.getString(Fields.TOKEN_TYPE)),
					UUID.fromString(t.getString(Fields.TOKEN_ID)),
					getUserName(t.getString(Fields.TOKEN_USER_NAME)))
				.withLifeTime(
						t.getDate(Fields.TOKEN_CREATION).toInstant(),
						t.getDate(Fields.TOKEN_EXPIRY).toInstant())
				.withNullableTokenName(getTokenName(t.getString(Fields.TOKEN_NAME)))
				.withContext(toTokenCreationContext(t))
				.build();
	}
	
	private TokenCreationContext toTokenCreationContext(final Document t)
			throws AuthStorageException {
		final TokenCreationContext.Builder b = TokenCreationContext.getBuilder()
				.withNullableIpAddress(getIPAddress(t.getString(Fields.TOKEN_IP)))
				.withNullableAgent(t.getString(Fields.TOKEN_AGENT),
						t.getString(Fields.TOKEN_AGENT_VER))
				.withNullableOS(t.getString(Fields.TOKEN_OS), t.getString(Fields.TOKEN_OS_VER))
				.withNullableDevice(t.getString(Fields.TOKEN_DEVICE));
		
		@SuppressWarnings("unchecked")
		final List<Document> custom = (List<Document>) t.get(Fields.TOKEN_CUSTOM_CONTEXT);
		if (custom != null) { // backwards compatibility
			for (final Document c: custom) {
				try {
					b.withCustomContext(c.getString(Fields.TOKEN_CUSTOM_KEY),
							c.getString(Fields.TOKEN_CUSTOM_VALUE));
				} catch (MissingParameterException | IllegalParameterException e) {
					throw new AuthStorageException(
							"Illegal value stored in db: " + e.getMessage(), e);
				}
			}
		}
		return b.build();
	}

	@Override
	public Set<StoredToken> getTokens(final UserName userName) throws AuthStorageException {
		nonNull(userName, "userName");
		final Set<StoredToken> ret = new HashSet<>();
		try {
			final FindIterable<Document> ts = db.getCollection(COL_TOKEN).find(
					new Document(Fields.TOKEN_USER_NAME, userName.getName())).projection(
					new Document(Fields.TOKEN_TOKEN, 0));
			for (final Document d: ts) {
				ret.add(getToken(d));
			}
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
		return ret;
	}
	
	@Override
	public AuthUser getUser(final UserName userName)
			throws AuthStorageException, NoSuchUserException {
		return toUser(getUserDoc(userName, false));
	}

	private AuthUser toUser(final Document user) throws AuthStorageException {
		@SuppressWarnings("unchecked")
		final List<Document> ids = (List<Document>) user.get(Fields.USER_IDENTITIES);
		
		final AuthUser.Builder b = AuthUser.getBuilder(
				getUserName(user.getString(Fields.USER_NAME)),
				getDisplayName(user.getString(Fields.USER_DISPLAY_NAME)),
				user.getDate(Fields.USER_CREATED).toInstant())
				.withEmailAddress(getEmail(user.getString(Fields.USER_EMAIL)))
				.withUserDisabledState(getUserDisabledState(user));
		for (final RemoteIdentity ri: toIdentities(ids)) {
			b.withIdentity(ri);
		}
		addRoles(b, user);
		addCustomRoles(b, user);
		addPolicyIDs(b, user);
		addLastLogin(b, user);
		return b.build();
	}
	
	private Optional<Instant> getOptionalDate(final Document d, final String field) {
		if (d.get(field) != null) {
			return Optional.of(d.getDate(field).toInstant());
		} else {
			return Optional.absent();
		}
	}
	
	@Override
	public Map<UserName, DisplayName> getUserDisplayNames(final Set<UserName> users)
			throws AuthStorageException {
		nonNull(users, "users");
		Utils.noNulls(users, "Null username in users set");
		if (users.isEmpty()) {
			return new HashMap<>();
		}
		final List<String> queryusers = users.stream().map(u -> u.getName())
				.collect(Collectors.toList());
		final Document query = new Document(Fields.USER_NAME, new Document("$in", queryusers))
				.append(Fields.USER_DISABLED_REASON, null);
		return getDisplayNames(query, Fields.USER_NAME, -1);
	}

	private Map<UserName, DisplayName> getDisplayNames(
			final Document query,
			final String sortField,
			final int limit)
			throws AuthStorageException {
		final Document projection = new Document(Fields.USER_NAME, 1)
				.append(Fields.USER_DISPLAY_NAME, 1);
		try {
			final FindIterable<Document> docs = db.getCollection(COL_USERS)
					.find(query).projection(projection);
			if (limit > 0) {
				docs.sort(new Document(sortField, 1)).limit(limit);
			}
			final Map<UserName, DisplayName> ret = new HashMap<>();
			for (final Document d: docs) {
				ret.put(getUserName(d.getString(Fields.USER_NAME)),
						getDisplayName(d.getString(Fields.USER_DISPLAY_NAME)));
			}
			return ret;
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}
	
	private static final Map<UserSearchSpec.SearchField, String> SEARCHFIELD_TO_FIELD;
	static {
		final Map<UserSearchSpec.SearchField, String> m = new HashMap<>();
		m.put(UserSearchSpec.SearchField.USERNAME, Fields.USER_NAME);
		m.put(UserSearchSpec.SearchField.DISPLAYNAME, Fields.USER_DISPLAY_NAME_CANONICAL);
		m.put(UserSearchSpec.SearchField.ROLE, Fields.USER_ROLES);
		m.put(UserSearchSpec.SearchField.CUSTOMROLE, Fields.USER_CUSTOM_ROLES);
		SEARCHFIELD_TO_FIELD = m;
	}

	@Override
	public Map<UserName, DisplayName> getUserDisplayNames(
			final UserSearchSpec spec,
			final int limit)
			throws AuthStorageException {
		nonNull(spec, "spec");
		final Document query = new Document();
		if (spec.getSearchPrefix().isPresent()) {
			final String prefix = spec.getSearchPrefix().get();
			final List<Document> queries = new LinkedList<>();
			final Document regex = new Document("$regex", spec.isRegex() ? prefix :
				"^" + Pattern.quote(prefix.toLowerCase()));
			if (spec.isDisplayNameSearch()) {
				queries.add(new Document(Fields.USER_DISPLAY_NAME_CANONICAL, regex));
			}
			if (spec.isUserNameSearch()) {
				queries.add(new Document(Fields.USER_NAME, regex));
			}
			if (queries.size() == 1) {
				query.putAll(queries.get(0));
			} else {
				query.put("$or", queries);
			}
			
		}
		if (spec.isRoleSearch()) {
			query.put(Fields.USER_ROLES, new Document("$all", spec.getSearchRoles()
					.stream().map(r -> r.getID()).collect(Collectors.toSet())));
		}
		if (spec.isCustomRoleSearch()) {
			final Set<Document> crs = getCustomRoles(new Document(Fields.ROLES_ID,
					new Document("$in", spec.getSearchCustomRoles())));
			query.put(Fields.USER_CUSTOM_ROLES, new Document("$all", crs.stream()
					.map(d -> d.getObjectId(Fields.MONGO_ID)).collect(Collectors.toSet())));
		}
		if (!spec.isDisabledIncluded()) {
			query.put(Fields.USER_DISABLED_REASON, null);
		}
		return getDisplayNames(query, SEARCHFIELD_TO_FIELD.get(spec.orderBy()), limit);
	}

	@Override
	public void deleteToken(final UserName userName, final UUID tokenId)
			throws AuthStorageException, NoSuchTokenException {
		nonNull(userName, "userName");
		nonNull(tokenId, "tokenId");
		try {
			final DeleteResult dr = db.getCollection(COL_TOKEN)
					.deleteOne(new Document(Fields.TOKEN_USER_NAME, userName.getName())
							.append(Fields.TOKEN_ID, tokenId.toString()));
			if (dr.getDeletedCount() != 1L) {
				throw new NoSuchTokenException(String.format(
						"No token %s for user %s exists",
						tokenId, userName.getName()));
			}
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}

	@Override
	public void deleteTokens(final UserName userName)
			throws AuthStorageException {
		nonNull(userName, "userName");
		deleteTokens(new Document(Fields.TOKEN_USER_NAME, userName.getName()));
	}

	private void deleteTokens(final Document document) throws AuthStorageException {
		try {
			db.getCollection(COL_TOKEN).deleteMany(document);
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed", e);
		}
	}
	
	@Override
	public void deleteTokens() throws AuthStorageException {
		deleteTokens(new Document());
	}

	@Override
	public void updateRoles(
			final UserName userName,
			final Set<Role> addRoles,
			final Set<Role> removeRoles)
			throws AuthStorageException, NoSuchUserException {
		nonNull(addRoles, "addRoles");
		nonNull(removeRoles, "removeRoles");
		if (addRoles.contains(Role.ROOT) || removeRoles.contains(Role.ROOT)) {
			// I don't like this at all. The whole way the root user is managed needs a rethink.
			// note that the Authorization code shouldn't allow this either, but to be safe...
			throw new IllegalArgumentException("Cannot change root role");
		}
		Utils.noNulls(addRoles, "Null role in addRoles");
		Utils.noNulls(removeRoles, "Null role in removeRoles");
		final Set<Object> stradd = addRoles.stream().map(r -> r.getID())
				.collect(Collectors.toSet());
		final Set<Object> strremove = removeRoles.stream().map(r -> r.getID())
				.collect(Collectors.toSet());
		setRoles(userName, stradd, strremove, Fields.USER_ROLES);
	}

	private void setRoles(
			final UserName userName,
			final Set<Object> addRoles,
			final Set<Object> removeRoles,
			final String field)
			throws NoSuchUserException, AuthStorageException {
		nonNull(userName, "userName");
		if (addRoles.isEmpty() && removeRoles.isEmpty()) {
			return;
		}
		final Document query = new Document(Fields.USER_NAME, userName.getName());
		try {
			// ordered is true by default
			// http://api.mongodb.com/java/3.3/com/mongodb/client/model/BulkWriteOptions.html
			final BulkWriteResult res = db.getCollection(COL_USERS).bulkWrite(Arrays.asList(
					new UpdateOneModel<>(query, new Document("$addToSet",
							new Document(field, new Document("$each", addRoles)))),
					new UpdateOneModel<>(query, new Document("$pull",
							new Document(field, new Document("$in", removeRoles))))));
			// might not modify the roles if they're the same as input so don't check modified
			if (res.getMatchedCount() != 2) {
				throw new NoSuchUserException(userName.getName());
			}
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}
	
	@Override
	public void setCustomRole(final CustomRole role) throws AuthStorageException {
		nonNull(role, "role");
		try {
			db.getCollection(COL_CUST_ROLES).updateOne(
					new Document(Fields.ROLES_ID, role.getID()),
					new Document("$set", new Document(Fields.ROLES_DESC, role.getDesc())),
					new UpdateOptions().upsert(true));
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}
	
	@Override
	public void deleteCustomRole(final String roleId)
			throws NoSuchRoleException, AuthStorageException,
			MissingParameterException, IllegalParameterException {
		CustomRole.checkValidRoleID(roleId);
		try {
			final Document role = db.getCollection(COL_CUST_ROLES).findOneAndDelete(
					new Document(Fields.ROLES_ID, roleId));
			if (role == null) {
				throw new NoSuchRoleException(roleId);
			}
			/* note that in the getCustomRoles() method the user's roles are checked against the
			 * db and removed if they don't exist, which protects against race conditions and
			 * mongo / server downs.
			 */
			db.getCollection(COL_USERS).updateMany(new Document(), new Document("$pull",
					new Document(Fields.USER_CUSTOM_ROLES, role.getObjectId(Fields.MONGO_ID))));
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}
	
	@Override
	public Set<CustomRole> getCustomRoles() throws AuthStorageException {
		return toCustomRoles(getCustomRoles(new Document()));
	}

	private Set<Document> getCustomRoles(final Document query)
			throws AuthStorageException {
		try {
			final FindIterable<Document> roles = db.getCollection(COL_CUST_ROLES).find(query);
			final Set<Document> ret = new HashSet<>();
			for (final Document d: roles) {
				ret.add(d);
			}
			return ret;
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}
	
	private Set<CustomRole> toCustomRoles(final Set<Document> roledocs)
			throws AuthStorageException {
		final Set<CustomRole> ret = new HashSet<>();
		for (final Document d: roledocs) {
			try {
				ret.add(new CustomRole(d.getString(Fields.ROLES_ID),
						d.getString(Fields.ROLES_DESC)));
			} catch (MissingParameterException | IllegalParameterException e) {
				throw new AuthStorageException(
						"Error in roles collection - role with illegal or missing field", e);
			}
		}
		return ret;
	}

	private Set<String> getCustomRoles(final UserName user, final Set<ObjectId> roleIds)
			throws AuthStorageException {
		final Set<Document> roledocs = getCustomRoles(new Document(
				Fields.MONGO_ID, new Document("$in", roleIds)));
		final Set<ObjectId> extantRoleIds = roledocs.stream()
				.map(d -> d.getObjectId(Fields.MONGO_ID)).collect(Collectors.toSet());
		for (final ObjectId role: roleIds) {
			if (!extantRoleIds.contains(role)) {
				// should very rarely happen, if at all, so don't worry about optimization
				final Document query = new Document(Fields.USER_NAME, user.getName());
				final Document mod = new Document("$pull",
						new Document(Fields.USER_CUSTOM_ROLES, role));
				try {
					// don't care if no changes are made, just means the role is already gone
					db.getCollection(COL_USERS).updateOne(query, mod);
				} catch (MongoException e) {
					throw new AuthStorageException("Connection to database failed: " +
							e.getMessage(), e);
				}
			}
		}
		return roledocs.stream().map(d -> d.getString(Fields.ROLES_ID))
				.collect(Collectors.toSet());
	}

	@Override
	public void updateCustomRoles(
			final UserName userName,
			final Set<String> addRoles,
			final Set<String> removeRoles)
			throws NoSuchUserException, AuthStorageException, NoSuchRoleException {
		nonNull(addRoles, "addRoles");
		nonNull(removeRoles, "removeRoles");
		Utils.noNulls(addRoles, "Null role in addRoles");
		Utils.noNulls(removeRoles, "Null role in removeRoles");
		final Set<String> allRoles = new HashSet<>(addRoles);
		allRoles.addAll(removeRoles);
		final Map<String, ObjectId> roleIDs = getCustomRoleIds(allRoles);
		final Set<Object> addRoleIDs = addRoles.stream().map(r -> roleIDs.get(r))
				.collect(Collectors.toSet());
		final Set<Object> removeRoleIDs = removeRoles.stream().map(r -> roleIDs.get(r))
				.collect(Collectors.toSet());
		setRoles(userName, addRoleIDs, removeRoleIDs, Fields.USER_CUSTOM_ROLES);
	}

	private Map<String, ObjectId> getCustomRoleIds(final Set<String> roles)
			throws AuthStorageException, NoSuchRoleException {
		if (roles.isEmpty()) {
			return new HashMap<>();
		}
		final Map<String, ObjectId> roleIDs =  getCustomRoles(new Document(
				Fields.ROLES_ID, new Document("$in", roles))).stream()
						.collect(Collectors.toMap(
								d -> d.getString(Fields.ROLES_ID),
								d -> d.getObjectId(Fields.MONGO_ID)));
		if (roles.size() != roleIDs.size()) {
			final Set<String> rolescopy = new HashSet<>(roles);
			rolescopy.removeAll(roleIDs.keySet());
			throw new NoSuchRoleException(rolescopy.iterator().next());
		}
		return roleIDs;
	}

	@Override
	public Optional<AuthUser> getUser(final RemoteIdentity remoteID) throws AuthStorageException {
		final Document query = makeUserQuery(remoteID);
		//note a user with identities should never have these fields, but
		//doesn't hurt to be safe
		final Document projection = new Document(Fields.USER_PWD_HSH, 0)
				.append(Fields.USER_SALT, 0);
		final Document u = findOne(COL_USERS, query, projection);
		if (u == null) {
			return Optional.absent();
		}
		AuthUser user = toUser(u);
		/* could do a findAndModify to set the fields on the first query, but
		 * 99% of the time a set won't be necessary, so don't write lock the
		 * DB/collection (depending on mongo version) unless necessary 
		 */
		RemoteIdentity update = null;
		for (final RemoteIdentity ri: user.getIdentities()) {
			if (ri.getRemoteID().equals(remoteID.getRemoteID()) &&
					!ri.getDetails().equals(remoteID.getDetails())) {
				update = ri;
			}
		}
		if (update != null) {
			final AuthUser.Builder b = AuthUser.getBuilderWithoutIdentities(user);
			for (final RemoteIdentity ri: user.getIdentities()) {
				if (!ri.equals(update)) {
					b.withIdentity(ri);
				}
			}
			b.withIdentity(remoteID);
			user = b.build();
			updateIdentity(remoteID);
		}
		return Optional.of(user);
	}

	private Document makeUserQuery(final RemoteIdentity remoteID) {
		return new Document(Fields.USER_IDENTITIES + Fields.FIELD_SEP + Fields.IDENTITIES_ID,
				remoteID.getRemoteID().getID());
	}
	
	private void updateIdentity(final RemoteIdentity remoteID)
			throws AuthStorageException {
		final Document query = makeUserQuery(remoteID);
		
		final String pre = Fields.USER_IDENTITIES + ".$.";
		final RemoteIdentityDetails rid = remoteID.getDetails();
		final Document update = new Document("$set",
				new Document(pre + Fields.IDENTITIES_USER, rid.getUsername())
				.append(pre + Fields.IDENTITIES_EMAIL, rid.getEmail())
				.append(pre + Fields.IDENTITIES_NAME, rid.getFullname()));
		try {
			// id might have been unlinked, so we just assume
			// the update worked. If it was just unlinked we don't care.
			db.getCollection(COL_USERS).updateOne(query, update);
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}
	
	private static class DuplicateKeyExceptionChecker {
		// super hacky and fragile, but doesn't seem another way to do this.
		
		private final Pattern keyPattern = Pattern.compile("dup key:\\s+\\{ : \"(.*)\" \\}");
		private final Pattern indexPattern = Pattern.compile(
				"duplicate key error (index|collection): " +
				"\\w+\\.(\\w+)( index: |\\.\\$)([\\.\\w]+)\\s+");
		
		private final boolean isDuplicate;
		private final Optional<String> collection;
		private final Optional<String> index;
		private final Optional<String> key;
		
		public DuplicateKeyExceptionChecker(final MongoWriteException mwe)
				throws AuthStorageException {
			// split up indexes better at some point - e.g. in a Document
			isDuplicate = isDuplicate(mwe);
			if (isDuplicate) {
				final Matcher indexMatcher = indexPattern.matcher(mwe.getMessage());
				if (indexMatcher.find()) {
					collection = Optional.of(indexMatcher.group(2));
					index = Optional.of(indexMatcher.group(4));
				} else {
					throw new AuthStorageException("Unable to parse duplicate key error: " +
							// could include a token hash as the key, so split it out if it's there
							mwe.getMessage().split("dup key")[0], mwe);
				}
				final Matcher keyMatcher = keyPattern.matcher(mwe.getMessage());
				if (keyMatcher.find()) {
					key = Optional.of(keyMatcher.group(1));
				} else { // some errors include the dup key, some don't
					key = Optional.absent();
				}
			} else {
				collection = Optional.absent();
				index = Optional.absent();
				key = Optional.absent();
			}
			
		}
		
		public static boolean isDuplicate(final MongoWriteException mwe) {
			return mwe.getError().getCategory().equals(ErrorCategory.DUPLICATE_KEY);
		}

		public boolean isDuplicate() {
			return isDuplicate;
		}

		public Optional<String> getCollection() {
			return collection;
		}

		public Optional<String> getIndex() {
			return index;
		}

		@SuppressWarnings("unused") // may need later
		public Optional<String> getKey() {
			return key;
		}
	}
	
	@Override
	public void storeTemporarySessionData(final TemporarySessionData data, final String hash)
			throws AuthStorageException {
		nonNull(data, "data");
		checkStringNoCheckedException(hash, "hash");
		final Set<Document> ids;
		if (data.getIdentities().isPresent()) {
			ids = toDocument(data.getIdentities().get());
		} else {
			ids = new HashSet<>();
		}
		final Document td = new Document(
				Fields.TEMP_SESSION_ID, data.getId().toString())
				.append(Fields.TEMP_SESSION_OPERATION, data.getOperation().toString())
				.append(Fields.TEMP_SESSION_TOKEN, hash)
				.append(Fields.TEMP_SESSION_EXPIRY, Date.from(data.getExpires()))
				.append(Fields.TEMP_SESSION_CREATION, Date.from(data.getCreated()))
				.append(Fields.TEMP_SESSION_ERROR,
						data.getError().isPresent() ? data.getError().get() : null)
				.append(Fields.TEMP_SESSION_ERROR_TYPE, data.getErrorType().isPresent() ?
						data.getErrorType().get().getErrorCode() : null)
				.append(Fields.TEMP_SESSION_IDENTITIES, ids)
				.append(Fields.TEMP_SESSION_USER,
						data.getUser().isPresent() ? data.getUser().get().getName() : null);
		storeTemporarySessionData(td);
	}

	private void storeTemporarySessionData(final Document td) throws AuthStorageException {
		try {
			db.getCollection(COL_TEMP_DATA).insertOne(td);
		} catch (MongoWriteException mwe) {
			// not happy about this, but getDetails() returns an empty map
			final DuplicateKeyExceptionChecker dk = new DuplicateKeyExceptionChecker(mwe);
			if (dk.isDuplicate() && COL_TEMP_DATA.equals(dk.getCollection().get())) {
				if ((Fields.TEMP_SESSION_ID + "_1").equals(dk.getIndex().get())) {
					throw new IllegalArgumentException(String.format(
							"Temporary token ID %s already exists in the database",
							td.getString(Fields.TEMP_SESSION_ID)));
				} else if ((Fields.TEMP_SESSION_TOKEN + "_1").equals(dk.getIndex().get())) {
					throw new IllegalArgumentException(String.format(
							"Token hash for temporary token ID %s already exists in the database",
							td.getString(Fields.TEMP_SESSION_ID)));
				}
			} // otherwise throw next exception
			throw new AuthStorageException("Database write failed", mwe);
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}
	
	private Document toDocument(final RemoteIdentity id) {
		final RemoteIdentityDetails rid = id.getDetails();
		return new Document(Fields.IDENTITIES_ID, id.getRemoteID().getID())
				.append(Fields.IDENTITIES_PROVIDER, id.getRemoteID().getProviderName())
				.append(Fields.IDENTITIES_PROV_ID, id.getRemoteID().getProviderIdentityId())
				.append(Fields.IDENTITIES_USER, rid.getUsername())
				.append(Fields.IDENTITIES_NAME, rid.getFullname())
				.append(Fields.IDENTITIES_EMAIL, rid.getEmail());
	}
	
	@Override
	public TemporarySessionData getTemporarySessionData(
			final IncomingHashedToken token)
			throws AuthStorageException, NoSuchTokenException {
		nonNull(token, "token");
		final Document d = findOne(COL_TEMP_DATA,
				new Document(Fields.TEMP_SESSION_TOKEN, token.getTokenHash()));
		if (d == null) {
			throw new NoSuchTokenException("Token not found");
		}
		// if we do this anywhere else should make a method to go from doc -> temptoken class
		if (Instant.now().isAfter(d.getDate(Fields.TEMP_SESSION_EXPIRY).toInstant())) {
			throw new NoSuchTokenException("Token not found");
		}
		final Builder b = TemporarySessionData.create(
				UUID.fromString(d.getString(Fields.TOKEN_ID)),
				d.getDate(Fields.TOKEN_CREATION).toInstant(),
				d.getDate(Fields.TOKEN_EXPIRY).toInstant());
		final Operation op = Operation.valueOf(d.getString(Fields.TEMP_SESSION_OPERATION));
		final TemporarySessionData tis;
		@SuppressWarnings("unchecked")
		final List<Document> ids = (List<Document>) d.get(Fields.TEMP_SESSION_IDENTITIES);
		if (op.equals(Operation.ERROR)) {
			tis = b.error(d.getString(Fields.TEMP_SESSION_ERROR),
					ErrorType.fromErrorCode(d.getInteger(Fields.TEMP_SESSION_ERROR_TYPE)));
		} else if (op.equals(Operation.LOGIN)) {
			tis = b.login(toIdentities(ids));
		} else if (op.equals(Operation.LINKSTART)) {
			tis = b.link(getUserName(d.getString(Fields.TEMP_SESSION_USER)));
		} else if (op.equals(Operation.LINKIDENTS)) {
			tis = b.link(getUserName(d.getString(Fields.TEMP_SESSION_USER)),
					toIdentities(ids));
		} else {
			// no way to test this
			throw new RuntimeException("Unexpected operation " + op);
		}
		return tis;
	}

	private Set<RemoteIdentity> toIdentities(final List<Document> ids) {
		final Set<RemoteIdentity> ret = new HashSet<>();
		for (final Document i: ids) {
			final RemoteIdentityID rid = new RemoteIdentityID(
					i.getString(Fields.IDENTITIES_PROVIDER),
					i.getString(Fields.IDENTITIES_PROV_ID));
			final RemoteIdentityDetails det = new RemoteIdentityDetails(
					i.getString(Fields.IDENTITIES_USER),
					i.getString(Fields.IDENTITIES_NAME),
					i.getString(Fields.IDENTITIES_EMAIL));
			ret.add(new RemoteIdentity(rid, det));
		}
		return ret;
	}
	
	@Override
	public Optional<UUID> deleteTemporarySessionData(final IncomingHashedToken token)
			throws AuthStorageException {
		nonNull(token, "token");
		try {
			final Document tempIds = db.getCollection(COL_TEMP_DATA).findOneAndDelete(
					new Document(Fields.TEMP_SESSION_TOKEN, token.getTokenHash()),
					new FindOneAndDeleteOptions().projection(
							new Document(Fields.TEMP_SESSION_ID, 1)));
			if (tempIds == null) {
				return Optional.absent();
			} else {
				return Optional.of(UUID.fromString(tempIds.getString(Fields.TEMP_SESSION_ID)));
			}
			// if it's not there, fine. Job's done.
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}
	
	@Override
	public long deleteTemporarySessionData(final UserName userName) throws AuthStorageException {
		/* would be nice to return the deleted IDs, but it doesn't seem like there's any way to 
		 * to so that isn't subject to race conditions that could mean deleted IDs are missing from
		 * the list
		 */
		nonNull(userName, "userName");
		try {
			final DeleteResult tempIds = db.getCollection(COL_TEMP_DATA).deleteMany(
					new Document(Fields.TEMP_SESSION_USER, userName.getName()));
			return tempIds.getDeletedCount();
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}
	
	/* See notes for this method between this method and the next. These two methods are tightly
	 * coupled.
	 */
	@Override
	public boolean link(final UserName user, final RemoteIdentity remoteID)
			throws NoSuchUserException, AuthStorageException, LinkFailedException,
			IdentityLinkedException {
		int count = 0;
		int complete = -1;
		while (complete < 0) {
			count++;
			if (count > 5) {
				// there's not really any way to test this without some crazy timing stuff
				throw new RuntimeException("Attempted link update 5 times without success. " +
						"There's probably a programming error here.");
			}
			complete = addIdentity(getUser(user), remoteID);
		}
		return complete == 1;
	}
	
	/* The methods above and below are split for two reasons: 1) readability, and 2) so that
	 * tests can use reflection to exercise the method below with the case where the user 
	 * identities change between getting the user and updating the identities due to a race
	 * condition.
	 */
	
	/* return:
	 * -1 try again
	 * 0 already linked
	 * 1 link added
	 */
	private int addIdentity(
			final AuthUser user,
			final RemoteIdentity remoteID)
			throws NoSuchUserException, AuthStorageException, LinkFailedException,
			IdentityLinkedException {
		/* This method is written as it is to avoid adding the same provider ID to a user twice.
		 * Since mongodb unique indexes only enforce uniqueness between documents, not within
		 * documents, adding the same provider ID to a single document twice is possible without
		 * careful db updates.
		 */
		nonNull(remoteID, "remoteID");
		if (user.isLocal()) {
			throw new LinkFailedException("Cannot link identities to a local user");
		}
		// firstly check to see if the ID is already linked. If so, just update the associated
		// user info.
		for (final RemoteIdentity ri: user.getIdentities()) {
			if (ri.getRemoteID().equals(remoteID.getRemoteID())) {
				// if the details are the same, there's nothing to do, user is already linked and
				// user info is the same
				if (!ri.getDetails().equals(remoteID.getDetails())) {
					updateIdentity(remoteID);
				}
				return 0; // update complete
			}
		}
		
		/* ok, we need to link. To ensure we don't add the identity twice, we search for a user
		 * that does not have an identity ID matching the new remote identity ID, and if so add
		 * the new id. If a remote identity with the same identity ID (e.g. the provider and
		 * provider account id are the same) has been linked in the time since pulling the user
		 * from the database the update will fail and we try again by calling this function again.
		 */

		final Document query = new Document(Fields.USER_NAME, user.getUserName().getName())
				.append(Fields.USER_IDENTITIES + Fields.FIELD_SEP + Fields.IDENTITIES_ID,
						new Document("$ne", remoteID.getRemoteID().getID()));
		final Document update = new Document("$addToSet",
				new Document(Fields.USER_IDENTITIES, toDocument(remoteID)));
		try {
			final UpdateResult r = db.getCollection(COL_USERS).updateOne(query, update);
			// return true if the user was updated, false otherwise (meaning retry and call this
			// method again)
			return r.getModifiedCount() == 1 ? 1 : -1;
		} catch (MongoWriteException mwe) {
			if (DuplicateKeyExceptionChecker.isDuplicate(mwe)) {
				// another user already is linked to this ID, fail permanently, no retry
				throw new IdentityLinkedException(remoteID.getRemoteID().getID());
			} else {
				throw new AuthStorageException("Database write failed", mwe);
			}
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}
	
	@Override
	public void unlink(
			final UserName userName,
			final String id)
			throws AuthStorageException, UnLinkFailedException, NoSuchUserException,
				NoSuchIdentityException {
		checkStringNoCheckedException(id, "id");
		final AuthUser u = getUser(userName);
		if (u.isLocal()) {
			throw new UnLinkFailedException("Local users have no identities");
		}
		final Document q = new Document(Fields.USER_NAME, userName.getName())
				/* this a neat trick to ensure that there's at least 2
				 * identities for the user. See http://stackoverflow.com/a/15224544/643675
				 * Normal users must always have at least one identity.
				 */
				.append(Fields.USER_IDENTITIES + ".1", new Document("$exists", true));
		final Document a = new Document("$pull", new Document(
				Fields.USER_IDENTITIES, new Document(Fields.IDENTITIES_ID, id.toString())));
		try {
			final UpdateResult r = db.getCollection(COL_USERS).updateOne(q, a);
			if (r.getMatchedCount() != 1) {
				throw new UnLinkFailedException("The user has only one associated identity");
			}
			if (r.getModifiedCount() != 1) {
				throw new NoSuchIdentityException(
						"The user is not linked to identity " + id.toString());
			}
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}

	private Set<Document> toDocument(final Set<RemoteIdentity> rids) {
		return rids.stream().map(ri -> toDocument(ri)).collect(Collectors.toSet());
	}

	@Override
	public void updateUser(final UserName userName, final UserUpdate update)
			throws NoSuchUserException, AuthStorageException {
		nonNull(update, "update");
		if (!update.hasUpdates()) {
			return; //noop
		}
		final Document d = new Document();
		if (update.getDisplayName().isPresent()) {
			d.append(Fields.USER_DISPLAY_NAME, update.getDisplayName().get().getName())
				.append(Fields.USER_DISPLAY_NAME_CANONICAL, 
						update.getDisplayName().get().getCanonicalDisplayName());
		}
		if (update.getEmail().isPresent()) {
			d.append(Fields.USER_EMAIL, update.getEmail().get().getAddress());
		}
		updateUser(userName, d);
	}

	// wraps update in a $set
	// assume coders are not stupid enough to pass in a null document
	private void updateUser(final UserName userName, final Document update)
			throws NoSuchUserException, AuthStorageException {
		final Document u = new Document("$set", update);
		updateUserAnyUpdate(userName, u);
	}

	// applies the update directly
	// assume coders are stupid enough to pass in null documents
	private void updateUserAnyUpdate(final UserName userName, final Document update)
			throws NoSuchUserException, AuthStorageException {
		nonNull(userName, "userName");
		final Document query = new Document(Fields.USER_NAME, userName.getName());
		try {
			final UpdateResult r = db.getCollection(COL_USERS).updateOne(query, update);
			if (r.getMatchedCount() != 1) {
				throw new NoSuchUserException(userName.getName());
			}
			// if it wasn't modified no problem.
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}
	
	@Override
	public void setLastLogin(final UserName user, final Instant lastLogin) 
			throws NoSuchUserException, AuthStorageException {
		nonNull(lastLogin, "lastLogin");
		updateUser(user, new Document(Fields.USER_LAST_LOGIN, Date.from(lastLogin)));
	}
	
	@Override
	public void addPolicyIDs(final UserName userName, final Set<PolicyID> policyIDs)
			throws NoSuchUserException, AuthStorageException {
		nonNull(userName, "userName");
		nonNull(policyIDs, "policyIDs");
		noNulls(policyIDs, "null item in policyIDs");
		if (!userExists(userName)) {
			throw new NoSuchUserException(userName.getName());
		}
		for (final PolicyID pid: policyIDs) {
			setPolicyID(userName, pid);
		}
	}
	
	//assumes user exists
	private void setPolicyID(final UserName userName, final PolicyID pid)
			throws AuthStorageException, NoSuchUserException {
		final Document query = new Document(Fields.USER_NAME, userName.getName())
				.append(Fields.USER_POLICY_IDS + Fields.FIELD_SEP + Fields.POLICY_ID,
						new Document("$ne", pid.getName()));
		final Document update = new Document("$addToSet", new Document(Fields.USER_POLICY_IDS,
				new Document(Fields.POLICY_ID, pid.getName())
						.append(Fields.POLICY_AGREED_ON, Date.from(clock.instant()))));
		try {
			db.getCollection(COL_USERS).updateOne(query, update);
			// either nothing happened, in which case the user already had the policy, or
			// the policy was updated, so done
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}
	
	private boolean userExists(final UserName userName) throws AuthStorageException {
		try {
			return db.getCollection(COL_USERS).count(
					new Document(Fields.USER_NAME, userName.getName())) == 1;
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}

	@Override
	public void removePolicyID(final PolicyID policyID) throws AuthStorageException {
		nonNull(policyID, "policyID");
		try {
			db.getCollection(COL_USERS).updateMany(new Document(), new Document("$pull",
					new Document(Fields.USER_POLICY_IDS, new Document(Fields.POLICY_ID,
							policyID.getName()))));
			// don't care if nothing happened, just means no one had the policy
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}

	private <T> void updateConfig(
			final String collection,
			final String key,
			final Optional<T> value,
			final boolean overwrite)
			throws AuthStorageException {
		if (!value.isPresent()) {
			return;
		}
		final Document q = new Document(Fields.CONFIG_KEY, key);
		updateConfig(collection, q, value.get(), overwrite);
	}
	
	private <T> void updateConfig(
			final String collection,
			final String key,
			final long value,
			final boolean overwrite)
			throws AuthStorageException {
		final Document q = new Document(Fields.CONFIG_KEY, key);
		updateConfig(collection, q, value, overwrite);
	}
	
	// assumes a set action
	private void updateConfig(
			final String collection,
			final String key,
			final ConfigItem<String, Action> value,
			final boolean overwrite)
			throws AuthStorageException {
		final Document q = new Document(Fields.CONFIG_KEY, key);
		updateConfig(collection, q, value.getItem(), overwrite);
	}
	
	// assumes value is non null
	private void updateConfig(
			final String collection,
			final Document query,
			final Object value,
			final boolean overwrite) // may want to have an action type to allow remove?
			throws AuthStorageException {
		final String op = overwrite ? "$set" : "$setOnInsert";
		final Document u = new Document(op, new Document(Fields.CONFIG_VALUE, value));
		try {
			db.getCollection(collection).updateOne(query, u, new UpdateOptions().upsert(true));
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}
	
	private void updateProviderConfig(
			final String provider,
			final String key,
			final Optional<Boolean> value,
			final boolean overwrite)
			throws AuthStorageException {
		if (!value.isPresent()) {
			return;
		}
		final Document q = new Document(Fields.CONFIG_KEY, key)
				.append(Fields.CONFIG_PROVIDER, provider);
		updateConfig(COL_CONFIG_PROVIDERS, q, value.get(), overwrite);
	}
	
	private void removeConfig(final String collection, final String key, final boolean overwrite)
			throws AuthStorageException {
		if (!overwrite) {
			return; // don't remove keys unless overwrite is specified
		}
		try {
			db.getCollection(collection).deleteOne(new Document(Fields.CONFIG_KEY, key));
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}

	
	@Override
	public <T extends ExternalConfig> void updateConfig(
			final AuthConfigUpdate<T> cfgUpdate,
			final boolean overwrite)
			throws AuthStorageException {

		nonNull(cfgUpdate, "cfgSet");
		updateConfig(COL_CONFIG_APPLICATION,
				Fields.CONFIG_APP_ALLOW_LOGIN, cfgUpdate.getLoginAllowed(), overwrite);
		for (final Entry<TokenLifetimeType, Long> e:
				cfgUpdate.getTokenLifetimeMS().entrySet()) {
			updateConfig(COL_CONFIG_APPLICATION,
					TOKEN_LIFETIME_FIELD_MAP.get(e.getKey()), e.getValue(), overwrite);
		}
		for (final Entry<String, ProviderUpdate> e: cfgUpdate.getProviders().entrySet()) {
			updateProviderConfig(e.getKey(), Fields.CONFIG_PROVIDER_ENABLED,
					e.getValue().getEnabled(), overwrite);
			updateProviderConfig(e.getKey(), Fields.CONFIG_PROVIDER_FORCE_LOGIN_CHOICE,
					e.getValue().getForceLoginChoice(), overwrite);
			updateProviderConfig(e.getKey(), Fields.CONFIG_PROVIDER_FORCE_LINK_CHOICE,
					e.getValue().getForceLinkChoice(), overwrite);
		}
		
		if (cfgUpdate.getExternalConfig().isPresent()) {
			for (final Entry<String, ConfigItem<String, Action>> e:
					cfgUpdate.getExternalConfig().get().toMap().entrySet()) {
				if (e.getValue().getAction().isSet()) {
					updateConfig(COL_CONFIG_EXTERNAL, e.getKey(), e.getValue(),
							overwrite);
				} else if (e.getValue().getAction().isRemove()) {
					removeConfig(COL_CONFIG_EXTERNAL, e.getKey(), overwrite);
				}
			}
		}
	}
	
	private Map<String, Document> getAppConfig() {
		final FindIterable<Document> i = db.getCollection(COL_CONFIG_APPLICATION).find();
		final Map<String, Document> ret = new HashMap<>();
		for (final Document d: i) {
			ret.put(d.getString(Fields.CONFIG_KEY), d);
		}
		return ret;
	}
	
	private Map<String, ProviderConfig> getProviderConfig() {
		final FindIterable<Document> proviter = db.getCollection(COL_CONFIG_PROVIDERS).find();
		final Map<String, Map<String, Document>> provdocs = new HashMap<>();
		for (final Document d: proviter) {
			final String p = d.getString(Fields.CONFIG_PROVIDER);
			final String key = d.getString(Fields.CONFIG_KEY);
			if (!provdocs.containsKey(p)) {
				provdocs.put(p, new HashMap<>());
			}
			provdocs.get(p).put(key, d);
		}
		final Map<String, ProviderConfig> provs = new HashMap<>();
		for (final Entry<String, Map<String, Document>> d: provdocs.entrySet()) {
			final ProviderConfig pc = new ProviderConfig(
					d.getValue().get(Fields.CONFIG_PROVIDER_ENABLED)
							.getBoolean(Fields.CONFIG_VALUE),
					d.getValue().get(Fields.CONFIG_PROVIDER_FORCE_LOGIN_CHOICE)
							.getBoolean(Fields.CONFIG_VALUE),
					d.getValue().get(Fields.CONFIG_PROVIDER_FORCE_LINK_CHOICE)
							.getBoolean(Fields.CONFIG_VALUE));
			provs.put(d.getKey(), pc);
		}
		return provs;
	}
			
	@Override
	public <T extends ExternalConfig> AuthConfigSet<T> getConfig(
			final ExternalConfigMapper<T> mapper)
			throws AuthStorageException, ExternalConfigMappingException {
		
		nonNull(mapper, "mapper");
		try {
			final FindIterable<Document> extiter = db.getCollection(COL_CONFIG_EXTERNAL).find();
			final Map<String, ConfigItem<String, State>> ext = new HashMap<>();
			for (final Document d: extiter) {
				ext.put(d.getString(Fields.CONFIG_KEY),
						ConfigItem.state(d.getString(Fields.CONFIG_VALUE)));
			}
			final Map<String, ProviderConfig> provs = getProviderConfig();
			final Map<String, Document> appcfg = getAppConfig();
			final boolean allowLogin;
			if (appcfg.containsKey(Fields.CONFIG_APP_ALLOW_LOGIN)) {
				allowLogin = appcfg.get(Fields.CONFIG_APP_ALLOW_LOGIN)
						.getBoolean(Fields.CONFIG_VALUE);
			} else {
				allowLogin = AuthConfig.DEFAULT_LOGIN_ALLOWED;
			}
			final Map<TokenLifetimeType, Long> tokens = new HashMap<>();
			for (final Entry<TokenLifetimeType, String> e: TOKEN_LIFETIME_FIELD_MAP.entrySet()) {
				if (appcfg.get(e.getValue()) != null) {
					tokens.put(e.getKey(), appcfg.get(e.getValue()).getLong(Fields.CONFIG_VALUE));
				}
			}
			return new AuthConfigSet<T>(new AuthConfig(allowLogin, provs, tokens),
					mapper.fromMap(ext));
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}
}
