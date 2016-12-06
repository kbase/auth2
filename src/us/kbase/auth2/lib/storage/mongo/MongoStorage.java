package us.kbase.auth2.lib.storage.mongo;

import static us.kbase.auth2.lib.Utils.clear;

import java.util.Arrays;
import java.util.Base64;
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
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.bson.Document;
import org.bson.types.ObjectId;

import com.mongodb.ErrorCategory;
import com.mongodb.MongoException;
import com.mongodb.MongoWriteException;
import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.model.UpdateOptions;
import com.mongodb.client.result.DeleteResult;
import com.mongodb.client.result.UpdateResult;

import us.kbase.auth2.lib.AuthConfig;
import us.kbase.auth2.lib.AuthConfig.ProviderConfig;
import us.kbase.auth2.lib.AuthConfig.TokenLifetimeType;
import us.kbase.auth2.lib.AuthConfigSet;
import us.kbase.auth2.lib.AuthUser;
import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.ExternalConfig;
import us.kbase.auth2.lib.ExternalConfigMapper;
import us.kbase.auth2.lib.LocalUser;
import us.kbase.auth2.lib.NewLocalUser;
import us.kbase.auth2.lib.NewUser;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.SearchField;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.UserUpdate;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.LinkFailedException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UnLinkFailedException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentityWithID;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.storage.exceptions.StorageInitException;
import us.kbase.auth2.lib.token.HashedToken;
import us.kbase.auth2.lib.token.IncomingHashedToken;
import us.kbase.auth2.lib.token.TemporaryHashedToken;
import us.kbase.auth2.lib.token.TokenType;

public class MongoStorage implements AuthStorage {

	/* Don't use mongo built in object mapping to create the returned objects
	 * since that tightly couples the classes to the storage implementation.
	 * Instead, if needed, create classes specific to the implementation for
	 * mapping purposes that produce the returned classes.
	 */
	
	//TODO TEST unit tests
	//TODO JAVADOC
	
	private static final int SCHEMA_VERSION = 1;
	
	private static final String COL_CONFIG = "config";
	private static final String COL_CONFIG_APPLICATION = "config_app";
	private static final String COL_CONFIG_PROVIDERS = "config_prov";
	private static final String COL_CONFIG_EXTERNAL = "config_ext";
	private static final String COL_USERS = "users";
	private static final String COL_TOKEN = "tokens";
	private static final String COL_TEMP_TOKEN = "temptokens";
	private static final String COL_CUST_ROLES = "cust_roles";
	
	private static final Map<TokenLifetimeType, String>
			TOKEN_LIFETIME_FIELD_MAP;
	static {
		final Map<TokenLifetimeType, String> m = new HashMap<>();
		m.put(TokenLifetimeType.EXT_CACHE, Fields.CONFIG_APP_TOKEN_LIFE_CACHE);
		m.put(TokenLifetimeType.LOGIN, Fields.CONFIG_APP_TOKEN_LIFE_LOGIN);
		m.put(TokenLifetimeType.DEV, Fields.CONFIG_APP_TOKEN_LIFE_DEV);
		m.put(TokenLifetimeType.SERV, Fields.CONFIG_APP_TOKEN_LIFE_SERV);
		TOKEN_LIFETIME_FIELD_MAP = Collections.unmodifiableMap(m);
	}
	
	private static final Map<String, Map<List<String>, IndexOptions>> INDEXES;
	private static final IndexOptions IDX_UNIQ =
			new IndexOptions().unique(true);
	private static final IndexOptions IDX_UNIQ_SPARSE =
			new IndexOptions().unique(true).sparse(true);
	static {
		//hardcoded indexes
		INDEXES = new HashMap<String, Map<List<String>, IndexOptions>>();
		
		//user indexes
		final Map<List<String>, IndexOptions> users = new HashMap<>();
		//find users and ensure user names are unique
		users.put(Arrays.asList(Fields.USER_NAME), IDX_UNIQ);
		//find user by identity provider and identity id and ensure identities
		//are 1:1 with users
		users.put(Arrays.asList(
				Fields.USER_IDENTITIES + Fields.FIELD_SEP +
					Fields.IDENTITIES_PROVIDER,
				Fields.USER_IDENTITIES + Fields.FIELD_SEP +
					Fields.IDENTITIES_PROV_ID),
				IDX_UNIQ_SPARSE);
		//find user by local identity id and ensure unique ids
		users.put(Arrays.asList(Fields.USER_IDENTITIES + Fields.FIELD_SEP +
				Fields.IDENTITIES_ID), IDX_UNIQ_SPARSE);
		//find users by display name
		users.put(Arrays.asList(Fields.USER_DISPLAY_NAME_CANONICAL), null);
		INDEXES.put(COL_USERS, users);
		
		//roles indexes
		final Map<List<String>, IndexOptions> roles = new HashMap<>();
		roles.put(Arrays.asList(Fields.ROLES_ID), IDX_UNIQ);
		INDEXES.put(COL_CUST_ROLES, roles);
		
		//token indexes
		final Map<List<String>, IndexOptions> token = new HashMap<>();
		token.put(Arrays.asList(Fields.TOKEN_USER_NAME), null);
		token.put(Arrays.asList(Fields.TOKEN_TOKEN), IDX_UNIQ);
		token.put(Arrays.asList(Fields.TOKEN_ID), IDX_UNIQ);
		token.put(Arrays.asList(Fields.TOKEN_EXPIRY),
				// this causes the tokens to expire at their expiration date
				//TODO TEST that tokens expire appropriately
				new IndexOptions().expireAfter(0L, TimeUnit.SECONDS));
		INDEXES.put(COL_TOKEN, token);
		
		//temporary token indexes
		final Map<List<String>, IndexOptions> temptoken = new HashMap<>();
		temptoken.put(Arrays.asList(Fields.TEMP_TOKEN_TOKEN), IDX_UNIQ);
		temptoken.put(Arrays.asList(Fields.TEMP_TOKEN_EXPIRY),
				// this causes the tokens to expire at their expiration date
				//TODO TEST that tokens expire appropriately
				new IndexOptions().expireAfter(0L, TimeUnit.SECONDS));
		INDEXES.put(COL_TEMP_TOKEN, temptoken);
		
		//config indexes
		final Map<List<String>, IndexOptions> cfg = new HashMap<>();
		//ensure only one config object
		cfg.put(Arrays.asList(Fields.DB_CONFIG_KEY), IDX_UNIQ);
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


	}
	
	private MongoDatabase db;
	
	public MongoStorage(final MongoDatabase db) throws StorageInitException {
		if (db == null) {
			throw new NullPointerException("db");
		}
		this.db = db;
		
		//TODO MISC check workspace startup for stuff to port over
		checkConfig();
		ensureIndexes();
	}
	
	private void checkConfig() throws StorageInitException  {
		final MongoCollection<Document> col = db.getCollection(COL_CONFIG);
		final Document cfg = new Document(
				Fields.DB_CONFIG_KEY, Fields.DB_CONFIG_VALUE);
		cfg.put(Fields.DB_CONFIG_UPDATE, false);
		cfg.put(Fields.DB_CONFIG_SCHEMA_VERSION, SCHEMA_VERSION);
		try {
			col.insertOne(cfg);
		} catch (MongoWriteException dk) {
			if (!isDuplicateKeyException(dk)) {
				throw new StorageInitException(
						"There was a problem communicating with the " +
						"database: " + dk.getMessage(), dk);
			}
			//ok, the version doc is already there, this isn't the first
			//startup
			if (col.count() != 1) {
				throw new StorageInitException(
						"Multiple config objects found in the database. " +
						"This should not happen, something is very wrong.");
			}
			final FindIterable<Document> cur = db.getCollection(COL_CONFIG)
					.find(Filters.eq(Fields.DB_CONFIG_KEY, Fields.DB_CONFIG_VALUE));
			final Document doc = cur.first();
			if ((Integer) doc.get(Fields.DB_CONFIG_SCHEMA_VERSION) !=
					SCHEMA_VERSION) {
				throw new StorageInitException(String.format(
						"Incompatible database schema. Server is v%s, " +
						"DB is v%s", SCHEMA_VERSION,
						doc.get(Fields.DB_CONFIG_SCHEMA_VERSION)));
			}
			if ((Boolean) doc.get(Fields.DB_CONFIG_UPDATE)) {
				throw new StorageInitException(String.format(
						"The database is in the middle of an update from " +
								"v%s of the schema. Aborting startup.", 
								doc.get(Fields.DB_CONFIG_SCHEMA_VERSION)));
			}
		} catch (MongoException me) {
			throw new StorageInitException(
					"There was a problem communicating with the database: " +
					me.getMessage(), me);
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

	private List<String> getCanonicalDisplayName(final DisplayName display) {
		final String[] parts = display.getName().toLowerCase().split("\\s");
		final List<String> ret = new LinkedList<>();
		for (String p: parts) {
			p = p.trim();
			if (!p.isEmpty()) {
				ret.add(p);
			}
		}
		return ret;
	}
	
	@Override
	public void createRoot(
			final UserName root,
			final DisplayName displayName,
			final EmailAddress email,
			final Set<Role> roles,
			final Date created,
			final byte[] passwordHash,
			final byte[] salt) throws AuthStorageException {
		
		final String encpwd = Base64.getEncoder().encodeToString(passwordHash);
		clear(passwordHash);
		final String encsalt = Base64.getEncoder().encodeToString(salt);
		clear(salt);
		final Document q = new Document(Fields.USER_NAME, root.getName());
		final List<String> rolestr = roles.stream().map(r -> r.getID())
				.collect(Collectors.toList());
		final Document set = new Document(
				Fields.USER_LOCAL, true)
				.append(Fields.USER_ROLES, rolestr)
				.append(Fields.USER_RESET_PWD, false)
				.append(Fields.USER_PWD_HSH, encpwd)
				.append(Fields.USER_SALT, encsalt)
				// ideally only set name to  root if 1) the root account already exists and 2)
				// the field isn't set to root, but that's too much trouble for now
				// could do it with an insert/update cycle
				.append(Fields.USER_DISABLED_ADMIN, null)
				.append(Fields.USER_DISABLED_REASON, null);// always enable
		final Document setIfMissing = new Document(
				Fields.USER_EMAIL, email.getAddress())
				.append(Fields.USER_DISPLAY_NAME, displayName.getName())
				.append(Fields.USER_DISPLAY_NAME_CANONICAL, getCanonicalDisplayName(displayName))
				.append(Fields.USER_CUSTOM_ROLES, Collections.emptyList())
				.append(Fields.USER_CREATED, created)
				.append(Fields.USER_LAST_LOGIN, null)
				.append(Fields.USER_RESET_PWD_LAST, null);
		final Document u = new Document("$set", set)
				.append("$setOnInsert", setIfMissing);
		try {
			db.getCollection(COL_USERS).updateOne(q, u,
					new UpdateOptions().upsert(true));
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}
	
	@Override
	public void createLocalUser(final NewLocalUser local)
			throws UserExistsException, AuthStorageException {
		final String pwdhsh = Base64.getEncoder().encodeToString(
				local.getPasswordHash());
		final String salt = Base64.getEncoder().encodeToString(
				local.getSalt());
		final UserName admin = local.getAdminThatToggledEnabledState();
		final Document u = new Document(
				Fields.USER_NAME, local.getUserName().getName())
				.append(Fields.USER_LOCAL, true)
				.append(Fields.USER_EMAIL, local.getEmail().getAddress())
				.append(Fields.USER_DISPLAY_NAME, local.getDisplayName().getName())
				.append(Fields.USER_DISPLAY_NAME_CANONICAL, getCanonicalDisplayName(
						local.getDisplayName()))
				.append(Fields.USER_ROLES, new LinkedList<String>())
				.append(Fields.USER_CUSTOM_ROLES, new LinkedList<String>())
				.append(Fields.USER_CREATED, local.getCreated())
				.append(Fields.USER_LAST_LOGIN, local.getLastLogin())
				.append(Fields.USER_DISABLED_ADMIN, admin == null ? null : admin.getName())
				.append(Fields.USER_DISABLED_REASON, local.getReasonForDisabled())
				.append(Fields.USER_RESET_PWD, local.isPwdResetRequired())
				.append(Fields.USER_RESET_PWD_LAST, local.getLastPwdReset())
				.append(Fields.USER_PWD_HSH, pwdhsh)
				.append(Fields.USER_SALT, salt);
		try {
			db.getCollection(COL_USERS).insertOne(u);
		} catch (MongoWriteException mwe) {
			if (isDuplicateKeyException(mwe)) {
				throw new UserExistsException(local.getUserName().getName());
			} else {
				throw new AuthStorageException("Database write failed", mwe);
			}
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}
	
	//note this always returns pwd info. Add boolean to avoid if needed.
	@Override
	public LocalUser getLocalUser(final UserName userName)
			throws AuthStorageException, NoSuchUserException {
		final Document user = getUserDoc(userName, true);
		@SuppressWarnings("unchecked")
		final List<String> rolestr = (List<String>) user.get(Fields.USER_ROLES);
		final List<Role> roles = rolestr.stream().map(s -> Role.getRole(s))
				.collect(Collectors.toList());
		@SuppressWarnings("unchecked")
		final List<ObjectId> custroles = (List<ObjectId>) user.get(Fields.USER_CUSTOM_ROLES);
		return new MongoLocalUser(
				getUserName(user.getString(Fields.USER_NAME)),
				getEmail(user.getString(Fields.USER_EMAIL)),
				getDisplayName(user.getString(Fields.USER_DISPLAY_NAME)),
				new HashSet<>(roles),
				new HashSet<>(custroles),
				user.getDate(Fields.USER_CREATED),
				user.getDate(Fields.USER_LAST_LOGIN),
				getUserNameAllowNull(user.getString(Fields.USER_DISABLED_ADMIN)),
				user.getString(Fields.USER_DISABLED_REASON),
				Base64.getDecoder().decode(user.getString(Fields.USER_PWD_HSH)),
				Base64.getDecoder().decode(user.getString(Fields.USER_SALT)),
				user.getBoolean(Fields.USER_RESET_PWD),
				user.getDate(Fields.USER_RESET_PWD_LAST),
				this);
	}
	

	private UserName getUserNameAllowNull(final String namestr) throws AuthStorageException {
		if (namestr == null) {
			return null;
		}
		return getUserName(namestr);
	}

	private UserName getUserName(String namestr) throws AuthStorageException {
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
	@Override
	public void changePassword(final UserName name, final byte[] pwdHash, final byte[] salt)
			throws NoSuchUserException, AuthStorageException {
		getUserDoc(name, true); //check the user actually is local
		final String pwdhsh = Base64.getEncoder().encodeToString(pwdHash);
		final String encsalt = Base64.getEncoder().encodeToString(salt);
		final Document set = new Document(Fields.USER_RESET_PWD, false)
				.append(Fields.USER_RESET_PWD_LAST, new Date())
				.append(Fields.USER_PWD_HSH, pwdhsh)
				.append(Fields.USER_SALT, encsalt);
		updateUser(name, set);
	}
	
	@Override
	public void createUser(final NewUser user)
			throws UserExistsException, AuthStorageException {
		if (user.isLocal()) {
			throw new IllegalArgumentException("cannot create a local user");
		}
		if (user.getIdentities().size() > 1) {
			throw new IllegalArgumentException(
					"user can only have one identity");
		}
		final RemoteIdentityWithID ri = user.getIdentities().iterator().next();
		final Document id = toDocument(ri);
		
		final UserName admin = user.getAdminThatToggledEnabledState();
		final Document u = new Document(
				Fields.USER_NAME, user.getUserName().getName())
				.append(Fields.USER_LOCAL, false)
				.append(Fields.USER_EMAIL, user.getEmail().getAddress())
				.append(Fields.USER_DISPLAY_NAME, user.getDisplayName().getName())
				.append(Fields.USER_DISPLAY_NAME_CANONICAL, getCanonicalDisplayName(
						user.getDisplayName()))
				.append(Fields.USER_ROLES, new LinkedList<String>())
				.append(Fields.USER_CUSTOM_ROLES, new LinkedList<String>())
				.append(Fields.USER_IDENTITIES, Arrays.asList(id))
				.append(Fields.USER_CREATED, user.getCreated())
				.append(Fields.USER_LAST_LOGIN, user.getLastLogin())
				.append(Fields.USER_DISABLED_ADMIN, admin == null ? null : admin.getName())
				.append(Fields.USER_DISABLED_REASON, user.getReasonForDisabled());
		try {
			db.getCollection(COL_USERS).insertOne(u);
		} catch (MongoWriteException mwe) {
			if (isDuplicateKeyException(mwe)) {
				//TODO ERRHANDLE handle case where duplicate is a remote id, not the username
				throw new UserExistsException(user.getUserName().getName());
			} else {
				throw new AuthStorageException("Database write failed", mwe);
			}
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}

	private Document getUserDoc(final UserName userName, final boolean local)
			throws AuthStorageException, NoSuchUserException {
		final Document projection = local ? null : new Document(
				Fields.USER_PWD_HSH, 0).append(Fields.USER_SALT, 0);
		final Document user = findOne(COL_USERS,
				new Document(Fields.USER_NAME, userName.getName()),
				projection);
		if (user == null || (local && !user.getBoolean(Fields.USER_LOCAL))) {
			throw new NoSuchUserException(userName.getName());
		}
		return user;
	}

	private boolean isDuplicateKeyException(final MongoWriteException mwe) {
		return mwe.getError().getCategory().equals(ErrorCategory.DUPLICATE_KEY);
	}
	
	@Override
	public void disableAccount(final UserName user, final UserName admin, final String reason)
			throws NoSuchUserException, AuthStorageException {
		toggleAccount(user, admin, reason);
	}

	private void toggleAccount(final UserName user, final UserName admin, final String reason)
			throws NoSuchUserException, AuthStorageException {
		final Document update = new Document(Fields.USER_DISABLED_REASON, reason)
				.append(Fields.USER_DISABLED_ADMIN, admin.getName());
		updateUser(user, update);
	}
	
	@Override
	public void enableAccount(final UserName user, final UserName admin)
			throws NoSuchUserException, AuthStorageException {
		toggleAccount(user, admin, null);
	}

	@Override
	public void storeToken(final HashedToken t) throws AuthStorageException {
		final Document td = new Document(
				Fields.TOKEN_TYPE, t.getTokenType().getID())
				.append(Fields.TOKEN_USER_NAME, t.getUserName().getName())
				.append(Fields.TOKEN_ID, t.getId().toString())
				.append(Fields.TOKEN_NAME, t.getTokenName())
				.append(Fields.TOKEN_TOKEN, t.getTokenHash())
				.append(Fields.TOKEN_EXPIRY, t.getExpirationDate())
				.append(Fields.TOKEN_CREATION, t.getCreationDate());
		try {
			db.getCollection(COL_TOKEN).insertOne(td);
			/* could catch a duplicate key exception here but that indicates
			 * a programming error - should never try to insert a duplicate
			 *  token
			 */
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
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
			return db.getCollection(collection).find(query)
					.projection(projection).first();
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}

	@Override
	public HashedToken getToken(final IncomingHashedToken token)
			throws AuthStorageException, NoSuchTokenException {
		final Document t = findOne(COL_TOKEN, new Document(
				Fields.TOKEN_TOKEN, token.getTokenHash()));
		if (t == null) {
			throw new NoSuchTokenException("Token not found");
		}
		//TODO TOKEN if token expired, throw error
		return getToken(t);
	}
	
	private HashedToken getToken(final Document t)
			throws AuthStorageException {
		return new HashedToken(
				TokenType.getType(t.getString(Fields.TOKEN_TYPE)),
				t.getString(Fields.TOKEN_NAME),
				UUID.fromString(t.getString(Fields.TOKEN_ID)),
				t.getString(Fields.TOKEN_TOKEN),
				getUserName(t.getString(Fields.TOKEN_USER_NAME)),
				t.getDate(Fields.TOKEN_CREATION),
				t.getDate(Fields.TOKEN_EXPIRY));
	}

	@Override
	public Set<HashedToken> getTokens(final UserName userName)
			throws AuthStorageException {
		if (userName == null) {
			throw new NullPointerException("userName");
		}
		final Set<HashedToken> ret = new HashSet<>();
		try {
			final FindIterable<Document> ts = db.getCollection(COL_TOKEN).find(
					new Document(Fields.TOKEN_USER_NAME, userName.getName()));
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
		final Document user = getUserDoc(userName, false);
		return toUser(user);
	}

	private MongoUser toUser(final Document user) throws AuthStorageException {
		@SuppressWarnings("unchecked")
		final List<String> rolestr = (List<String>) user.get(Fields.USER_ROLES);
		final List<Role> roles = rolestr.stream().map(s -> Role.getRole(s))
				.collect(Collectors.toList());
		@SuppressWarnings("unchecked")
		final List<ObjectId> custroles = (List<ObjectId>) user.get(Fields.USER_CUSTOM_ROLES);
		@SuppressWarnings("unchecked")
		final List<Document> ids = (List<Document>) user.get(Fields.USER_IDENTITIES);
		return new MongoUser(
				getUserName(user.getString(Fields.USER_NAME)),
				getEmail(user.getString(Fields.USER_EMAIL)),
				getDisplayName(user.getString(Fields.USER_DISPLAY_NAME)),
				toIdentities(ids),
				new HashSet<>(roles),
				new HashSet<>(custroles),
				user.getDate(Fields.USER_CREATED),
				user.getDate(Fields.USER_LAST_LOGIN),
				getUserNameAllowNull(user.getString(Fields.USER_DISABLED_ADMIN)),
				user.getString(Fields.USER_DISABLED_REASON),
				this);
	}
	
	@Override
	public Map<UserName, DisplayName> getUserDisplayNames(final Set<UserName> users)
			throws AuthStorageException {
		if (users.isEmpty()) {
			return new HashMap<>();
		}
		final List<String> queryusers = users.stream().map(u -> u.getName())
				.collect(Collectors.toList());
		final Document query = new Document(Fields.USER_NAME, new Document("$in", queryusers));
		return getDisplayNames(query, -1);
	}

	private Map<UserName, DisplayName> getDisplayNames(final Document query, final int limit)
			throws AuthStorageException {
		final Document projection = new Document(Fields.USER_NAME, 1)
				.append(Fields.USER_DISPLAY_NAME, 1);
		try {
			final FindIterable<Document> docs = db.getCollection(COL_USERS)
					.find(query).projection(projection);
			if (limit > 0) {
				docs.limit(limit);
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
	
	@Override
	public Map<UserName, DisplayName> getUserDisplayNames(
			final String prefix,
			final Set<SearchField> searchFields,
			final int limit)
			throws AuthStorageException {
		final List<Document> queries = new LinkedList<>();
		final Document regex = new Document("$regex", "^" + Pattern.quote(prefix));
		if (searchFields.contains(SearchField.USERNAME) || searchFields.isEmpty()) {
			queries.add(new Document(Fields.USER_NAME, regex));
		}
		if (searchFields.contains(SearchField.DISPLAYNAME) || searchFields.isEmpty()) {
			queries.add(new Document(Fields.USER_DISPLAY_NAME_CANONICAL, regex));
		}
		final Document query;
		if (queries.size() == 1) {
			query = queries.get(0);
		} else {
			query = new Document("$or", queries);
		}
		return getDisplayNames(query, limit);
	}

	@Override
	public void deleteToken(
			final UserName userName,
			final UUID tokenId)
			throws AuthStorageException, NoSuchTokenException {
		try {
			final DeleteResult dr = db.getCollection(COL_TOKEN)
					.deleteOne(new Document(
							Fields.TOKEN_USER_NAME, userName.getName())
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
		try {
			db.getCollection(COL_TOKEN).deleteMany(new Document(
					Fields.TOKEN_USER_NAME, userName.getName()));
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed", e);
		}
	}

	@Override
	public void setRoles(final UserName userName, final Set<Role> roles)
			throws AuthStorageException, NoSuchUserException {
		final Set<Object> strrl = roles.stream().map(r -> r.getID())
				.collect(Collectors.toSet());
		setRoles(userName, strrl, Fields.USER_ROLES);
	}

	private void setRoles(
			final UserName userName,
			final Set<Object> roles,
			final String field)
			throws NoSuchUserException, AuthStorageException {
		try {
			final UpdateResult ret = db.getCollection(COL_USERS).updateOne(
					new Document(Fields.USER_NAME, userName.getName()),
					new Document("$set", new Document(field, roles)));
			// might not modify the roles if they're the same as input
			if (ret.getMatchedCount() != 1) {
				throw new NoSuchUserException(userName.getName());
			}
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}

	@Override
	public void setCustomRole(final CustomRole role)
			throws AuthStorageException {
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
			} catch (MissingParameterException e) { // should be impossible
				throw new AuthStorageException(
						"Error in roles colletion - role with missing field", e);
			}
		}
		return ret;
	}

	Set<String> getCustomRoles(final UserName user, final Set<ObjectId> roleIds)
			throws AuthStorageException {
		final Set<Document> roledocs = getCustomRoles(new Document(
				Fields.MONGO_ID, new Document("$in", roleIds)));
		final Set<ObjectId> extantRoleIds = roledocs.stream()
				.map(d -> d.getObjectId(Fields.MONGO_ID)).collect(Collectors.toSet());
		for (final ObjectId role: roleIds) {
			if (!extantRoleIds.contains(role)) {
				//TODO TEST need to exercise this race condition, generally shouldn't happen
				removeCustomRole(user, role);
			}
		}
		return roledocs.stream().map(d -> d.getString(Fields.ROLES_ID))
				.collect(Collectors.toSet());
	}

	private void removeCustomRole(final UserName user, final ObjectId role)
			throws AuthStorageException {
		final Document query = new Document(Fields.USER_NAME, user.getName());
		final Document mod = new Document("$pull", new Document(Fields.USER_CUSTOM_ROLES, role));
		try {
			// don't care if no changes are made, just means the role is already gone
			db.getCollection(COL_USERS).updateOne(query, mod);
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}

	@Override
	public void setCustomRoles(
			final UserName userName,
			final Set<String> roles)
			throws NoSuchUserException, AuthStorageException, NoSuchRoleException {
		final Set<Document> docroles;
		try {
			docroles = getCustomRoles(new Document(Fields.ROLES_ID, new Document("$in", roles)));
		} catch (MongoException me) {
			throw new AuthStorageException("Connection to database failed", me);
		}
		if (roles.size() != docroles.size()) {
			final Set<String> rolenames = docroles.stream().map(d -> d.getString(Fields.ROLES_ID))
					.collect(Collectors.toSet());
			for (final String role: roles) {
				if (!rolenames.contains(role)) {
					throw new NoSuchRoleException(role);
				}
			}
			throw new RuntimeException("Hole in reality matrix detected, please try turning " +
					"reality off and then on again");
		}
		final Set<Object> roleIDs = docroles.stream().map(d -> d.getObjectId(Fields.MONGO_ID))
				.collect(Collectors.toSet());
		setRoles(userName, roleIDs, Fields.USER_CUSTOM_ROLES);
	}

	@Override
	public AuthUser getUser(final RemoteIdentity remoteID)
			throws AuthStorageException {
		final Document query = makeUserQuery(remoteID);
		//note a user with identities should never have these fields, but
		//doesn't hurt to be safe
		final Document projection = new Document(Fields.USER_PWD_HSH, 0)
				.append(Fields.USER_SALT, 0);
		final Document u = findOne(COL_USERS, query, projection);
		if (u == null) {
			return null;
		}
		MongoUser user = toUser(u);
		/* could do a findAndModify to set the fields on the first query, but
		 * 99% of the time a set won't be necessary, so don't write lock the
		 * DB/collection (depending on mongo version) unless necessary 
		 */
		RemoteIdentityWithID update = null;
		for (final RemoteIdentityWithID ri: user.getIdentities()) {
			if (ri.getRemoteID().equals(remoteID.getRemoteID()) &&
					!ri.getDetails().equals(remoteID.getDetails())) {
				update = ri;
			}
		}
		if (update != null) {
			final Set<RemoteIdentityWithID> newIDs = new HashSet<>(user.getIdentities());
			newIDs.remove(update);
			newIDs.add(remoteID.withID(update.getID()));
			user = new MongoUser(user, newIDs);
			updateIdentity(remoteID);
		}
		return user;
	}

	private Document makeUserQuery(final RemoteIdentity remoteID) {
		final Document query = new Document(Fields.USER_IDENTITIES,
				new Document("$elemMatch", new Document(Fields.IDENTITIES_PROVIDER,
								remoteID.getRemoteID().getProvider())
						.append(Fields.IDENTITIES_PROV_ID,
								remoteID.getRemoteID().getId())));
		return query;
	}
	
	//TODO TEST exercise this function with tests
	private void updateIdentity(final RemoteIdentity remoteID)
			throws AuthStorageException {
		final Document query = makeUserQuery(remoteID);
		
		final String pre = Fields.USER_IDENTITIES + ".$.";
		final RemoteIdentityDetails rid = remoteID.getDetails();
		final Document update = new Document("$set", new Document(
				pre + Fields.IDENTITIES_USER, rid.getUsername())
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

	@Override
	public void storeIdentitiesTemporarily(
			final TemporaryHashedToken t,
			final Set<RemoteIdentityWithID> identitySet)
			throws AuthStorageException {
		final Set<Document> ids = toDocument(identitySet);
		final Document td = new Document(
				Fields.TEMP_TOKEN_ID, t.getId().toString())
				.append(Fields.TEMP_TOKEN_TOKEN, t.getTokenHash())
				.append(Fields.TEMP_TOKEN_EXPIRY, t.getExpirationDate())
				.append(Fields.TEMP_TOKEN_CREATION, t.getCreationDate())
				.append(Fields.TEMP_TOKEN_IDENTITIES, ids);
		try {
			db.getCollection(COL_TEMP_TOKEN).insertOne(td);
			/* could catch a duplicate key exception here but that indicates
			 * a programming error - should never try to insert a duplicate
			 *  token
			 */
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}

	private Document toDocument(final RemoteIdentityWithID id) {
		final RemoteIdentityDetails rid = id.getDetails();
		return new Document(Fields.IDENTITIES_ID, id.getID().toString())
				.append(Fields.IDENTITIES_PROVIDER, id.getRemoteID().getProvider())
				.append(Fields.IDENTITIES_PROV_ID, id.getRemoteID().getId())
				.append(Fields.IDENTITIES_USER, rid.getUsername())
				.append(Fields.IDENTITIES_NAME, rid.getFullname())
				.append(Fields.IDENTITIES_EMAIL, rid.getEmail());
	}
	
	@Override
	public Set<RemoteIdentityWithID> getTemporaryIdentities(
			final IncomingHashedToken token)
			throws AuthStorageException, NoSuchTokenException {
		final Document d = findOne(COL_TEMP_TOKEN,
				new Document(Fields.TEMP_TOKEN_TOKEN, token.getTokenHash()));
		if (d == null) {
			throw new NoSuchTokenException("Token not found");
		}
		@SuppressWarnings("unchecked")
		final List<Document> ids = (List<Document>) d.get(Fields.TEMP_TOKEN_IDENTITIES);
		if (ids == null) {
			final String tid = d.getString(Fields.TEMP_TOKEN_ID);
			throw new AuthStorageException(String.format(
					"Temporary token %s has no associated IDs field", tid));
		}
		return toIdentities(ids);
	}

	private Set<RemoteIdentityWithID> toIdentities(final List<Document> ids) {
		final Set<RemoteIdentityWithID> ret = new HashSet<>();
		if (ids == null) {
			return ret;
		}
		for (final Document i: ids) {
			final RemoteIdentityID rid = new RemoteIdentityID(
					i.getString(Fields.IDENTITIES_PROVIDER),
					i.getString(Fields.IDENTITIES_PROV_ID));
			final RemoteIdentityDetails det = new RemoteIdentityDetails(
					i.getString(Fields.IDENTITIES_USER),
					i.getString(Fields.IDENTITIES_NAME),
					i.getString(Fields.IDENTITIES_EMAIL));
			ret.add(new RemoteIdentityWithID(
					UUID.fromString(i.getString(Fields.IDENTITIES_ID)),
					rid, det));
		}
		return ret;
	}
	
	@Override
	public void link(final UserName user, final RemoteIdentityWithID remoteID)
			throws NoSuchUserException, AuthStorageException,
			LinkFailedException {
		int count = 0;
		boolean complete = false;
		// could just put addIdentity into the while loop but this is more readable IMO
		while (!complete) {
			count++;
			if (count > 5) {
				throw new RuntimeException("Attempted link update 5 times without success. " +
						"There's probably a programming error here.");
			}
			complete = addIdentity(user, remoteID);
		}
	}
	
	private boolean addIdentity(
			final UserName userName,
			final RemoteIdentityWithID remoteID)
			throws NoSuchUserException, AuthStorageException, LinkFailedException {
		/* This method is written as it is to avoid adding the same provider ID to a user twice.
		 * Since mongodb unique indexes only enforce uniqueness between documents, not within
		 * documents, adding the same provider ID to a single document twice is possible without
		 * careful db updates.
		 * Other alternatives were explored:
		 * $addToSet will add the same provider /user id combo to an array if the email etc. is
		 * different
		 * Splitting the user doc from the provider docs has a whole host of other issues, mostly
		 * wrt deletion
		 */
		
		final AuthUser user = getUser(userName);
		if (user.isLocal()) {
			throw new LinkFailedException("Cannot link accounts to a local user");
		}
		// firstly check to see if the ID is already linked. If so, just update the associated
		// user info.
		for (final RemoteIdentityWithID ri: user.getIdentities()) {
			if (ri.getRemoteID().equals(remoteID.getRemoteID())) {
				// if the details are the same, there's nothing to do, user is already linked and
				// user info is the same
				if (!ri.getDetails().equals(remoteID.getDetails())) {
					updateIdentity(remoteID);
				}
				return true; // update complete
			}
		}
		/* ok, we need to link. To ensure we don't add the identity twice, we search for a user
		 * that has the *exact* identity linkages as the current user, and then add one more. If
		 * another ID has been linked since we pulled the user from the DB, the update will fail
		 * and we try again by calling this function again.
		 */
		final Set<Document> oldIDs = toDocument(user.getIdentities()); // current ID linkages
		final Set<Document> newIDs = new HashSet<>(oldIDs);
		newIDs.add(toDocument(remoteID));
		
		final List<Document> idQuery = oldIDs.stream().map(d -> new Document("$elemMatch", d))
				.collect(Collectors.toList());
		final Document query = new Document(Fields.USER_NAME, user.getUserName().getName())
				.append(Fields.USER_IDENTITIES, new Document("$all", idQuery));
		
		try {
			final UpdateResult r = db.getCollection(COL_USERS).updateOne(query,
					new Document("$set", new Document(Fields.USER_IDENTITIES, newIDs)));
			// return true if the user was updated, false otherwise (meaning retry and call this
			// method again)
			return r.getModifiedCount() == 1;
		} catch (MongoWriteException mwe) {
			if (isDuplicateKeyException(mwe)) {
				// another user already is linked to this ID, fail permanently, no retry
				throw new LinkFailedException("Provider identity is already linked");
			} else {
				throw new AuthStorageException("Database write failed", mwe);
			}
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}
	
	@Override
	public void unlink(
			final UserName username,
			final UUID id)
			throws AuthStorageException, UnLinkFailedException {
		final Document q = new Document(Fields.USER_NAME, username.getName())
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
				// could pull the user here to ensure it exists, but meh
				throw new UnLinkFailedException("Either the user doesn't " +
						"exist or only has one associated identity");
			}
			if (r.getModifiedCount() != 1) {
				throw new UnLinkFailedException("The user is not linked to the provided identity");
			}
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}

	private Set<Document> toDocument(final Set<RemoteIdentityWithID> rids) {
		return rids.stream().map(ri -> toDocument(ri)).collect(Collectors.toSet());
	}

	@Override
	public void updateUser(final UserName userName, final UserUpdate update)
			throws NoSuchUserException, AuthStorageException{
		if (!update.hasUpdates()) {
			return; //noop
		}
		final Document d = new Document();
		if (update.getDisplayName() != null) {
			d.append(Fields.USER_DISPLAY_NAME, update.getDisplayName().getName())
				.append(Fields.USER_DISPLAY_NAME_CANONICAL, getCanonicalDisplayName(
						update.getDisplayName()));
		}
		if (update.getEmail() != null) {
			d.append(Fields.USER_EMAIL, update.getEmail().getAddress());
		}
		updateUser(userName, d);
	}

	private void updateUser(
			final UserName userName,
			final Document update)
			throws NoSuchUserException, AuthStorageException {
		final Document q = new Document(Fields.USER_NAME, userName.getName());
		final Document u = new Document("$set", update);
		try {
			final UpdateResult r = db.getCollection(COL_USERS).updateOne(q, u);
			if (r.getMatchedCount() != 1) {
				throw new NoSuchUserException(userName.getName());
			}
			// if it wasn't modified no problem.
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}
	
	@Override
	public void setLastLogin(final UserName user, final Date lastLogin) 
			throws NoSuchUserException, AuthStorageException {
		final Document d = new Document(Fields.USER_LAST_LOGIN, lastLogin);
		updateUser(user, d);
	}

	private void updateConfig(
			final String collection,
			final String key,
			final Object value,
			final boolean overwrite)
			throws AuthStorageException {
		final Document q = new Document(Fields.CONFIG_KEY, key);
		updateConfig(collection, q, value, overwrite);
	}

	private void updateConfig(
			final String collection,
			final Document query,
			final Object value,
			final boolean overwrite)
			throws AuthStorageException {
		if (value == null) {
			return;
		}
		final String op = overwrite ? "$set" : "$setOnInsert";
		final Document u = new Document(op,
				new Document(Fields.CONFIG_VALUE, value));
		try {
			db.getCollection(collection).updateOne(query, u,
					new UpdateOptions().upsert(true));
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}
	
	private void updateProviderConfig(
			final String provider,
			final String key,
			final Object value,
			final boolean overwrite)
			throws AuthStorageException {
		final Document q = new Document(Fields.CONFIG_KEY, key)
				.append(Fields.CONFIG_PROVIDER, provider);
		updateConfig(COL_CONFIG_PROVIDERS, q, value, overwrite);
	}
	
	@Override
	public <T extends ExternalConfig> void updateConfig(
			final AuthConfigSet<T> cfgSet,
			final boolean overwrite)
			throws AuthStorageException {
		
		updateConfig(COL_CONFIG_APPLICATION, Fields.CONFIG_APP_ALLOW_LOGIN,
				cfgSet.getCfg().isLoginAllowed(), overwrite);
		for (final Entry<TokenLifetimeType, Long> e:
				cfgSet.getCfg().getTokenLifetimeMS().entrySet()) {
			updateConfig(COL_CONFIG_APPLICATION,
					TOKEN_LIFETIME_FIELD_MAP.get(e.getKey()),
					e.getValue(), overwrite);
		}
		for (final Entry<String, ProviderConfig> e:
				cfgSet.getCfg().getProviders().entrySet()) {
			updateProviderConfig(e.getKey(),
					Fields.CONFIG_PROVIDER_ENABLED,
					e.getValue().isEnabled(), overwrite);
			updateProviderConfig(e.getKey(),
					Fields.CONFIG_PROVIDER_FORCE_LINK_CHOICE,
					e.getValue().isForceLinkChoice(), overwrite);
		}
		
		for (final Entry<String, String> e:
				cfgSet.getExtcfg().toMap().entrySet()) {
			updateConfig(COL_CONFIG_EXTERNAL, e.getKey(), e.getValue(),
					overwrite);
		}
	}
	
	private Map<String, Document> getAppConfig() {
		final FindIterable<Document> i =
				db.getCollection(COL_CONFIG_APPLICATION).find();
		final Map<String, Document> ret = new HashMap<>();
		for (final Document d: i) {
			ret.put(d.getString(Fields.CONFIG_KEY), d);
		}
		return ret;
	}
	
	private Map<String, Map<String, Document>> getProviderConfig() {
		final FindIterable<Document> proviter =
				db.getCollection(COL_CONFIG_PROVIDERS).find();
		final Map<String, Map<String, Document>> ret = new HashMap<>();
		for (final Document d: proviter) {
			final String p = d.getString(Fields.CONFIG_PROVIDER);
			final String key = d.getString(Fields.CONFIG_KEY);
			if (!ret.containsKey(p)) {
				ret.put(p, new HashMap<>());
			}
			ret.get(p).put(key, d);
		}
		return ret;
	}
			
	@Override
	public <T extends ExternalConfig> AuthConfigSet<T> getConfig(
			final ExternalConfigMapper<T> mapper)
			throws AuthStorageException, ExternalConfigMappingException {
		try {
			final FindIterable<Document> extiter = db.getCollection(COL_CONFIG_EXTERNAL).find();
			final Map<String, String> ext = new HashMap<>();
			for (final Document d: extiter) {
				ext.put(d.getString(Fields.CONFIG_KEY), d.getString(Fields.CONFIG_VALUE));
			}
			final Map<String, Map<String, Document>> provcfg = getProviderConfig();
			final Map<String, ProviderConfig> provs = new HashMap<>();
			for (final Entry<String, Map<String, Document>> d: provcfg.entrySet()) {
				final ProviderConfig pc = new ProviderConfig(
						d.getValue().get(Fields.CONFIG_PROVIDER_ENABLED)
								.getBoolean(Fields.CONFIG_VALUE),
						d.getValue().get(Fields.CONFIG_PROVIDER_FORCE_LINK_CHOICE)
								.getBoolean(Fields.CONFIG_VALUE));
				provs.put(d.getKey(), pc);
			}
			final Map<String, Document> appcfg = getAppConfig();
			final Boolean allowLogin = appcfg.get(Fields.CONFIG_APP_ALLOW_LOGIN)
					.getBoolean(Fields.CONFIG_VALUE);
			final Map<TokenLifetimeType, Long> tokens = new HashMap<>();
			for (final Entry<TokenLifetimeType, String> e: TOKEN_LIFETIME_FIELD_MAP.entrySet()) {
				tokens.put(e.getKey(), appcfg.get(e.getValue()).getLong(Fields.CONFIG_VALUE));
			}
			return new AuthConfigSet<T>(new AuthConfig(allowLogin, provs, tokens),
					mapper.fromMap(ext));
		} catch (MongoException e) {
			throw new AuthStorageException("Connection to database failed: " + e.getMessage(), e);
		}
	}
}
