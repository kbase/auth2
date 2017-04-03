package us.kbase.auth2.lib.storage.mongo;

/** This class defines the field names used in MongoDB documents for storing authentication
 * data.
 * @author gaprice@lbl.gov
 *
 */
public class Fields {

	/** The separator between mongo field names. */
	public static final String FIELD_SEP = ".";

	/** The key for the MongoDB ID in documents. */
	public static final String MONGO_ID = "_id";
	
	/* ****************
	 * user fields
	 * ****************
	 */
	
	/** The user name. */
	public static final String USER_NAME = "user";
	/** The display name for the user. */
	public static final String USER_DISPLAY_NAME = "display";
	/** The canonical version of the display name. E.g. split into parts, whitespace removed, etc.
	 */
	public static final String USER_DISPLAY_NAME_CANONICAL = "dispcan";
	/** The user's email address. */
	public static final String USER_EMAIL = "email";
	/** The user's remote identities. */
	public static final String USER_IDENTITIES = "idents";
	/** Whether the user is a local user (no remote identities) or not. */
	public static final String USER_LOCAL = "lcl";
	/** The roles the user possesses. */
	public static final String USER_ROLES = "roles";
	/** The custom roles the user possesses. */
	public static final String USER_CUSTOM_ROLES = "custrls";
	/** Any policy IDs associated with the user. */
	public static final String USER_POLICY_IDS = "policyids";
	/** The date the user account was created. */
	public static final String USER_CREATED = "create";
	/** The date of the user's last login. */
	public static final String USER_LAST_LOGIN = "login";
	/** The administrator that last enabled or disabled the account. Null if the account has never
	 * been disabled.
	 */
	public static final String USER_DISABLED_ADMIN = "dsbleadmin";
	/** The reason the account was disabled. Null if the the account is not disabled. */
	public static final String USER_DISABLED_REASON = "dsblereas";
	/** The date the account was last enabled or disabled. Null if the account has never been
	 * disabled.
	 */
	public static final String USER_DISABLED_DATE = "dsbledate";
	/** The users's hashed password. For local accounts only. */
	public static final String USER_PWD_HSH = "pwdhsh";
	/** The salt used for hashing the password. For local accounts only. */
	public static final String USER_SALT = "salt";
	/** Whether the a password reset is required for the user on the next login.
	 * For local accounts only.
	 */
	public static final String USER_RESET_PWD = "rstpwd";
	/** The date of the last password reset. For local accounts only.
	 * Null if the password has never been reset.
	 */
	public static final String USER_RESET_PWD_LAST = "lastrst";
	
	/* *****************
	 * Policy ID fields
	 * *****************
	 */
	
	/** The ID of a policy document to which a user has agreed. */
	public static final String POLICY_ID = "id";
	/** The time the user agreed to the document. */
	public static final String POLICY_AGREED_ON = "agreed";
	
	/* ****************
	 * identity fields
	 * ****************
	 */

	/** The locally assigned ID for the identity. */
	public static final String IDENTITIES_ID = "id";
	/** The provider of the identity. E.g. Globus, Google, etc. */
	public static final String IDENTITIES_PROVIDER = "prov";
	/** The ID assigned to the identity by the provider. */
	public static final String IDENTITIES_PROV_ID = "prov_id";
	/** The username of the identity. */
	public static final String IDENTITIES_USER = "uid";
	/** The display or fullname of the identity. */
	public static final String IDENTITIES_NAME = "fullname";
	/** The email address of the identity. */
	public static final String IDENTITIES_EMAIL = "email";
	
	/* **************
	 * token fields
	 * **************
	 */
	
	/** The type of the token. */
	public static final String TOKEN_TYPE = "type";
	/** The user name of the user the token is associated with. */
	public static final String TOKEN_USER_NAME = "user";
	/** The hashed token. */
	public static final String TOKEN_TOKEN = "token";
	/** The date the token expires. */
	public static final String TOKEN_EXPIRY = "expires";
	/** The ID of the token. */
	public static final String TOKEN_ID = "id";
	/** The name of the token, if any. */
	public static final String TOKEN_NAME = "name";
	/** The date the token was created. */
	public static final String TOKEN_CREATION = "create";
	/** The operating system of the user when the token was created. */
	public static final String TOKEN_OS = "os";
	/** The version of the operating system of the user when the token was created. */
	public static final String TOKEN_OS_VER = "osver";
	/** The agent of the user when the token was created. */
	public static final String TOKEN_AGENT = "agent";
	/** The version of the agent of the user when the token was created. */
	public static final String TOKEN_AGENT_VER = "agentver";
	/** The device of the user when the token was created. */
	public static final String TOKEN_DEVICE = "device";
	/** The IP address of the user when the token was created. */
	public static final String TOKEN_IP = "ip";
	/** Any custom token creation context information supplied by the user. */
	public static final String TOKEN_CUSTOM_CONTEXT = "custctx";
	/** A key for a custom context key / value pair. */
	public static final String TOKEN_CUSTOM_KEY = "k";
	/** A value for a custom context key / value pair. */
	public static final String TOKEN_CUSTOM_VALUE = "v";
	
	/* ************************
	 * temporary token fields
	 * ************************
	 */
	
	/** The hashed temporary token. */
	public static final String TOKEN_TEMP_TOKEN = "token";
	/** The date the temporary token expires. */
	public static final String TOKEN_TEMP_EXPIRY = "expires";
	/** The ID of the temporary token. */
	public static final String TOKEN_TEMP_ID = "id";
	/** The date the temporary token was created. */
	public static final String TOKEN_TEMP_CREATION = "create";
	/** The remote identities associated with the temporary token. */
	public static final String TOKEN_TEMP_IDENTITIES = "idents";
	
	/* ********************
	 * custom roles fields
	 * ********************
	 */
	
	/** The ID of the custom role. */
	public static final String ROLES_ID = "id";
	/** The description of the custom role. */
	public static final String ROLES_DESC = "desc";
	
	/* ***********************
	 * database schema fields
	 * ***********************
	 */
	
	/** The key for the schema field. The key and value are used to ensure there is
	 * never more than one schema record.
	 */
	public static final String DB_SCHEMA_KEY = "schema";
	/** The value for the schema field. The key and value are used to ensure there is
	 * never more than one schema record.
	 */
	public static final String DB_SCHEMA_VALUE = "schema";
	/** Whether the database schema is in the process of being updated. */
	public static final String DB_SCHEMA_UPDATE = "inupdate";
	/** The version of the database schema. */
	public static final String DB_SCHEMA_VERSION = "schemaver";

	/* *********************
	 * configuration fields
	 * *********************
	 */
	
	/** A key for a configuration key / value pair. */
	public static final String CONFIG_KEY = "key";
	/** A value for a configuration key / value pair. */
	public static final String CONFIG_VALUE = "val";
	/** Whether non-administrator logins are allowed. */
	public static final String CONFIG_APP_ALLOW_LOGIN = "allowlogin";
	/** The provider to which a configuration key / value pair applies. */
	public static final String CONFIG_PROVIDER = "prov";
	/** Whether a provider is enabled. */
	public static final String CONFIG_PROVIDER_ENABLED = "enabled";
	/** Whether a user should always have to choose to login, even if there's only one choice. */
	public static final String CONFIG_PROVIDER_FORCE_LOGIN_CHOICE = "loginchoice";
	/** Whether a user should always have to choose to link a remote identity to their account,
	 * even if there's only one choice.
	 */
	public static final String CONFIG_PROVIDER_FORCE_LINK_CHOICE = "linkchoice";
	/** The suggested lifetime for a token in an external cache. */
	public static final String CONFIG_APP_TOKEN_LIFE_CACHE = "tokenlifecache";
	/** The lifetime of a login token. */
	public static final String CONFIG_APP_TOKEN_LIFE_LOGIN = "tokenlifelogin";
	/** The lifetime of an agent token. */
	public static final String CONFIG_APP_TOKEN_LIFE_AGENT = "tokenlifeagent";
	/** The lifetime of a developer token. */
	public static final String CONFIG_APP_TOKEN_LIFE_DEV = "tokenlifedev";
	/** The lifetime of a server token. */
	public static final String CONFIG_APP_TOKEN_LIFE_SERV = "tokenlifeserv";
}
