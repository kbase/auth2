package us.kbase.auth2.lib.storage.mongo;

public class Fields {

	//TODO JAVADOC
	
	public static final String FIELD_SEP = ".";

	public static final String MONGO_ID = "_id";

	//user fields
	public static final String USER_NAME = "user";
	public static final String USER_FULL_NAME = "full";
	public static final String USER_EMAIL = "email";
	public static final String USER_IDENTITIES = "idents";
	public static final String USER_LOCAL = "lcl";
	public static final String USER_ROLES = "roles";
	public static final String USER_CUSTOM_ROLES = "custrls";
	public static final String USER_CREATED = "create";
	public static final String USER_LAST_LOGIN = "login";
	// these 3 are for local accounts only
	public static final String USER_PWD_HSH = "pwdhsh";
	public static final String USER_SALT = "salt";
	public static final String USER_RESET_PWD = "rstpwd";
	
	//identities fields
	public static final String IDENTITIES_ID = "id";
	public static final String IDENTITIES_PROVIDER = "prov";
	public static final String IDENTITIES_PROV_ID = "prov_id";
	public static final String IDENTITIES_USER = "uid";
	public static final String IDENTITIES_NAME = "fullname";
	public static final String IDENTITIES_EMAIL = "email";
	
	//token fields
	public static final String TOKEN_TYPE = "type";
	public static final String TOKEN_USER_NAME = "user";
	public static final String TOKEN_TOKEN = "token";
	public static final String TOKEN_EXPIRY = "expires";
	public static final String TOKEN_ID = "id";
	public static final String TOKEN_NAME = "name";
	public static final String TOKEN_CREATION = "create";
	
	//temporary token fields
	public static final String TEMP_TOKEN_TOKEN = "token";
	public static final String TEMP_TOKEN_EXPIRY = "expires";
	public static final String TEMP_TOKEN_ID = "id";
	public static final String TEMP_TOKEN_CREATION = "create";
	public static final String TEMP_TOKEN_IDENTITIES = "idents";
	
	//Custom roles fields
	public static final String ROLES_ID = "id";
	public static final String ROLES_DESC = "desc";
	
	// configuration fields
	public static final String CONFIG_KEY = "config";
	public static final String CONFIG_VALUE = "config";
	public static final String CONFIG_UPDATE = "inupdate";
	public static final String CONFIG_SCHEMA_VERSION = "schemaver";

}
