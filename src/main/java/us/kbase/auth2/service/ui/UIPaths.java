package us.kbase.auth2.service.ui;

/** Resource paths for the UI endpoints.
 * @author gaprice@lbl.gov
 *
 */
public class UIPaths {
	
	/* general strings */

	/** The URL path separator. */
	public static final String SEP = "/";
	private static final String COMPLETE = "complete";
	private static final String COMPLETE_PROVIDER = COMPLETE + SEP + "{provider}";
	private static final String CHOICE = "choice";
	private static final String CANCEL = "cancel";
	private static final String PICK = "pick";
	private static final String CREATE = "create";
	private static final String REVOKE = "revoke";
	private static final String REVOKE_ALL = "revokeall";
	private static final String SUGGESTNAME = "suggestname";
	private static final String NAME_ID = "{name}";
	private static final String ID = "{id}";
	private static final String LOGIN = "login";
	private static final String LOCAL = "localaccount";
	private static final String RESET = "reset";
	/** A portion of a path designating a user. */
	public static final String USER = "user";
	private static final String USER_PARAM = "{" + USER + "}";
	private static final String ROLES = "roles";
	private static final String START = "start";
	private static final String TOKEN = "token";
	private static final String UNLINK = "unlink";
	private static final String TOKENS = "tokens";
	/** A portion of a path designating a token ID. */
	public static final String TOKEN_ID = "tokenid";
	private static final String TOKEN_ID_PARAM = "{" + TOKEN_ID + "}";
	private static final String CUSTOM_ROLES = "customroles";
	
	/* Root endpoint */

	/** The root endpoint location. */
	public static final String ROOT = SEP;
	
	/* Admin endpoint */
	
	/** The admin endpoint root location. */
	public static final String ADMIN_ROOT = "/admin";

	/** A portion of a path designating the administration of a local account. */
	public static final String ADMIN_LOCALACCOUNT = LOCAL;
	/** A portion of a path designating the creation of a local account. */
	public static final String ADMIN_LOCAL_CREATE = LOCAL + SEP + CREATE;
	/** The local account creation endpoint location. */
	public static final String ADMIN_ROOT_LOCAL_CREATE = ADMIN_ROOT + SEP + ADMIN_LOCAL_CREATE;

	/** The user administration endpoint location. */
	public static final String ADMIN_ROOT_USER = ADMIN_ROOT + SEP + USER;
	/** A portion of a path designating the administration of a particular user, including the
	 * user's account name as a path parameter.
	 */
	public static final String ADMIN_USER_PARAM = USER + SEP + USER_PARAM;

	/** A portion of a path designating the disabling of a user. */
	public static final String ADMIN_DISABLE = "disable";
	/** A portion of a path designating the disabling of a particular user, including the user's
	 * account name as a path parameter.
	 */
	public static final String ADMIN_USER_DISABLE = ADMIN_USER_PARAM + SEP + ADMIN_DISABLE;

	/** A portion of a path designating the administration of a user's roles. */
	public static final String ADMIN_ROLES = ROLES;
	/** A portion of a path designating the administration of a particular users's roles, including
	 * the user's account name as a path parameter.
	 */
	public static final String ADMIN_USER_ROLES = ADMIN_USER_PARAM + SEP + ADMIN_ROLES;
	
	/** A portion of a path designating setting that a user or users should be required to reset
	 * their password on the next login. 
	 */
	public static final String ADMIN_FORCE_RESET_PWD = "force" + RESET;
	/** The force reset all passwords endpoint location. */
	public static final String ADMIN_ROOT_FORCE_RESET_PWD = ADMIN_ROOT + SEP +
			ADMIN_FORCE_RESET_PWD;
	/** A portion of a path designating setting that a particular user should be required to reset
	 * their password on the next login, including the user's account name as a path parameter.
	 */
	public static final String ADMIN_USER_FORCE_RESET_PWD = ADMIN_USER_PARAM + SEP +
			ADMIN_FORCE_RESET_PWD;
	
	/** A portion of a path designating the resetting of a password. */
	public static final String ADMIN_RESET_PWD = RESET;
	/** A portion of a path designating the resetting of a password for a particular user,
	 * including the user's account name as a path parameter.
	 */
	public static final String ADMIN_USER_RESET_PWD = ADMIN_USER_PARAM + SEP + ADMIN_RESET_PWD;

	/** A portion of a path indicating that all tokens should be revoked. */
	public static final String ADMIN_REVOKE_ALL = REVOKE_ALL;
	/** The revoke all tokens endpoint location. */
	public static final String ADMIN_ROOT_REVOKE_ALL = ADMIN_ROOT + SEP + ADMIN_REVOKE_ALL;
	
	/** A portion of a path indicating the administration of a policy ID. */
	public static final String ADMIN_POLICY_ID = "policyid";
	/** The administrate a policy ID endpoint location. */
	public static final String ADMIN_ROOT_POLICY_ID = ADMIN_ROOT + SEP + ADMIN_POLICY_ID;
	
	/** A portion of a path designating an administrator user search. */
	public static final String ADMIN_SEARCH = "search";
	/** The administrator user search endpoint location. */
	public static final String ADMIN_ROOT_SEARCH = ADMIN_ROOT + SEP + ADMIN_SEARCH;
	
	/** A portion of a path designating an administration operation on a token. */
	public static final String ADMIN_TOKEN = TOKEN;
	/** The administrator token introspection endpoint. */
	public static final String ADMIN_ROOT_TOKEN = ADMIN_ROOT + SEP + TOKEN;
	/** A portion of a path designating an administration operation on one or more tokens. */
	public static final String ADMIN_TOKENS = TOKENS;
	/** A portion of a path designating administration operations on a particular user's tokens,
	 * including the user's account name as a path parameter.
	 */
	public static final String ADMIN_USER_TOKENS = ADMIN_USER_PARAM + SEP + ADMIN_TOKENS;
	/** A portion of a path designating the revocation of all of a user's tokens, including the
	 * user's account name as a path parameter.
	 */
	public static final String ADMIN_USER_TOKENS_REVOKE_ALL = ADMIN_USER_TOKENS + SEP + REVOKE_ALL;
	/** A portion of a path designating the revocation of a token. */
	public static final String ADMIN_USER_TOKENS_REVOKE = REVOKE;
	/** A portoin of a path designating the revcation of a particular token from a particular user,
	 * including the user's account name and the token ID as path parameters.
	 */
	public static final String ADMIN_USER_TOKENS_REVOKE_ID = ADMIN_USER_TOKENS + SEP + 
			ADMIN_USER_TOKENS_REVOKE + SEP + TOKEN_ID_PARAM;
	
	/** A portion of a path designating the administration of a custom role. */
	public static final String ADMIN_CUSTOM_ROLES = CUSTOM_ROLES;
	/** A portion of a path designating the administration of a particular user's custom role,
	 * including the user's account name as a path parameter. */
	public static final String ADMIN_USER_CUSTOM_ROLES = ADMIN_USER_PARAM + SEP +
			ADMIN_CUSTOM_ROLES;
	
	/** A portion of a path designating setting a custom role. */
	public static final String ADMIN_CUSTOM_ROLES_SET = ADMIN_CUSTOM_ROLES + SEP +  "set";
	/** The set custom role endpoint location. */
	public static final String ADMIN_ROOT_CUSTOM_ROLES_SET = ADMIN_ROOT + SEP +
			ADMIN_CUSTOM_ROLES_SET;
	
	/** A portion of a path designating deleting a custom role. */
	public static final String ADMIN_CUSTOM_ROLES_DELETE = ADMIN_CUSTOM_ROLES + SEP +  "delete";
	/** The delete custom role endpoint location. */
	public static final String ADMIN_ROOT_CUSTOM_ROLES_DELETE = ADMIN_ROOT + SEP + 
			ADMIN_CUSTOM_ROLES_DELETE;
	
	/** A portion of a path designating the administration of the service configuration. */
	public static final String ADMIN_CONFIG = "config";
	/** A portion of a path designating the administration of the basic configuration. */
	public static final String ADMIN_CONFIG_BASIC = ADMIN_CONFIG + SEP + "basic";
	/** A portion of a path designating the administration of the configuration of an environment.
	 */
	public static final String ADMIN_CONFIG_ENVIRONMENT = ADMIN_CONFIG + SEP + "environment";
	/** A portion of a path designating the administration of the configuration of an identity
	 * provider.
	 */
	public static final String ADMIN_CONFIG_PROVIDER = ADMIN_CONFIG + SEP + "provider";
	/** A portion of a path designating the reset of the service configuration. */
	public static final String ADMIN_CONFIG_RESET = ADMIN_CONFIG + SEP + RESET;
	/** A portion of a path designating the administration of the tokens configuration. */
	public static final String ADMIN_CONFIG_TOKEN = ADMIN_CONFIG + SEP + TOKEN;
	/** The basic service configuration endpoint location. */
	public static final String ADMIN_ROOT_CONFIG_BASIC = ADMIN_ROOT + SEP + ADMIN_CONFIG_BASIC;
	/** The identity provider configuration endpoint location. */
	public static final String ADMIN_ROOT_CONFIG_PROVIDER = ADMIN_ROOT + SEP +
			ADMIN_CONFIG_PROVIDER;
	/** The environment configuration endpoint location. */
	public static final String ADMIN_ROOT_CONFIG_ENVIRONMENT = ADMIN_ROOT + SEP +
			ADMIN_CONFIG_ENVIRONMENT;
	/** The configuration reset endpoint location. */
	public static final String ADMIN_ROOT_CONFIG_RESET = ADMIN_ROOT + SEP + ADMIN_CONFIG_RESET;
	/** The token configuration endpoint location. */
	public static final String ADMIN_ROOT_CONFIG_TOKEN = ADMIN_ROOT + SEP + ADMIN_CONFIG_TOKEN;
	
	/* localaccount endpoint */
	
	/** The local account endpoint root location. */
	public static final String LOCAL_ROOT = SEP + LOCAL;
	
	/** A portion of a path designating a local account login. */
	public static final String LOCAL_LOGIN = LOGIN;
	/** The local account login endpoint location. */
	public static final String LOCAL_ROOT_LOGIN = LOCAL_ROOT + SEP + LOGIN;
	
	/** A portion of a path designating the resetting of a local account's password. */
	public static final String LOCAL_RESET = RESET;
	/** The local account password reset endpoint location. */
	public static final String LOCAL_ROOT_RESET = LOCAL_ROOT + SEP + LOCAL_RESET;
	
	/* login endpoint */
	
	/** The login endpoint root location. */
	public static final String LOGIN_ROOT = SEP + LOGIN;
	
	/** A portion of a path designating the start of an OAuth2 login process. */
	public static final String LOGIN_START = START;
	/** The OAuth2 login start endpoint location. */
	public static final String LOGIN_ROOT_START = LOGIN_ROOT + SEP + START;
	/** The OAuth2 login complete endpoint location. */
	public static final String LOGIN_ROOT_COMPLETE = LOGIN_ROOT + SEP + COMPLETE;
	/** A portion of a path designating the completion of an OAuth2 provider redirect, including
	 * the provider name as a path parameter.
	 */
	public static final String LOGIN_COMPLETE_PROVIDER = COMPLETE_PROVIDER;
	/** A portion of a path designating suggesting a user name for a new user. */
	public static final String LOGIN_SUGGEST_NAME = SUGGESTNAME + SEP + NAME_ID;
	/** The name suggestion endpoint location. */
	public static final String LOGIN_ROOT_SUGGESTNAME = LOGIN_ROOT + SEP + SUGGESTNAME;
	/** A portion of a path designating a choice must be made by a user with regard to an OAuth2
	 * login.
	 */
	public static final String LOGIN_CHOICE = CHOICE;
	/** The login user choice endpoint location. */
	public static final String LOGIN_ROOT_CHOICE = LOGIN_ROOT + SEP + LOGIN_CHOICE;
	/** A portion of a path designating cancellation of the login process. */
	public static final String LOGIN_CANCEL = CANCEL;
	/** The login cancel endpoint location */
	public static final String LOGIN_ROOT_CANCEL = LOGIN_ROOT + SEP + LOGIN_CANCEL;
	/** A portion of a path designating a user picking an account with which to login. */
	public static final String LOGIN_PICK = PICK;
	/** The login pink account endpoint location. */
	public static final String LOGIN_ROOT_PICK = LOGIN_ROOT + SEP + LOGIN_PICK;
	/** A portion of a path designating a user creating a new account. */
	public static final String LOGIN_CREATE = CREATE;
	/** The login create account endpoint location. */
	public static final String LOGIN_ROOT_CREATE = LOGIN_ROOT + SEP + LOGIN_CREATE;
	
	/* link endpoint */
	
	/** the link endpoint root location. */
	public static final String LINK_ROOT = SEP + "link";
	
	/** A portion of a path designating the start of an OAuth2 link process. */
	public static final String LINK_START = START;
	/** The OAuth2 link start endpoint location. */
	public static final String LINK_ROOT_START = LINK_ROOT + SEP + START;
	/** The OAuth2 link complete endpoint location. */
	public static final String LINK_ROOT_COMPLETE = LINK_ROOT + SEP + COMPLETE;
	/** A portion of a path designating the completion of an OAuth2 provider redirect, including
	 * the provider name as a path parameter.
	 */
	public static final String LINK_COMPLETE_PROVIDER = COMPLETE_PROVIDER;
	/** A portion of a path designating a choice must be made by a user with regard to an OAuth2
	 * account link.
	 */
	public static final String LINK_CHOICE = CHOICE;
	/** The link user choice endpoint location. */
	public static final String LINK_ROOT_CHOICE = LINK_ROOT + SEP + LINK_CHOICE;
	/** A portion of a path designating cancellation of the link process. */
	public static final String LINK_CANCEL = CANCEL;
	/** The link cancel endpoint location */
	public static final String LINK_ROOT_CANCEL = LINK_ROOT + SEP + LINK_CANCEL;
	/** A portion of a path designating a user picking a remote identity to link to their
	 * account.
	 */
	public static final String LINK_PICK = PICK;
	/** The link pink account endpoint location. */
	public static final String LINK_ROOT_PICK = LINK_ROOT + SEP + LINK_PICK;
	
	/* logout endpoint */
	
	/** The logout endpoint root location. */
	public static final String LOGOUT_ROOT = SEP + "logout";
	
	/* me endpoint */
	
	/** The me endpoint root location. */
	public static final String ME_ROOT = SEP + "me";

	/** A portion of a path designating the unlinking of a remote identity from a user account,
	 * including the identity's ID as a path parameter.
	 */
	public static final String ME_UNLINK_ID = UNLINK + SEP + ID;
	
	/** The unlink endpoint location. */
	public static final String ME_ROOT_UNLINK = ME_ROOT + SEP + UNLINK;
	
	/** A portion of a path designating the user's roles. */
	public static final String ME_ROLES = ROLES;
	/** The user roles endpoint location. */
	public static final String ME_ROOT_ROLES = ME_ROOT + SEP + ME_ROLES;
	
	/* tokens endpoint */
	
	/** The token endpoint root location. */
	public static final String TOKENS_ROOT = SEP + TOKENS;
	
	/** A portion of a path designating the revocation of a token. */
	public static final String TOKENS_REVOKE = REVOKE;
	/** The token revocation endpoint location. */
	public static final String TOKENS_ROOT_REVOKE = TOKENS_ROOT + SEP + TOKENS_REVOKE;
	/** A portion of a path designating the revocation of a token, including the token id as a
	 * path parameter.
	 */
	public static final String TOKENS_REVOKE_ID = TOKENS_REVOKE + SEP + TOKEN_ID_PARAM;
	/** A portion of a path designating the revocation of all of a user's tokens. */
	public static final String TOKENS_REVOKE_ALL = REVOKE_ALL;
	/** The revoke all tokens endpoint location. */
	public static final String TOKENS_ROOT_REVOKE_ALL = TOKENS_ROOT + SEP + TOKENS_REVOKE_ALL;
	
	/* customroles endpoint */
	
	/** The custom roles endpoint location. */
	public static final String CUSTOM_ROLES_ROOT = SEP + CUSTOM_ROLES;
}
