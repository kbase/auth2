package us.kbase.auth2.service.common;

/** Field names used in incoming and outgoing data structures.
 * @author gaprice@lbl.gov
 *
 */
public class Fields {

	/* general */
	
	/** The ID of some entity. */
	public static final String ID = "id";
	/** The description of some entity. */
	public static final String DESCRIPTION = "desc";
	/** Whether a user has some property */
	public static final String HAS = "has";
	
	/* root */
	
	/** The version of the service. */
	public static final String VERSION = "version";
	/** The service name. */
	public static final String SERVICE_NAME = "servicename";
	/** The time, in milliseconds since the epoch, at the service. */
	public static final String SERVER_TIME = "servertime";
	/** The Git commit from which the service was built. */
	public static final String GIT_HASH = "gitcommithash";
	
	/* login */
	
	/** Whether the user's token should be set as a session token or not. */
	public static final String STAY_LOGGED_IN = "stayloggedin";
	/** The set of accounts to which the user can log in. */
	public static final String LOGIN = "login";
	/** The set of identities that can be used to create an account. */
	public static final String CREATE = "create";
	/** Whether the user can currently log in. */
	public static final String LOGIN_ALLOWED = "loginallowed";
	/** Whether accounts can currently be created. */
	public static final String CREATION_ALLOWED = "creationallowed";
	/** Whether the user is restricted from logging in because they're not an admin. */
	public static final String ADMIN_ONLY = "adminonly";
	/** Whether all the user's remote identities should be linked to their account on login or
	 * creation.
	 */
	public static final String LINK_ALL = "linkall";
	
	/* linking */
	
	/** Whether unlinking a remote identity from an account is allowed. */
	public static final String UNLINK = "unlink";
	/** Identities that are already linked to an account. */
	public static final String LINKED = "linked";
	/** Whether identities are available for linking to an account. */
	public static final String HAS_LINKS = "haslinks";
	
	/* login and linking */
	
	/** When the temporary token associated with the login or linking process expires. */
	public static final String CHOICE_EXPIRES = "expires";
	/** The environment in which the login or linking operation is taking place. */
	public static final String ENVIRONMENT = "environment";
	
	/* policy ids */
	
	/** The ID of a policy. */
	public static final String POLICY_ID = "policyid";
	/** A set of policy IDs. */
	public static final String POLICY_IDS = "policyids";
	/** The date on which a policy ID was agreed to. */
	public static final String AGREED_ON = "agreedon";
	
	/* users */
	
	/** A user name. */
	public static final String USER = "user";
	/** A set of users. */
	public static final String USERS = "users";
	/** Whether any users are included in the results. */
	public static final String HAS_USERS = "hasusers";
	/** Whether the user is a local user. */
	public static final String LOCAL = "local";
	/** A user's display name. */
	public static final String DISPLAY = "display";
	/** A user's email address. */
	public static final String EMAIL = "email";
	/** When the user was created. */
	public static final String CREATED = "created";
	/** Whether the user is disabled. */
	public static final String DISABLED = "disabled";
	/** The reason the user was disabled. */
	public static final String DISABLED_REASON = "disabledreason";
	/** The time the user was last disabled or enabled. */
	public static final String ENABLE_TOGGLE_DATE = "enabletoggledate";
	/** The admin taht disabled or enabled the user. */
	public static final String ENABLE_TOGGLED_BY = "enabletoggledby";
	/** The time of the user's last login. */
	public static final String LAST_LOGIN = "lastlogin";
	
	/* passwords */
	
	/** A password. */
	public static final String PASSWORD = "pwd";
	/** An old password. */
	public static final String PASSWORD_OLD = "pwdold";
	/** A new password. */
	public static final String PASSWORD_NEW = "pwdnew";
	
	/* suggested names */
	
	/** A name for a user that is currently available. */
	public static final String AVAILABLE_NAME = "availablename";
	
	/* roles */
	
	/** A set of roles. */
	public static final String ROLES = "roles";
	/** Whether the user has any roles. */
	public static final String HAS_ROLES = "hasroles";
	/** A set of custom roles. */
	public static final String CUSTOM_ROLES = "customroles";
	/** Whether the user has any custom roles. */
	public static final String HAS_CUSTOM_ROLES = "hascustomroles";
	/** A prefix for custom roles when listing custom roles in a form. This prevents custom role
	 * names from conflicting with other items in the form.
	 */
	public static final String CUSTOM_ROLE_FORM_PREFIX = "crole_";
	
	/* search */
	
	/** Whether a user search should proceed on the user's user name. */
	public static final String SEARCH_USER = "username";
	/** Whether a user search should proceed on the user's display name. */
	public static final String SEARCH_DISPLAY = "displayname";
	/** The user name or display name prefix with which to conduct a search. */
	public static final String SEARCH_PREFIX = "prefix";
	/** A list of users. */
	public static final String LIST = "list";
	/** A list of fields upon which a user search should be conducted. */
	public static final String FIELDS = "fields";
	
	/* provider info */
	
	/** A set of identity providers. */
	public static final String PROVIDERS = "providers";
	/** Whether any identity providers are included in the response. */
	public static final String HAS_PROVIDERS = "hasprov";
	/** An identity provider. */
	public static final String PROVIDER = "provider";
	/** The user name for a user at the remote identity provider. */
	public static final String PROV_USER = "provusername";
	/** A set of user names from a remote identity provider. */
	public static final String PROV_USERS = "provusernames";
	/** The email address for a user at the remote identity provider. */
	public static final String PROV_EMAIL = "provemail";
	/** The full (e.g. display) name for a user at the remote identity provider. */
	public static final String PROV_FULL = "provfullname";
	/** A set of identities. */
	public static final String IDENTITIES = "idents";
	/** A provider OAuth2 access code. */
	public static final String PROVIDER_CODE = "code";
	/** The state returned from a provider as part of an OAuth2 response. */
	public static final String PROVIDER_STATE = "state";
	
	/* tokens */
	
	/** A token. */
	public static final String TOKEN = "token";
	/** A set of tokens. */
	public static final String TOKENS = "tokens";
	/** The name of a token. */
	public static final String TOKEN_NAME = "name";
	/** The type of a token. */
	public static final String TOKEN_TYPE = "type";
	/** Whether the user can create developer tokens. */
	public static final String TOKEN_DEV = "dev";
	/** Whether the user can create service tokens. */
	public static final String TOKEN_SERVICE = "service";
	/** User supplied context to be saved with a token on token creation. */
	public static final String CUSTOM_CONTEXT = "customcontext";
	/** The user's current token. */
	public static final String CURRENT = "current";
	
	/* urls */
	
	/** A url for a user. */
	public static final String URL_USER = "userurl";
	/** A url for performing a reset. */
	public static final String URL_RESET = "reseturl";
	/** A url for revoking a token(s). */
	public static final String URL_REVOKE = "revokeurl";
	/** A url for revoking all tokens. */
	public static final String URL_REVOKE_ALL = "revokeallurl";
	/** A url for accessing a token or token configuration. */
	public static final String URL_TOKEN = "tokenurl";
	/** A url for accessing a policy. */
	public static final String URL_POLICY = "policyurl";
	/** A url for performing a search. */
	public static final String URL_SEARCH = "searchurl";
	/** A url for creating an entity. */
	public static final String URL_CREATE = "createurl";
	/** A url for accessing a role. */
	public static final String URL_ROLE = "roleurl";
	/** A url for accessing a custom role. */
	public static final String URL_CUSTOM_ROLE = "customroleurl";
	/** A url for deleting a custom role. */
	public static final String URL_DELETE_CUSTOM_ROLE = "deletecustomroleurl";
	/** A url for disabling a user. */
	public static final String URL_DISABLE = "disableurl";
	/** A url for forcing a password reset. */
	public static final String URL_FORCE_RESET = "forcereseturl";
	/** A url for modifying the basic service configuration. */
	public static final String URL_CFG_BASIC = "cfgbasicurl";
	/** A url for modifying an environment configuration. */
	public static final String URL_ENVIRONMENT = "environmenturl";
	/** A url for modifying a provider configuration. */
	public static final String URL_PROVIDER = "providerurl";
	/** A url for starting the OAuth2 process. */
	public static final String URL_START = "starturl";
	/** A url for canceling a link or login process. */
	public static final String URL_CANCEL = "cancelurl";
	/** A url for picking an account. */
	public static final String URL_PICK = "pickurl";
	/** A url for logging in. */
	public static final String URL_LOGIN = "loginurl";
	/** A url for logging out. */
	public static final String URL_LOGOUT = "logouturl";
	/** A redirect url. */
	public static final String URL_REDIRECT = "redirecturl";
	/** A url for getting a suggested username. */
	public static final String URL_SUGGESTNAME = "suggestnameurl";
	/** A url for updating user information. */
	public static final String URL_USER_UPDATE = "userupdateurl";
	/** A url for unlinking a remote identity from an account. */
	public static final String URL_UNLINK = "unlinkurl";
	
	/* errors */
	
	/** An error. */
	public static final String ERROR = "error";
	
	/* ***** config ***** */
	
	/* providers */
	
	/** Whether a provider is enabled. */
	public static final String CFG_PROV_ENABLED = "enabled";
	/** Whether the user should always have to select a login choice, even if there's only one. */
	public static final String CFG_PROV_FORCE_LOGIN_CHOICE = "forceloginchoice";
	/** Whether the user should always have to select a link choice, even if there's only one. */
	public static final String CFG_PROV_FORCE_LINK_CHOICE = "forcelinkchoice";

	/* tokens */
	
	/** The suggested lifetime of tokens in a cache. */
	public static final String CFG_TOKEN_CACHE_TIME = "tokensugcache";
	/** The lifetime of a login token. */
	public static final String CFG_TOKEN_LOGIN = "tokenlogin";
	/** The lifetime of an agent token. */
	public static final String CFG_TOKEN_AGENT = "tokenagent";
	/** The lifetime of a developer token. */
	public static final String CFG_TOKEN_DEV = "tokendev";
	/** The lifetime of a server token. */
	public static final String CFG_TOKEN_SERV = "tokenserv";
	
	/* other */
	
	/** The environments */
	public static final String CFG_ENVIROMENTS = "environments";
	/** The environment */
	public static final String CFG_ENVIRONMENT = "environment";
	/** Whether returned errors should include a stack trace */
	public static final String CFG_SHOW_STACK_TRACE = "showstack";
	/** Whether the x-forward-for and x-real-ip headers should be ignored. */
	public static final String CFG_IGNORE_IP_HEADERS = "ignoreip";
	/** A prefix for urls that are allowed as redirect targets post login. */
	public static final String CFG_ALLOWED_LOGIN_REDIRECT = "allowedloginredirect";
	/** A url to redirect to when completing the login process and user interaction is required. */
	public static final String CFG_COMPLETE_LOGIN_REDIRECT = "completeloginredirect";
	/** A url to redirect to when the link process is complete. */
	public static final String CFG_POST_LINK_REDIRECT = "postlinkredirect";
	/** A url to redirect to when completing the link process and user interaction is required. */
	public static final String CFG_COMPLETE_LINK_REDIRECT = "completelinkredirect";
	/** Whether to allow non-admin logins. */
	public static final String CFG_ALLOW_LOGIN = "allowlogin";
	/** How often the configuration is synched from one service instance to another. */
	public static final String CFG_UPDATE_TIME_SEC = "updatetimesec";
	/** Configuration items to remove. */
	public static final String CFG_REMOVE = "remove";
	
}
