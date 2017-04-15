package us.kbase.auth2.service.common;

public class Fields {

	//TODO JAVADOC
	
	/* general */
	
	public static final String ID = "id";
	public static final String DESCRIPTION = "desc";
	public static final String HAS = "has";
	
	/* login */
	
	public static final String STAY_LOGGED_IN = "stayloggedin";
	public static final String LOGIN = "login";
	public static final String CREATE = "create";
	public static final String LOGIN_ALLOWED = "loginallowed";
	public static final String CREATION_ALLOWED = "creationallowed";
	public static final String ADMIN_ONLY = "adminonly";
	public static final String LINK_ALL = "linkall";
	
	/* login and linking */
	
	public static final String CHOICE_EXPIRES = "expires";
	
	/* policy ids */
	
	public static final String POLICY_ID = "policyid";
	public static final String POLICY_IDS = "policyids";
	public static final String AGREED_ON = "agreedon";
	
	/* users */
	
	public static final String USER = "user";
	public static final String USERS = "users";
	public static final String HAS_USERS = "hasusers";
	public static final String LOCAL = "local";
	public static final String DISPLAY = "display";
	public static final String EMAIL = "email";
	public static final String CREATED = "created";
	public static final String DISABLED = "disabled";
	public static final String DISABLED_REASON = "disabledreason";
	public static final String ENABLE_TOGGLE_DATE = "enabletoggledate";
	public static final String ENABLE_TOGGLED_BY = "enabletoggledby";
	public static final String LAST_LOGIN = "lastlogin";
	
	/* passwords */
	
	public static final String PASSWORD = "pwd";
	public static final String PASSWORD_OLD = "pwdold";
	public static final String PASSWORD_NEW = "pwdnew";
	
	/* suggested names */
	public static final String AVAILABLE_NAME = "availablename";
	
	/* roles */
	
	public static final String ROLES = "roles";
	public static final String HAS_ROLES = "hasroles";
	public static final String CUSTOM_ROLES = "customroles";
	public static final String HAS_CUSTOM_ROLES = "hascustomroles";
	public static final String CUSTOM_ROLE_FORM_PREFIX = "crole_";
	
	/* search */
	
	public static final String SEARCH_USER = "username";
	public static final String SEARCH_DISPLAY = "displayname";
	public static final String SEARCH_PREFIX = "prefix";
	public static final String LIST = "list";
	public static final String FIELDS = "fields";
	
	/* provider info */
	
	public static final String PROVIDERS = "providers";
	public static final String HAS_PROVIDERS = "hasprov";
	public static final String PROVIDER = "provider";
	public static final String PROV_USER = "provusername";
	public static final String PROV_USERS = "provusernames";
	public static final String PROV_EMAIL = "provemail";
	public static final String PROV_FULL = "provfullname";
	public static final String IDENTITIES = "idents";
	public static final String PROVIDER_CODE = "code";
	public static final String PROVIDER_STATE = "state";
	
	/* tokens */
	
	public static final String TOKEN = "token";
	public static final String TOKENS = "tokens";
	public static final String TOKEN_NAME = "name";
	public static final String CUSTOM_CONTEXT = "customcontext";
	
	/* urls */
	
	public static final String URL_USER = "userurl";
	public static final String URL_RESET = "reseturl";
	public static final String URL_REVOKE = "revokeurl";
	public static final String URL_REVOKE_ALL = "revokeallurl";
	public static final String URL_TOKEN = "tokenurl";
	public static final String URL_POLICY = "policyurl";
	public static final String URL_SEARCH = "searchurl";
	public static final String URL_CREATE = "createurl";
	public static final String URL_ROLE = "roleurl";
	public static final String URL_CUSTOM_ROLE = "customroleurl";
	public static final String URL_DELETE_CUSTOM_ROLE = "deletecustomroleurl";
	public static final String URL_DISABLE = "disableurl";
	public static final String URL_FORCE_RESET = "forcereseturl";
	public static final String URL_BASIC = "basicurl";
	public static final String URL_PROVIDER = "providerurl";
	public static final String URL_START = "starturl";
	public static final String URL_CANCEL = "cancelurl";
	public static final String URL_PICK = "pickurl";
	public static final String URL_LOGIN = "loginurl";
	public static final String URL_REDIRECT = "redirecturl";
	public static final String URL_SUGGESTNAME = "suggestnameurl";
	
	/* errors */
	
	public static final String ERROR = "error";
	
	/* ***** config ***** */
	
	/* providers */
	
	public static final String CFG_PROV_ENABLED = "enabled";
	public static final String CFG_PROV_FORCE_LOGIN_CHOICE = "forceloginchoice";
	public static final String CFG_PROV_FORCE_LINK_CHOICE = "forcelinkchoice";

	/* tokens */
	
	public static final String CFG_TOKEN_CACHE_TIME = "tokensugcache";
	public static final String CFG_TOKEN_LOGIN = "tokenlogin";
	public static final String CFG_TOKEN_AGENT = "tokenagent";
	public static final String CFG_TOKEN_DEV = "tokendev";
	public static final String CFG_TOKEN_SERV = "tokenserv";
	
	/* other */
	
	public static final String CFG_SHOW_STACK_TRACE = "showstack";
	public static final String CFG_IGNORE_IP_HEADERS = "ignoreip";
	public static final String CFG_ALLOWED_LOGIN_REDIRECT = "allowedloginredirect";
	public static final String CFG_COMPLETE_LOGIN_REDIRECT = "completeloginredirect";
	public static final String CFG_POST_LINK_REDIRECT = "postlinkredirect";
	public static final String CFG_COMPLETE_LINK_REDIRECT = "completelinkredirect";
	public static final String CFG_ALLOW_LOGIN = "allowlogin";
	public static final String CFG_UPDATE_TIME_SEC = "updatetimesec";
	
}
