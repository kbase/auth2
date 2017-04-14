package us.kbase.auth2.service.common;

public class Fields {

	//TODO JAVADOC
	
	/* general */
	
	public static final String ID = "id";
	public static final String DESCRIPTION = "desc";
	public static final String HAS = "has";
	
	/* login */
	
	public static final String STAY_LOGGED_IN = "stayloggedin";
	
	/* roles */
	
	public static final String HAS_ROLES = "hasroles";
	
	/* policy ids */
	
	public static final String POLICY_ID = "policyid";
	public static final String POLICY_IDS = "policyids";
	public static final String AGREED_ON = "agreedon";
	
	/* users */
	
	public static final String USER = "user";
	public static final String LOCAL = "local";
	public static final String DISPLAY = "display";
	public static final String EMAIL = "email";
	public static final String CREATED = "created";
	public static final String LAST_LOGIN = "lastlogin";
	
	/* roles */
	
	public static final String ROLES = "roles";
	public static final String CUSTOM_ROLES = "customroles";
	
	/* search */
	
	public static final String SEARCH_USER = "username";
	public static final String SEARCH_DISPLAY = "displayname";
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
	
	/* tokens */
	
	public static final String TOKEN_NAME = "name";
	public static final String CUSTOM_CONTEXT = "customcontext";
	
	/* urls */
	
	public static final String URL_RESET = "reseturl";
	public static final String URL_REVOKE = "revokeurl";
	public static final String URL_TOKEN = "tokenurl";
	public static final String URL_POLICY = "policyurl";
	public static final String URL_SEARCH = "searchurl";
}
