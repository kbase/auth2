package us.kbase.auth2.service.ui;

public class UIPaths {

	//TODO JAVADOC
	
	/* general strings */
	
	public static final String SEP = "/";
	private static final String COMPLETE = "complete";
	private static final String COMPLETE_PROVIDER = COMPLETE + SEP + "{provider}";
	private static final String CHOICE = "choice";
	private static final String PICK = "pick";
	private static final String CREATE = "create";
	private static final String RESULT = "result";
	private static final String LOGIN = "login";
	private static final String LOCAL = "localaccount";
	private static final String USER = "user";
	private static final String CUSTOM_ROLES = "customroles";
	
	/* Admin endpoint */
	
	public static final String ADMIN_ROOT = "/admin/";

	public static final String ADMIN_LOCALACCOUNT = LOCAL;
	public static final String ADMIN_LOCAL_CREATE = LOCAL + SEP + CREATE;
	public static final String ADMIN_ROOT_LOCAL_CREATE = ADMIN_ROOT + ADMIN_LOCAL_CREATE;

	public static final String ADMIN_ROOT_USER = ADMIN_ROOT + USER;
	public static final String ADMIN_USER_PARAM = USER + SEP + "{user}";
	
	public static final String ADMIN_DISABLE = "disable";
	public static final String ADMIN_USER_DISABLE = ADMIN_USER_PARAM + SEP + ADMIN_DISABLE;

	public static final String ADMIN_ROLES = "roles";
	public static final String ADMIN_USER_ROLES = ADMIN_USER_PARAM + SEP + ADMIN_ROLES;
	
	public static final String ADMIN_CUSTOM_ROLES = CUSTOM_ROLES;
	public static final String ADMIN_USER_CUSTOM_ROLES = ADMIN_USER_PARAM + SEP +
			ADMIN_CUSTOM_ROLES;
	
	public static final String ADMIN_CUSTOM_ROLES_SET = ADMIN_CUSTOM_ROLES + SEP +  "set";
	public static final String ADMIN_ROOT_CUSTOM_ROLES_SET = ADMIN_ROOT + ADMIN_CUSTOM_ROLES_SET;
	
	
	public static final String ADMIN_CONFIG = "config";
	public static final String ADMIN_CONFIG_BASIC = ADMIN_CONFIG + SEP + "basic";
	public static final String ADMIN_CONFIG_PROVIDER = ADMIN_CONFIG + SEP + "provider";
	public static final String ADMIN_CONFIG_TOKEN = ADMIN_CONFIG + SEP + "token";
	public static final String ADMIN_ROOT_CONFIG_BASIC = ADMIN_ROOT + ADMIN_CONFIG_BASIC;
	public static final String ADMIN_ROOT_CONFIG_PROVIDER = ADMIN_ROOT + ADMIN_CONFIG_PROVIDER;
	public static final String ADMIN_ROOT_CONFIG_TOKEN = ADMIN_ROOT + ADMIN_CONFIG_TOKEN;
	
	/* localaccount endpoint */
	
	public static final String LOCAL_ROOT = SEP + LOCAL + SEP;
	
	public static final String LOCAL_LOGIN = LOGIN;
	public static final String LOCAL_ROOT_LOGIN = LOCAL_ROOT + LOGIN;
	public static final String LOCAL_LOGIN_RESULT = LOCAL_LOGIN + SEP + RESULT;
	public static final String LOCAL_ROOT_LOGIN_RESULT = LOCAL_ROOT + LOCAL_LOGIN + SEP + RESULT;
	
	public static final String LOCAL_RESET = "reset";
	public static final String LOCAL_ROOT_RESET = LOCAL_ROOT + LOCAL_RESET;
	public static final String LOCAL_RESET_RESULT = LOCAL_RESET + SEP + RESULT;
	public static final String LOCAL_ROOT_RESET_RESULT = LOCAL_ROOT + LOCAL_RESET_RESULT;
	
	/* login endpoint */
	
	public static final String LOGIN_ROOT = SEP + LOGIN + SEP;
	
	public static final String LOGIN_ROOT_COMPLETE = LOGIN_ROOT + COMPLETE;
	public static final String LOGIN_COMPLETE_PROVIDER = COMPLETE_PROVIDER;
	public static final String LOGIN_CHOICE = CHOICE;
	public static final String LOGIN_ROOT_CHOICE = LOGIN_ROOT + LOGIN_CHOICE;
	public static final String LOGIN_PICK = PICK;
	public static final String LOGIN_ROOT_PICK = LOGIN_ROOT + LOGIN_PICK;
	public static final String LOGIN_CREATE = CREATE;
	public static final String LOGIN_ROOT_CREATE = LOGIN_ROOT + LOGIN_CREATE;
	
	/* link endpoint */
	
	public static final String LINK_ROOT = "/link/";
	
	public static final String LINK_ROOT_COMPLETE = LINK_ROOT + COMPLETE;
	public static final String LINK_COMPLETE_PROVIDER = COMPLETE_PROVIDER;
	public static final String LINK_CHOICE = CHOICE;
	public static final String LINK_ROOT_CHOICE = LINK_ROOT + LINK_CHOICE;
	public static final String LINK_PICK = PICK;
	public static final String LINK_ROOT_PICK = LINK_ROOT + LINK_PICK;
	
	/* logout endpoint */
	public static final String LOGOUT_ROOT = "/logout/";
	
	public static final String LOGOUT_RESULT = RESULT;
	public static final String LOGOUT_ROOT_RESULT = LOGOUT_ROOT + RESULT;
	
	/* me endpoint */
	
	public static final String ME_ROOT = "/me/";
	
	public static final String ME_PARAM_ID = "{id}";
	
	/* tokens endpoint */
	
	public static final String TOKENS_ROOT = "/tokens/";
	
	public static final String TOKENS_CREATE = CREATE;
	public static final String TOKENS_ROOT_CREATE = TOKENS_ROOT + TOKENS_CREATE;
	public static final String TOKENS_ID = "{tokenid}";
	public static final String TOKENS_REVOKE_ALL = "revokeall";
	public static final String TOKENS_ROOT_REVOKE_ALL = TOKENS_ROOT + TOKENS_REVOKE_ALL;
	
	/* customroles endpoint */
	
	public static final String CUSTOM_ROLES_ROOT = SEP + CUSTOM_ROLES + SEP;
}
