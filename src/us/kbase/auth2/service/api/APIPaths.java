package us.kbase.auth2.service.api;

public class APIPaths {

	private static final String SEP = "/";
	private static final String TOKEN = "token";
	private static final String USERS = "users";
	
	private static final String API = "/api";
	private static final String API_V2 = API + "/V2";
	private static final String API_LEGACY = API + "/legacy";
	
	public static final String LEGACY_KBASE = API_LEGACY + "/KBase/Sessions/Login";
	
	public static final String LEGACY_GLOBUS = API_LEGACY + "/globus";
	
	public static final String LEGACY_GLOBUS_USERS = USERS + SEP + "{user}";
	public static final String LEGACY_GLOBUS_TOKEN = "goauth" + SEP + TOKEN;
	
	public static final String API_V2_TOKEN = API_V2 + SEP + TOKEN;
	
	public static final String API_V2_USERS = API_V2 + SEP + USERS;
	public static final String USERS_SEARCH = "search/{prefix}";
	
	public static final String API_V2_ME = API_V2 + SEP + "me";
}
