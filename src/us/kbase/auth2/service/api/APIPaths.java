package us.kbase.auth2.service.api;

public class APIPaths {

	private static final String API = "/api";
//	private static final String API_V2 = API + "/V2";
	private static final String API_LEGACY = API + "/legacy";
	
	public static final String LEGACY_KBASE = API_LEGACY + "/KBase/Sessions/Login";
	
	public static final String LEGACY_GLOBUS = API_LEGACY + "/globus";
	
	public static final String LEGACY_GLOBUS_USERS = "users/{user}";
	public static final String LEGACY_GLOBUS_TOKEN = "goauth/token";
}
