package us.kbase.auth2.lib;

public class AuthConfigSet {

	//TODO TEST
	//TODO JAVADOC
	
	private AuthConfig cfg;
	private ExternalConfig extcfg;
	
	public AuthConfigSet(final AuthConfig cfg, final ExternalConfig extcfg) {
		if (cfg == null) {
			throw new NullPointerException("cfg");
		}
		if (extcfg == null) {
			throw new NullPointerException("extcfg");
		}
		this.cfg = cfg;
		this.extcfg = extcfg;
	}

	public AuthConfig getCfg() {
		return cfg;
	}

	public ExternalConfig getExtcfg() {
		return extcfg;
	}
}
