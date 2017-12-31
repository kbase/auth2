package us.kbase.auth2.service;

import java.util.Set;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.identity.IdentityProviderConfig;

public interface AuthStartupConfig {

	//TODO JAVADOC
	
	SLF4JAutoLogger getLogger();
	Set<IdentityProviderConfig> getIdentityProviderConfigs();
	String getMongoHost();
	String getMongoDatabase();
	// note both or neither for user & pwd
	Optional<String> getMongoUser();
	Optional<char[]> getMongoPwd();
	String getTokenCookieName();
	boolean isTestModeEnabled();
}
