package us.kbase.auth2.service;

import java.nio.file.Path;
import java.util.Optional;
import java.util.Set;

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
	String getEnvironmentHeaderName();
	Path getPathToTemplateDirectory();
	boolean isTestModeEnabled();
	Set<String> getEnvironments();
}
