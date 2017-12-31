package us.kbase.auth2.service;

import static us.kbase.auth2.lib.Utils.nonNull;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.LoggerFactory;

import com.mongodb.MongoClient;
import com.mongodb.MongoCredential;
import com.mongodb.MongoException;
import com.mongodb.ServerAddress;
import com.mongodb.client.MongoDatabase;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.config.ExternalConfig;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.lib.identity.IdentityProviderFactory;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.storage.exceptions.StorageInitException;
import us.kbase.auth2.lib.storage.mongo.MongoStorage;
import us.kbase.auth2.service.common.ServiceCommon;
import us.kbase.auth2.service.exceptions.AuthConfigurationException;

public class AuthBuilder {

	//TODO TEST
	//TODO JAVADOC
	
	private MongoClient mc;
	private Authentication auth;
	
	public AuthBuilder(
			final AuthStartupConfig cfg,
			final ExternalConfig defaultExternalConfig)
			throws StorageInitException, AuthConfigurationException {
		nonNull(cfg, "cfg");
		nonNull(defaultExternalConfig, "defaultExternalConfig");
		mc = buildMongo(cfg);
		auth = buildAuth(cfg, mc, defaultExternalConfig);
	}
	
	public AuthBuilder(
			final AuthStartupConfig cfg,
			final ExternalConfig defaultExternalConfig,
			final MongoClient mc)
			throws StorageInitException, AuthConfigurationException {
		nonNull(cfg, "cfg");
		nonNull(defaultExternalConfig, "defaultExternalConfig");
		nonNull(mc, "mc");
		this.mc = mc;
		auth = buildAuth(cfg, mc, defaultExternalConfig);
	}
	
	private MongoClient buildMongo(final AuthStartupConfig c) throws StorageInitException {
		//TODO ZLATER MONGO handle shards & replica sets
		try {
			if (c.getMongoUser().isPresent()) {
				final List<MongoCredential> creds = Arrays.asList(MongoCredential.createCredential(
						c.getMongoUser().get(), c.getMongoDatabase(), c.getMongoPwd().get()));
				// unclear if and when it's safe to clear the password
				return new MongoClient(new ServerAddress(c.getMongoHost()), creds);
			} else {
				return new MongoClient(new ServerAddress(c.getMongoHost()));
			}
		} catch (MongoException e) {
			LoggerFactory.getLogger(getClass()).error(
					"Failed to connect to MongoDB: " + e.getMessage(), e);
			throw new StorageInitException("Failed to connect to MongoDB: " + e.getMessage(), e);
		}
	}
	
	private Authentication buildAuth(
			final AuthStartupConfig c,
			final MongoClient mc,
			final ExternalConfig defaultExternalConfig)
			throws StorageInitException, AuthConfigurationException {
		final MongoDatabase db;
		try {
			db = mc.getDatabase(c.getMongoDatabase());
		} catch (MongoException e) {
			LoggerFactory.getLogger(getClass()).error(
					"Failed to get database from MongoDB: " + e.getMessage(), e);
			throw new StorageInitException("Failed to get database from MongoDB: " +
					e.getMessage(), e);
		}
		//TODO TEST authenticate to db, write actual test with authentication
		final AuthStorage s = new MongoStorage(db);
		
		final Set<IdentityProvider> providers = new HashSet<>();
		for (final IdentityProviderConfig idc: c.getIdentityProviderConfigs()) {
			final IdentityProviderFactory fac = ServiceCommon.loadClassWithInterface(
					idc.getIdentityProviderFactoryClassName(), IdentityProviderFactory.class);
			providers.add(fac.configure(idc));
		}
		return new Authentication(s, providers, defaultExternalConfig, c.isTestModeEnabled());
	}
	
	public MongoClient getMongoClient() {
		return mc;
	}

	public Authentication getAuth() {
		return auth;
	}
	
}
