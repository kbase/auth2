package us.kbase.auth2.service;

import static java.util.Objects.requireNonNull;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.slf4j.LoggerFactory;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.MongoClientSettings;
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
	private AuthStorage storage;
	
	public AuthBuilder(
			final AuthStartupConfig cfg,
			final ExternalConfig defaultExternalConfig)
			throws StorageInitException, AuthConfigurationException {
		requireNonNull(cfg, "cfg");
		requireNonNull(defaultExternalConfig, "defaultExternalConfig");
		mc = buildMongo(cfg);
		final AuthBits ab = buildAuth(cfg, mc, defaultExternalConfig);
		auth = ab.auth;
		storage = ab.storage;
	}
	
	public AuthBuilder(
			final AuthStartupConfig cfg,
			final ExternalConfig defaultExternalConfig,
			final MongoClient mc)
			throws StorageInitException, AuthConfigurationException {
		requireNonNull(cfg, "cfg");
		requireNonNull(defaultExternalConfig, "defaultExternalConfig");
		requireNonNull(mc, "mc");
		this.mc = mc;
		final AuthBits ab = buildAuth(cfg, mc, defaultExternalConfig);
		auth = ab.auth;
		storage = ab.storage;
	}
	
	private MongoClient buildMongo(final AuthStartupConfig c) throws StorageInitException {
		//TODO ZLATER MONGO handle shards & replica sets
		try {
			if (c.getMongoUser().isPresent()) {
				final MongoCredential creds = MongoCredential.createCredential(
						c.getMongoUser().get(), c.getMongoDatabase(), c.getMongoPwd().get());
				// unclear if and when it's safe to clear the password
				return MongoClients.create(
						MongoClientSettings.builder()
								.credential(creds)
								.applyToClusterSettings(builder ->
										builder.hosts(Arrays.asList(
												new ServerAddress(c.getMongoHost()))))
								.build());
			} else {
				return MongoClients.create(
						MongoClientSettings.builder()
								.applyToClusterSettings(builder ->
										builder.hosts(Arrays.asList(
												new ServerAddress(c.getMongoHost()))))
								.build());
			}
		} catch (MongoException e) {
			LoggerFactory.getLogger(getClass()).error(
					"Failed to connect to MongoDB: " + e.getMessage(), e);
			throw new StorageInitException("Failed to connect to MongoDB: " + e.getMessage(), e);
		}
	}
	
	private static class AuthBits {
		private final Authentication auth;
		private final AuthStorage storage;

		public AuthBits(final Authentication auth, final AuthStorage storage) {
			this.auth = auth;
			this.storage = storage;
		}
	}
	
	private AuthBits buildAuth(
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
		return new AuthBits(
				new Authentication(s, providers, defaultExternalConfig, c.isTestModeEnabled()),
				s
		);
	}
	
	/** Get the mongo client used by the storage instance.
	 * @see #getStorage()
	 * @return the mongo client.
	 */
	public MongoClient getMongoClient() {
		return mc;
	}

	/** Get the built authentication instance.
	 * @return the authentication instance.
	 */
	public Authentication getAuth() {
		return auth;
	}
	
	/** Get the storage instance backing the authentication instance.
	 * @see #getAuth()
	 * @return the storage instance.
	 */
	public AuthStorage getStorage() {
		return storage;
	}
	
}
