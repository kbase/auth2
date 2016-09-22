package us.kbase.auth2.service;

import org.slf4j.LoggerFactory;

import com.mongodb.MongoClient;
import com.mongodb.MongoException;
import com.mongodb.client.MongoDatabase;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.lib.identity.IdentityProviderFactory;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.storage.exceptions.StorageInitException;
import us.kbase.auth2.lib.storage.mongo.MongoStorage;
import us.kbase.auth2.service.exceptions.AuthConfigurationException;

public class AuthBuilder {

	//TODO TEST
	//TODO JAVADOC
	
	private MongoClient mc;
	private Authentication auth;
	
	public AuthBuilder(final AuthStartupConfig cfg)
			throws StorageInitException, AuthConfigurationException {
		if (cfg == null) {
			throw new NullPointerException("cfg");
		}
		mc = buildMongo(cfg);
		auth = buildAuth(cfg, mc);
	}
	
	public AuthBuilder(final AuthStartupConfig cfg, final MongoClient mc)
			throws StorageInitException, AuthConfigurationException {
		if (cfg == null) {
			throw new NullPointerException("cfg");
		}
		if (mc == null) {
			throw new NullPointerException("mc");
		}
		this.mc = mc;
		auth = buildAuth(cfg, mc);
	}
	
	private MongoClient buildMongo(final AuthStartupConfig c) {
		//TODO ZLATER handle shards
		try {
			return new MongoClient(c.getMongoHost());
		} catch (MongoException e) {
			LoggerFactory.getLogger(getClass()).error(
					"Failed to connect to MongoDB: " + e.getMessage(), e);
			throw e;
		}
	}
	
	private Authentication buildAuth(
			final AuthStartupConfig c,
			final MongoClient mc)
			throws StorageInitException, AuthConfigurationException {
		final MongoDatabase db;
		try {
			db = mc.getDatabase(c.getMongoDatabase());
		} catch (MongoException e) {
			LoggerFactory.getLogger(getClass()).error(
					"Failed to get database from MongoDB: " + e.getMessage(),
					e);
			throw e;
		}
		//TODO MONGO & TEST authenticate to db with user/pwd
		final AuthStorage s = new MongoStorage(db);
		return new Authentication(s, getIdentityProviders(c));
	}
	
	private IdentityProviderFactory getIdentityProviders(
			final AuthStartupConfig c)
			throws AuthConfigurationException {
		final IdentityProviderFactory fac =
				IdentityProviderFactory.getInstance();
		for (final IdentityProviderConfig idc:
				c.getIdentityProviderConfigs()) {
			try {
				fac.configure(idc);
			} catch (IllegalArgumentException e) {
				throw new AuthConfigurationException(String.format(
						"Error registering identity provider %s: %s",
						idc.getIdentityProviderName(),  e.getMessage()), e);
			}
		}
		return fac;
	}

	public MongoClient getMongoClient() {
		return mc;
	}

	public Authentication getAuth() {
		return auth;
	}
	
}
