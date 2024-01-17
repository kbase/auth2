package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Optional;

import org.bson.BsonDocument;
import org.junit.Test;

import com.mongodb.MongoWriteException;
import com.mongodb.ServerAddress;
import com.mongodb.WriteError;

import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageDuplicateKeyCheckerTest {
	
	/* Note the duplicate key error message style changed in 3.2 */

	private static final String CLASSNAME =
			"us.kbase.auth2.lib.storage.mongo.MongoStorage$DuplicateKeyExceptionChecker";
	
	private static final int DUPLICATE = 11000;
	
	@Test
	public void dupStatic() throws Exception {
		final MongoWriteException e = new MongoWriteException(new WriteError(DUPLICATE,
				"some message", new BsonDocument()), new ServerAddress());
		
		assertThat("incorrect is duplicate static", runStaticIsDuplicate(e), is(true));
	}
	
	@Test
	public void dupNotStatic() throws Exception {
		final MongoWriteException e = new MongoWriteException(new WriteError(9000,
				"some message", new BsonDocument()), new ServerAddress());
		
		assertThat("incorrect is duplicate static", runStaticIsDuplicate(e), is(false));
	}

	@Test
	public void dupConstructorOldMessageNoKey() throws Exception {
		final String message = "E11000 duplicate key error index: " +
				"test_mongostorage.usersa.$identsa.id_1  ";
		final String expectedCollection = "usersa";
		final String expectedIndex = "identsa.id_1";
		final Optional<Object> expectedKey = Optional.empty();
		checkDuplicateViaConstructor(message, expectedCollection, expectedIndex, expectedKey);
	}
	
	@Test
	public void dupConstructorOldMessageWithKey() throws Exception {
		final String message = "E11000 duplicate key error index: " +
				"test_mongostorage.usersb.$identsb.id_1  " +
				"dup key: { : \"thinger\" }";
		final String expectedCollection = "usersb";
		final String expectedIndex = "identsb.id_1";
		final Optional<Object> expectedKey = Optional.of("thinger");
		checkDuplicateViaConstructor(message, expectedCollection, expectedIndex, expectedKey);
	}
	
	@Test
	public void dupConstructorNewMessageNoKey() throws Exception {
		final String message = "E11000 duplicate key error collection: " +
				"test_mongostorage.usersc index: identsc.id_1 dup key";
		final String expectedCollection = "usersc";
		final String expectedIndex = "identsc.id_1";
		final Optional<Object> expectedKey = Optional.empty();
		checkDuplicateViaConstructor(message, expectedCollection, expectedIndex, expectedKey);
	}
	
	@Test
	public void dupConstructorNewMessageWithKey() throws Exception {
		final String message = "E11000 duplicate key error collection: " +
				"test_mongostorage.usersd index: identsd.id_1 " +
				"dup key: { : \"thinger2\" }";
		final String expectedCollection = "usersd";
		final String expectedIndex = "identsd.id_1";
		final Optional<Object> expectedKey = Optional.of("thinger2");
		checkDuplicateViaConstructor(message, expectedCollection, expectedIndex, expectedKey);
	}

	private void checkDuplicateViaConstructor(
			final String message,
			final String expectedCollection,
			final String expectedIndex,
			final Optional<Object> expectedKey)
			throws Exception {
		final MongoWriteException e = new MongoWriteException(new WriteError(DUPLICATE,
				message, new BsonDocument()), new ServerAddress());
		
		final Object instance = getInstance(e);
		
		final Optional<String> col = runMethod(instance, "getCollection");
		final Optional<String> idx = runMethod(instance, "getIndex");
		final Optional<String> key = runMethod(instance, "getKey");
		assertThat("incorrect isDuplicate", runIsDuplicate(instance), is(true));
		assertThat("incorrect collection", col, is(Optional.of(expectedCollection)));
		assertThat("incorrect index", idx, is(Optional.of(expectedIndex)));
		assertThat("incorrect key", key, is(expectedKey));
	}
	
	@Test
	public void dupNotConstructor() throws Exception {
		final MongoWriteException e = new MongoWriteException(new WriteError(9000,
				"some message", new BsonDocument()), new ServerAddress());
		
		final Object instance = getInstance(e);
		
		final Optional<String> col = runMethod(instance, "getCollection");
		final Optional<String> idx = runMethod(instance, "getIndex");
		final Optional<String> key = runMethod(instance, "getKey");
		assertThat("incorrect isDuplicate", runIsDuplicate(instance), is(false));
		assertThat("incorrect collection", col, is(Optional.empty()));
		assertThat("incorrect index", idx, is(Optional.empty()));
		assertThat("incorrect key", key, is(Optional.empty()));
	}
	
	@Test
	public void unparseable() throws Exception {
		final MongoWriteException e = new MongoWriteException(new WriteError(DUPLICATE,
				"some dup key message", new BsonDocument()), new ServerAddress());
		try {
			getInstance(e);
			fail("expected exception");
		} catch (InvocationTargetException ex) {
			assertThat("some dup key message", ex.getTargetException().getMessage(),
					is("Unable to parse duplicate key error: Write operation error on server 127.0.0.1:27017. " +
							"Write error: WriteError{code=11000, message='some "));
		}
	}

	private boolean runStaticIsDuplicate(final MongoWriteException e) throws Exception {
		final Class<?> inner = Class.forName(CLASSNAME);
		
		final Method isDuplicateStatic = inner.getMethod("isDuplicate", MongoWriteException.class);
		isDuplicateStatic.setAccessible(true);
		
		return (boolean) isDuplicateStatic.invoke(null, e);
	}
	
	private boolean runIsDuplicate(final Object instance) throws Exception {
		final Class<?> inner = Class.forName(CLASSNAME);
		
		final Method m = inner.getDeclaredMethod("isDuplicate");
		m.setAccessible(true);
		return (boolean) m.invoke(instance);
	}

	@SuppressWarnings("unchecked")
	private Optional<String> runMethod(final Object instance, final String string)
			throws Exception {
		final Class<?> inner = Class.forName(CLASSNAME);
		
		final Method m = inner.getDeclaredMethod(string);
		m.setAccessible(true);
		return (Optional<String>) m.invoke(instance);
	}

	private Object getInstance(final MongoWriteException e) throws Exception {
		final Class<?> inner = Class.forName(CLASSNAME);
		
		final Constructor<?> constructor = inner.getConstructor(MongoWriteException.class);
		constructor.setAccessible(true);
		
		return constructor.newInstance(e);
	}
	
}
