package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static us.kbase.test.auth2.lib.storage.mongo.MongoStorageTestCommon.getRecanonicalizationFlag;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

import org.bson.Document;
import org.junit.Test;

import com.github.zafarkhaja.semver.Version;

import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageRecanonicalizationTest extends MongoStorageTester {
	
	private void createUser(final String username, final String displayName, final int remoteID)
			throws Exception {
		MongoStorageTestCommon.createUser(storage, username, displayName, remoteID);
	}
	
	private void trashCanonicalizationData(final String username) {
		MongoStorageTestCommon.trashCanonicalizationData(db, username);
	}
	
	private void setRecanonicalizedFlag(final String username, final String version) {
		MongoStorageTestCommon.setRecanonicalizedFlag(db, username, version);
	}
	
	private void assertNoRecanonicalizationFlag(final String username) {
		MongoStorageTestCommon.assertNoRecanonicalizationFlag(db, username);
	}
	
	private void assertOneRecanonicalizationFlag(final String username, final String version) {
		MongoStorageTestCommon.assertOneRecanonicalizationFlag(db, username, version);
	}
	
	private void assertCorrectRecanonicalization(
			final String username,
			final List<String> canonicalizedName,
			final String version) {
		MongoStorageTestCommon.assertCorrectRecanonicalization(
				db, username, canonicalizedName, version);
	}
	
	@Test
	public void recanonicalizeAllUsers() throws Exception {
		createUser("user1", "ba%r foo^a", 1);
		createUser("user2", "Allen Gins-burg", 2);
		trashCanonicalizationData("user1");
		trashCanonicalizationData("user2");
		final long count = storage.recanonicalizeDisplayNames(Version.valueOf("0.3.1"));
		
		assertCorrectRecanonicalization("user1", Arrays.asList("bar", "fooa"), "0_3_1");
		assertCorrectRecanonicalization("user2", Arrays.asList("allen", "gins", "burg"), "0_3_1");
		assertThat("incorrect count", count, is(2L));
	}
	
	@Test
	public void recanonicalizeSomeUsers() throws Exception {
		createUser("user1", "ba%r foo^a", 1);
		createUser("user2", "Allen Gins-burg", 2);
		setRecanonicalizedFlag("user1", "0_3_2");
		trashCanonicalizationData("user1");
		trashCanonicalizationData("user2");
		final long count = storage.recanonicalizeDisplayNames(Version.valueOf("0.3.2"));
		
		assertCorrectRecanonicalization("user1", Arrays.asList("messed", "up", "user1"), "0_3_2");
		assertCorrectRecanonicalization("user2", Arrays.asList("allen", "gins", "burg"), "0_3_2");
		assertThat("incorrect count", count, is(1L));
	}
	
	
	public Method getInternalRecanonicalizationMethod() throws NoSuchMethodException {
		final Method method = storage.getClass().getDeclaredMethod(
				"updateUserCanonicalDisplayName", String.class, Document.class, int.class);
		method.setAccessible(true);
		return method;
	}
	
	@Test
	public void recanonicalizeInternalsWithImmediateSuccess() throws Exception {
		// Tests race condition where the user changes their name after their record is
		// pulled from the DB and before the recanonicalization changes are applied.
		// In this case, no race condition occurs on the current recursion level
		final Method method = getInternalRecanonicalizationMethod();
		createUser("user1", "bar foo", 1);
		
		for (int attempt = 1; attempt < 6; attempt++) {
			trashCanonicalizationData("user1");
			method.invoke(
					storage,
					getRecanonicalizationFlag("7_6_3"),
					new Document("user", "user1").append("display", "bar foo"),
					attempt
			);
			assertCorrectRecanonicalization("user1", Arrays.asList("bar", "foo"), "7_6_3");
		}
	}
	
	@Test
	public void recanonicalizeInternalsWithRecursionSuccess() throws Exception {
		// Tests race condition where the user changes their name after their record is
		// pulled from the DB and before the recanonicalization changes are applied.
		// In this case, a race condition occurs and the method recurses again.
		final Method method = getInternalRecanonicalizationMethod();
		createUser("user1", "bar foo-baz", 1);
		
		for (int attempt = 1; attempt < 5; attempt++) {
			trashCanonicalizationData("user1");
			method.invoke(
					storage,
					getRecanonicalizationFlag("0_0_1"),
					new Document("user", "user1").append("display", "bar foo"),
					attempt
			);
			assertCorrectRecanonicalization("user1", Arrays.asList("bar", "foo", "baz"), "0_0_1");
		}
	}
	
	@Test
	public void recanonicalizeInternalsWithImmediateFail() throws Exception {
		// Tests race condition where the user changes their name after their record is
		// pulled from the DB and before the recanonicalization changes are applied.
		// In this case, attempts ran out without another recursion.
		final Method method = getInternalRecanonicalizationMethod();
		createUser("user1", "bar foo", 1);
		
		try {
			method.invoke(
					storage,
					getRecanonicalizationFlag("7_6_3"),
					new Document("user", "user1").append("display", "bar foo"),
					6
			);
			fail("expected exception");
		} catch (InvocationTargetException e) {
			final Exception got = (Exception) e.getCause();
			TestCommon.assertExceptionCorrect(got, new AuthStorageException(
					"Failed to recanonicalize user user1 after 5 attempts"));
		}
	}
	
	@Test
	public void recanonicalizeInternalsWithRecursionFail() throws Exception {
		// Tests race condition where the user changes their name after their record is
		// pulled from the DB and before the recanonicalization changes are applied.
		// In this case, attempts will run out on the next recursion
		final Method method = getInternalRecanonicalizationMethod();
		createUser("user1", "bar foo-baz", 1);
		
		try {
			method.invoke(
					storage,
					getRecanonicalizationFlag("0_0_1"),
					new Document("user", "user1").append("display", "bar foo"),
					5
			);
			fail("expected exception");
		} catch (InvocationTargetException e) {
			final Exception got = (Exception) e.getCause();
			TestCommon.assertExceptionCorrect(got, new AuthStorageException(
					"Failed to recanonicalize user user1 after 5 attempts"));
		}
	}
	
	@Test
	public void recanonicalizationFail() throws Exception {
		try {
			storage.recanonicalizeDisplayNames(null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("version"));
		}
	}
	
	@Test
	public void removeRecanonicalizationFlag() throws Exception {
		createUser("user1", "ba%r foo^a", 1);
		createUser("user2", "Allen Gins-burg", 2);
		createUser("user3", "Mr. Creosote", 3);
		setRecanonicalizedFlag("user2", "8_5_1");
		setRecanonicalizedFlag("user3", "8_5_0");
		setRecanonicalizedFlag("user3", "8_5_1");
		final long count = storage.removeDisplayNameRecanonicalizationFlag(
				Version.valueOf("8.5.1"));
		assertNoRecanonicalizationFlag("user1");
		assertNoRecanonicalizationFlag("user2");
		assertOneRecanonicalizationFlag("user3", "8_5_0");
		assertThat("incorrect count", count, is(2L));
	}

	@Test
	public void removeRecanonicalizationFlagFail() throws Exception {
		try {
			storage.removeDisplayNameRecanonicalizationFlag(null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("version"));
		}
	}
}
