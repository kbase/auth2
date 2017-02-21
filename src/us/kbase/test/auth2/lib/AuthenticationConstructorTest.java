package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.when;

import java.util.Collections;

import static org.mockito.Mockito.verify;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.AuthConfig;
import us.kbase.auth2.lib.AuthConfigSet;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.CollectingExternalConfig;
import us.kbase.auth2.lib.CollectingExternalConfig.CollectingExternalConfigMapper;
import us.kbase.auth2.lib.ExternalConfig;
import us.kbase.auth2.lib.identity.IdentityProviderSet;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.storage.exceptions.StorageInitException;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.TestExternalConfig.TestExternalConfigMapper;

public class AuthenticationConstructorTest {
	
	@Test
	public void construct() throws Exception {
		/** Doesn't test the default auth config. Tested in the methods that use that config. */
		final AuthStorage storage = mock(AuthStorage.class);
		final AuthConfig ac =  new AuthConfig(AuthConfig.DEFAULT_LOGIN_ALLOWED, null,
				AuthConfig.DEFAULT_TOKEN_LIFETIMES_MS);
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(ac,
						new CollectingExternalConfig(ImmutableMap.of("thing", "foo"))));
		
		final Authentication auth = new Authentication(storage, new IdentityProviderSet(),
				new TestExternalConfig("thingy"));
		verify(storage).updateConfig(new AuthConfigSet<TestExternalConfig>(ac,
				new TestExternalConfig("thingy")), false);
		
		final TestExternalConfig t = auth.getExternalConfig(new TestExternalConfigMapper());
		assertThat("incorrect external config", t, is(new TestExternalConfig("foo")));
		assertThat("incorrect providers", auth.getIdentityProviders(), is(Collections.emptyList()));
	}
	
	@Test
	public void updateConfigFail() throws Exception {
		final AuthStorage storage = mock(AuthStorage.class);
		final AuthConfig ac =  new AuthConfig(AuthConfig.DEFAULT_LOGIN_ALLOWED, null,
				AuthConfig.DEFAULT_TOKEN_LIFETIMES_MS);
		doThrow(new AuthStorageException("foobar")).when(
				storage).updateConfig(new AuthConfigSet<TestExternalConfig>(ac,
						new TestExternalConfig("thingy")), false);
		
		failConstruct(storage, new IdentityProviderSet(), new TestExternalConfig("thingy"),
				new StorageInitException("Failed to set config in storage: foobar"));
	}
	
	private void failConstruct(
			final AuthStorage storage,
			final IdentityProviderSet ids, 
			final ExternalConfig cfg,
			final Exception e) {
		try {
			new Authentication(storage, ids, cfg);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getConfigFail() throws Exception {
		final AuthStorage storage = mock(AuthStorage.class);
		doThrow(new AuthStorageException("whee")).when(storage)
				.getConfig(isA(CollectingExternalConfigMapper.class));
		
		failConstruct(storage, new IdentityProviderSet(), new TestExternalConfig("foo"),
				new StorageInitException("Failed to initialize config manager: whee"));
	}
	
}
