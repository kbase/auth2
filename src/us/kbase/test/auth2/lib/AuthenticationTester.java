package us.kbase.test.auth2.lib;

import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.AuthConfig;
import us.kbase.auth2.lib.AuthConfigSet;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.CollectingExternalConfig;
import us.kbase.auth2.lib.CollectingExternalConfig.CollectingExternalConfigMapper;
import us.kbase.auth2.lib.identity.IdentityProviderSet;
import us.kbase.auth2.lib.storage.AuthStorage;

public class AuthenticationTester {
	
	public static class TestAuth {
		final AuthStorage storageMock;
		final Authentication auth;
		
		public TestAuth(AuthStorage storageMock, Authentication auth) {
			this.storageMock = storageMock;
			this.auth = auth;
		}
	}
	
	public static TestAuth initTestAuth() throws Exception {
		final AuthStorage storage = mock(AuthStorage.class);
		final AuthConfig ac =  new AuthConfig(AuthConfig.DEFAULT_LOGIN_ALLOWED, null,
				AuthConfig.DEFAULT_TOKEN_LIFETIMES_MS);
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(ac,
						new CollectingExternalConfig(ImmutableMap.of("thing", "foo"))));
		
		return new TestAuth(storage, new Authentication(
				storage, new IdentityProviderSet(), new TestExternalConfig("foo")));
	}
	
}
