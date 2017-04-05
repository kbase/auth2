package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.isA;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.util.Collections;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.config.AuthConfig;
import us.kbase.auth2.lib.config.AuthConfig.TokenLifetimeType;
import us.kbase.auth2.lib.config.AuthConfigSet;
import us.kbase.auth2.lib.config.CollectingExternalConfig;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.config.ExternalConfig;
import us.kbase.auth2.lib.config.ExternalConfigMapper;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.config.CollectingExternalConfig.CollectingExternalConfigMapper;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;
import us.kbase.test.auth2.lib.config.FailConfig.FailingMapper;
import us.kbase.test.auth2.lib.config.TestExternalConfig;
import us.kbase.test.auth2.lib.config.TestExternalConfig.TestExternalConfigMapper;

public class AuthenticationConfigTest {
	
	@Test
	public void getCacheTime() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null,
								ImmutableMap.of(TokenLifetimeType.EXT_CACHE, 70000L)),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		assertThat("incorrect cache time", auth.getSuggestedTokenCacheTime(), is(70000L));
	}
	
	@Test
	public void getCacheTimeDefault() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		assertThat("incorrect cache time", auth.getSuggestedTokenCacheTime(), is(300000L));
	}
	
	@Test
	public void getExternalConfig() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(ImmutableMap.of(
								"thing", ConfigItem.state("foo"),
								"nothing", ConfigItem.state("bar")))));
		
		assertThat("incorrect external config", auth.getExternalConfig(
				new TestExternalConfigMapper()),
				is(new TestExternalConfig<>(ConfigItem.state("foo"))));
	}
	
	@Test
	public void getExternalConfigFailNull() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failGetExternalConfig(auth, null, new NullPointerException("mapper"));
	}
	
	@Test
	public void getExternalConfigFailMappingError() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		failGetExternalConfig(auth, new FailingMapper(),
				new ExternalConfigMappingException("always fails"));
	}
	
	private <T extends ExternalConfig> void failGetExternalConfig(
			final Authentication auth,
			final ExternalConfigMapper<T> mapper,
			final Exception e) {
		try {
			auth.getExternalConfig(mapper);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}

}
