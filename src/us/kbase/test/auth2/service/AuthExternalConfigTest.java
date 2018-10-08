package us.kbase.test.auth2.service;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static us.kbase.test.auth2.TestCommon.set;

import java.net.URL;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.config.ConfigAction;
import us.kbase.auth2.lib.config.ConfigAction.Action;
import us.kbase.auth2.lib.config.ConfigAction.State;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchEnvironmentException;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.auth2.service.AuthExternalConfig.AuthExternalConfigMapper;
import us.kbase.auth2.service.AuthExternalConfig.URLSet;
import us.kbase.test.auth2.MapBuilder;
import us.kbase.test.auth2.TestCommon;

public class AuthExternalConfigTest {
	
	@Test
	public void equals() {
		EqualsVerifier.forClass(AuthExternalConfig.class).usingGetClass().verify();
		EqualsVerifier.forClass(AuthExternalConfigMapper.class).usingGetClass().verify();
		EqualsVerifier.forClass(URLSet.class).usingGetClass().verify();
	}
	
	@Test
	public void URLSetNoAction() {
		final URLSet<Action> urlSet = URLSet.noAction();
		
		assertThat("incorrect log prefix", urlSet.getAllowedLoginRedirectPrefix(),
				is(ConfigItem.noAction()));
		assertThat("incorrect login redirect", urlSet.getCompleteLoginRedirect(),
				is(ConfigItem.noAction()));
		assertThat("incorrect post link redirect", urlSet.getPostLinkRedirect(),
				is(ConfigItem.noAction()));
		assertThat("incorrect link redirect", urlSet.getCompleteLinkRedirect(),
				is(ConfigItem.noAction()));
	}
	
	@Test
	public void URLSetRemove() {
		final URLSet<Action> urlSet = URLSet.remove();
		
		assertThat("incorrect log prefix", urlSet.getAllowedLoginRedirectPrefix(),
				is(ConfigItem.remove()));
		assertThat("incorrect login redirect", urlSet.getCompleteLoginRedirect(),
				is(ConfigItem.remove()));
		assertThat("incorrect post link redirect", urlSet.getPostLinkRedirect(),
				is(ConfigItem.remove()));
		assertThat("incorrect link redirect", urlSet.getCompleteLinkRedirect(),
				is(ConfigItem.remove()));
	}
	
	@Test
	public void URLSetEmptyState() {
		final URLSet<State> urlSet = URLSet.emptyState();
		
		assertThat("incorrect log prefix", urlSet.getAllowedLoginRedirectPrefix(),
				is(ConfigItem.emptyState()));
		assertThat("incorrect login redirect", urlSet.getCompleteLoginRedirect(),
				is(ConfigItem.emptyState()));
		assertThat("incorrect post link redirect", urlSet.getPostLinkRedirect(),
				is(ConfigItem.emptyState()));
		assertThat("incorrect link redirect", urlSet.getCompleteLinkRedirect(),
				is(ConfigItem.emptyState()));
	}
	
	@Test
	public void constructURLSetAction() throws Exception {
		final URLSet<Action> urlSet = new URLSet<>(
				ConfigItem.noAction(),
				ConfigItem.remove(),
				ConfigItem.set(new URL("http://u.com")),
				ConfigItem.remove());
		
		assertThat("incorrect log prefix", urlSet.getAllowedLoginRedirectPrefix(),
				is(ConfigItem.noAction()));
		assertThat("incorrect login redirect", urlSet.getCompleteLoginRedirect(),
				is(ConfigItem.remove()));
		assertThat("incorrect post link redirect", urlSet.getPostLinkRedirect(),
				is(ConfigItem.set(new URL("http://u.com"))));
		assertThat("incorrect link redirect", urlSet.getCompleteLinkRedirect(),
				is(ConfigItem.remove()));
	}
	
	@Test
	public void constructURLSetState() throws Exception {
		final URLSet<State> urlSet = new URLSet<>(
				ConfigItem.emptyState(),
				ConfigItem.state(new URL("http://u2.com")),
				ConfigItem.state(new URL("http://u.com")),
				ConfigItem.emptyState());
		
		assertThat("incorrect log prefix", urlSet.getAllowedLoginRedirectPrefix(),
				is(ConfigItem.emptyState()));
		assertThat("incorrect login redirect", urlSet.getCompleteLoginRedirect(),
				is(ConfigItem.state(new URL("http://u2.com"))));
		assertThat("incorrect post link redirect", urlSet.getPostLinkRedirect(),
				is(ConfigItem.state(new URL("http://u.com"))));
		assertThat("incorrect link redirect", urlSet.getCompleteLinkRedirect(),
				is(ConfigItem.emptyState()));
	}
	
	@Test
	public void constructURLSetFail() throws Exception {
		final ConfigItem<URL, Action> setU = ConfigItem.set(new URL("http://f.com"));
		final ConfigItem<URL, State> staU = ConfigItem.state(new URL("http://f.com"));
		
		failConstruct(null, setU, setU, setU,
				new NullPointerException("allowedPostLoginRedirectPrefix"));
		failConstruct(staU, null, staU, staU,
				new NullPointerException("completeLoginRedirect"));
		failConstruct(setU, setU, null, setU,
				new NullPointerException("postLinkRedirect"));
		failConstruct(staU, staU, staU, null,
				new NullPointerException("completeLinkRedirect"));
		
		final ConfigItem<URL, Action> setUB = ConfigItem.set(new URL("http://f^.com"));
		final ConfigItem<URL, State> staUB = ConfigItem.state(new URL("http://g^.com"));
		
		failConstruct(setUB, setU, setU, setU,
				new IllegalParameterException("Illegal URL http://f^.com: Illegal character " +
						"in authority at index 7: http://f^.com"));
		failConstruct(staU, staUB, staU, staU,
				new IllegalParameterException("Illegal URL http://g^.com: Illegal character " +
						"in authority at index 7: http://g^.com"));
		failConstruct(setU, setU, setUB, setU,
				new IllegalParameterException("Illegal URL http://f^.com: Illegal character " +
						"in authority at index 7: http://f^.com"));
		failConstruct(staU, staU, staU, staUB,
				new IllegalParameterException("Illegal URL http://g^.com: Illegal character " +
						"in authority at index 7: http://g^.com"));
	}
	
	private <T extends ConfigAction> void failConstruct(
			final ConfigItem<URL, T> allowedPostLoginRedirectPrefix,
			final ConfigItem<URL, T> completeLoginRedirect,
			final ConfigItem<URL, T> postLinkRedirect,
			final ConfigItem<URL, T> completeLinkRedirect,
			final Exception expected) {
		try {
			new URLSet<>(
					allowedPostLoginRedirectPrefix,
					completeLoginRedirect,
					postLinkRedirect,
					completeLinkRedirect);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
		
	}
	
	@Test
	public void constructNoAction() throws Exception {
		final AuthExternalConfig<Action> cfg = AuthExternalConfig.getBuilder(
				new URLSet<>(
						ConfigItem.noAction(),
						ConfigItem.noAction(),
						ConfigItem.noAction(),
						ConfigItem.noAction()),
				ConfigItem.noAction(),
				ConfigItem.noAction())
				.build();
		
		assertThat("incorrect trace", cfg.isIncludeStackTraceInResponse(),
				is(ConfigItem.noAction()));
		assertThat("incorrect def trace", cfg.isIncludeStackTraceInResponseOrDefault(), is(false));
		assertThat("incorrect headers", cfg.isIgnoreIPHeaders(),
				is(ConfigItem.noAction()));
		assertThat("incorrect def headers", cfg.isIgnoreIPHeadersOrDefault(), is(false));
		assertThat("incorrect url set", cfg.getURLSet(), is(new URLSet<>(
				ConfigItem.noAction(),
				ConfigItem.noAction(),
				ConfigItem.noAction(),
				ConfigItem.noAction())));
		assertThat("incorrect url set", cfg.getURLSetOrDefault(null), is(URLSet.noAction()));
		assertThat("incorrect envs", cfg.getEnvironments(), is(set()));
		assertThat("incorrect toMap", cfg.toMap(), is(Collections.emptyMap()));
	}
	
	@Test
	public void constructRemove() throws Exception {
		final AuthExternalConfig<Action> cfg = AuthExternalConfig.getBuilder(
				new URLSet<>(
						ConfigItem.remove(),
						ConfigItem.remove(),
						ConfigItem.remove(),
						ConfigItem.remove()),
				ConfigItem.remove(),
				ConfigItem.remove())
				.build();
		
		assertThat("incorrect trace", cfg.isIncludeStackTraceInResponse(),
				is(ConfigItem.remove()));
		assertThat("incorrect def trace", cfg.isIncludeStackTraceInResponseOrDefault(), is(false));
		assertThat("incorrect headers", cfg.isIgnoreIPHeaders(),
				is(ConfigItem.remove()));
		assertThat("incorrect def headers", cfg.isIgnoreIPHeadersOrDefault(), is(false));
		assertThat("incorrect envs", cfg.getEnvironments(), is(set()));
		assertThat("incorrect url set", cfg.getURLSet(), is(new URLSet<>(
				ConfigItem.remove(),
				ConfigItem.remove(),
				ConfigItem.remove(),
				ConfigItem.remove())));
		assertThat("incorrect url set", cfg.getURLSetOrDefault(null), is(URLSet.remove()));
		
		assertThat("incorrect toMap", cfg.toMap(),
				is(MapBuilder.<String, ConfigItem<String, Action>>newHashMap()
						.with("allowedPostLoginRedirectPrefix", ConfigItem.remove())
						.with("completeLoginRedirect", ConfigItem.remove())
						.with("postLinkRedirect", ConfigItem.remove())
						.with("completeLinkRedirect", ConfigItem.remove())
						.with("ignoreIPHeaders", ConfigItem.remove())
						.with("includeStackTraceInResponse", ConfigItem.remove())
						.build()));
	}
	
	@Test
	public void constructSet() throws Exception {
		final AuthExternalConfig<Action> cfg = AuthExternalConfig.getBuilder(
				new URLSet<>(
						ConfigItem.set(new URL("http://u1.com")),
						ConfigItem.set(new URL("http://u2.com")),
						ConfigItem.set(new URL("http://u3.com")),
						ConfigItem.set(new URL("http://u4.com"))),
				ConfigItem.set(true),
				ConfigItem.set(false))
				.build();
		
		assertThat("incorrect trace", cfg.isIncludeStackTraceInResponse(),
				is(ConfigItem.set(false)));
		assertThat("incorrect def trace", cfg.isIncludeStackTraceInResponseOrDefault(), is(false));
		assertThat("incorrect headers", cfg.isIgnoreIPHeaders(),
				is(ConfigItem.set(true)));
		assertThat("incorrect def headers", cfg.isIgnoreIPHeadersOrDefault(), is(false));
		assertThat("incorrect envs", cfg.getEnvironments(), is(set()));
		assertThat("incorrect url set", cfg.getURLSet(), is(new URLSet<>(
				ConfigItem.set(new URL("http://u1.com")),
				ConfigItem.set(new URL("http://u2.com")),
				ConfigItem.set(new URL("http://u3.com")),
				ConfigItem.set(new URL("http://u4.com")))));
		assertThat("incorrect url set", cfg.getURLSetOrDefault(null), is(new URLSet<>(
				ConfigItem.set(new URL("http://u1.com")),
				ConfigItem.set(new URL("http://u2.com")),
				ConfigItem.set(new URL("http://u3.com")),
				ConfigItem.set(new URL("http://u4.com")))));
		
		assertThat("incorrect toMap", cfg.toMap(),
				is(MapBuilder.<String, ConfigItem<String, Action>>newHashMap()
						.with("allowedPostLoginRedirectPrefix", ConfigItem.set("http://u1.com"))
						.with("completeLoginRedirect", ConfigItem.set("http://u2.com"))
						.with("postLinkRedirect", ConfigItem.set("http://u3.com"))
						.with("completeLinkRedirect", ConfigItem.set("http://u4.com"))
						.with("ignoreIPHeaders", ConfigItem.set("true"))
						.with("includeStackTraceInResponse", ConfigItem.set("false"))
						.build()));
	}
	
	@Test
	public void constructState() throws Exception {
		final AuthExternalConfig<State> cfg = AuthExternalConfig.getBuilder(
				new URLSet<>(ConfigItem.emptyState(),
						ConfigItem.state(new URL("http://u2.com")),
						ConfigItem.state(new URL("http://u3.com")),
						ConfigItem.emptyState()),
				ConfigItem.emptyState(),
				ConfigItem.state(true))
				.build();
		
		assertThat("incorrect trace", cfg.isIncludeStackTraceInResponse(),
				is(ConfigItem.state(true)));
		assertThat("incorrect def trace", cfg.isIncludeStackTraceInResponseOrDefault(), is(true));
		assertThat("incorrect headers", cfg.isIgnoreIPHeaders(), is(ConfigItem.emptyState()));
		assertThat("incorrect def headers", cfg.isIgnoreIPHeadersOrDefault(), is(false));
		assertThat("incorrect envs", cfg.getEnvironments(), is(set()));
		assertThat("incorrect url set", cfg.getURLSet(), is(new URLSet<>(
				ConfigItem.emptyState(),
				ConfigItem.state(new URL("http://u2.com")),
				ConfigItem.state(new URL("http://u3.com")),
				ConfigItem.emptyState())));
		assertThat("incorrect url set", cfg.getURLSetOrDefault(null), is(new URLSet<>(
				ConfigItem.emptyState(),
				ConfigItem.state(new URL("http://u2.com")),
				ConfigItem.state(new URL("http://u3.com")),
				ConfigItem.emptyState())));
		
		assertThat("incorrect toMap", cfg.toMap(), is(Collections.emptyMap()));
		
		// swap the boolean states
		final AuthExternalConfig<State> cfg2 = AuthExternalConfig.getBuilder(
				new URLSet<>(
						ConfigItem.emptyState(),
						ConfigItem.state(new URL("http://u2.com")),
						ConfigItem.state(new URL("http://u3.com")),
						ConfigItem.emptyState()),
				ConfigItem.state(true),
				ConfigItem.emptyState())
				.build();
		
		assertThat("incorrect trace", cfg2.isIncludeStackTraceInResponse(),
				is(ConfigItem.emptyState()));
		assertThat("incorrect def trace", cfg2.isIncludeStackTraceInResponseOrDefault(), is(false));
		assertThat("incorrect headers", cfg2.isIgnoreIPHeaders(), is(ConfigItem.state(true)));
		assertThat("incorrect def headers", cfg2.isIgnoreIPHeadersOrDefault(), is(true));
	}
	
	@Test
	public void constructMixed() throws Exception {
		final AuthExternalConfig<Action> cfg = AuthExternalConfig.getBuilder(
				new URLSet<>(
						ConfigItem.remove(),
						ConfigItem.set(new URL("http://u2.com")),
						ConfigItem.noAction(),
						ConfigItem.set(new URL("http://u4.com"))),
				ConfigItem.remove(),
				ConfigItem.set(false))
				.build();
		
		assertThat("incorrect trace", cfg.isIncludeStackTraceInResponse(),
				is(ConfigItem.set(false)));
		assertThat("incorrect def trace", cfg.isIncludeStackTraceInResponseOrDefault(), is(false));
		assertThat("incorrect headers", cfg.isIgnoreIPHeaders(), is(ConfigItem.remove()));
		assertThat("incorrect def headers", cfg.isIgnoreIPHeadersOrDefault(), is(false));
		assertThat("incorrect envs", cfg.getEnvironments(), is(set()));
		assertThat("incorrect url set", cfg.getURLSet(), is(new URLSet<>(
				ConfigItem.remove(),
				ConfigItem.set(new URL("http://u2.com")),
				ConfigItem.noAction(),
				ConfigItem.set(new URL("http://u4.com")))));
		assertThat("incorrect url set", cfg.getURLSetOrDefault(null), is(new URLSet<>(
				ConfigItem.remove(),
				ConfigItem.set(new URL("http://u2.com")),
				ConfigItem.noAction(),
				ConfigItem.set(new URL("http://u4.com")))));
		
		assertThat("incorrect toMap", cfg.toMap(),
				is(MapBuilder.<String, ConfigItem<String, Action>>newHashMap()
						.with("allowedPostLoginRedirectPrefix", ConfigItem.remove())
						.with("completeLoginRedirect", ConfigItem.set("http://u2.com"))
						.with("completeLinkRedirect", ConfigItem.set("http://u4.com"))
						.with("ignoreIPHeaders", ConfigItem.remove())
						.with("includeStackTraceInResponse", ConfigItem.set("false"))
						.build()));
	}
	
	@Test
	public void constructWithEnvironments() throws Exception {
		final AuthExternalConfig<Action> cfg = AuthExternalConfig.getBuilder(
				new URLSet<>(
						ConfigItem.remove(),
						ConfigItem.set(new URL("http://u2.com")),
						ConfigItem.noAction(),
						ConfigItem.set(new URL("http://u4.com"))),
				ConfigItem.remove(),
				ConfigItem.set(false))
				.withEnvironment("e1", new URLSet<>(
						ConfigItem.noAction(),
						ConfigItem.set(new URL("http://u6.com")),
						ConfigItem.remove(),
						ConfigItem.set(new URL("http://u8.com"))))
				.withEnvironment("e2", new URLSet<>(
						ConfigItem.set(new URL("http://u10.com")),
						ConfigItem.remove(),
						ConfigItem.set(new URL("http://u16.com")),
						ConfigItem.noAction()))
				.build();
		
		assertThat("incorrect trace", cfg.isIncludeStackTraceInResponse(),
				is(ConfigItem.set(false)));
		assertThat("incorrect def trace", cfg.isIncludeStackTraceInResponseOrDefault(), is(false));
		assertThat("incorrect headers", cfg.isIgnoreIPHeaders(), is(ConfigItem.remove()));
		assertThat("incorrect def headers", cfg.isIgnoreIPHeadersOrDefault(), is(false));
		assertThat("incorrect envs", cfg.getEnvironments(), is(set("e1", "e2")));
		assertThat("incorrect url set", cfg.getURLSet(), is(new URLSet<>(
				ConfigItem.remove(),
				ConfigItem.set(new URL("http://u2.com")),
				ConfigItem.noAction(),
				ConfigItem.set(new URL("http://u4.com")))));
		assertThat("incorrect url set", cfg.getURLSet("e1"), is(new URLSet<>(
				ConfigItem.noAction(),
				ConfigItem.set(new URL("http://u6.com")),
				ConfigItem.remove(),
				ConfigItem.set(new URL("http://u8.com")))));
		assertThat("incorrect url set", cfg.getURLSet("e2"), is(new URLSet<>(
				ConfigItem.set(new URL("http://u10.com")),
				ConfigItem.remove(),
				ConfigItem.set(new URL("http://u16.com")),
				ConfigItem.noAction())));
		assertThat("incorrect url set", cfg.getURLSetOrDefault(null), is(new URLSet<>(
				ConfigItem.remove(),
				ConfigItem.set(new URL("http://u2.com")),
				ConfigItem.noAction(),
				ConfigItem.set(new URL("http://u4.com")))));
		assertThat("incorrect url set", cfg.getURLSetOrDefault("e1"), is(new URLSet<>(
				ConfigItem.noAction(),
				ConfigItem.set(new URL("http://u6.com")),
				ConfigItem.remove(),
				ConfigItem.set(new URL("http://u8.com")))));
		assertThat("incorrect url set", cfg.getURLSetOrDefault("e2"), is(new URLSet<>(
				ConfigItem.set(new URL("http://u10.com")),
				ConfigItem.remove(),
				ConfigItem.set(new URL("http://u16.com")),
				ConfigItem.noAction())));
		
		assertThat("incorrect toMap", cfg.toMap(),
				is(MapBuilder.<String, ConfigItem<String, Action>>newHashMap()
						.with("allowedPostLoginRedirectPrefix", ConfigItem.remove())
						.with("completeLoginRedirect", ConfigItem.set("http://u2.com"))
						.with("completeLinkRedirect", ConfigItem.set("http://u4.com"))
						
						.with("e1-completeLoginRedirect", ConfigItem.set("http://u6.com"))
						.with("e1-postLinkRedirect", ConfigItem.remove())
						.with("e1-completeLinkRedirect", ConfigItem.set("http://u8.com"))
						
						.with("e2-allowedPostLoginRedirectPrefix",
								ConfigItem.set("http://u10.com"))
						.with("e2-completeLoginRedirect", ConfigItem.remove())
						.with("e2-postLinkRedirect", ConfigItem.set("http://u16.com"))

						.with("ignoreIPHeaders", ConfigItem.remove())
						.with("includeStackTraceInResponse", ConfigItem.set("false"))
						.build()));
	}
	
	@Test
	public void defaultConfig() throws Exception {
		final AuthExternalConfig<Action> cfg = AuthExternalConfig.getDefaultConfig(set());
		
		assertThat("incorrect trace", cfg.isIncludeStackTraceInResponse(),
				is(ConfigItem.set(false)));
		assertThat("incorrect def trace", cfg.isIncludeStackTraceInResponseOrDefault(), is(false));
		assertThat("incorrect headers", cfg.isIgnoreIPHeaders(), is(ConfigItem.set(false)));
		assertThat("incorrect def headers", cfg.isIgnoreIPHeadersOrDefault(), is(false));
		assertThat("incorrect envs", cfg.getEnvironments(), is(set()));
		assertThat("incorrect url set", cfg.getURLSet(), is(URLSet.remove()));
		assertThat("incorrect url set", cfg.getURLSetOrDefault(null), is(URLSet.remove()));
		
		assertThat("incorrect toMap", cfg.toMap(),
				is(MapBuilder.<String, ConfigItem<String, Action>>newHashMap()
						.with("allowedPostLoginRedirectPrefix", ConfigItem.remove())
						.with("completeLoginRedirect", ConfigItem.remove())
						.with("postLinkRedirect", ConfigItem.remove())
						.with("completeLinkRedirect", ConfigItem.remove())
						.with("ignoreIPHeaders", ConfigItem.set("false"))
						.with("includeStackTraceInResponse", ConfigItem.set("false"))
						.build()));
	}
	
	@Test
	public void defaultConfigWithEnvironments() throws Exception {
		final AuthExternalConfig<Action> cfg = AuthExternalConfig.getDefaultConfig(
				set("env1", "env2"));
		
		assertThat("incorrect trace", cfg.isIncludeStackTraceInResponse(),
				is(ConfigItem.set(false)));
		assertThat("incorrect def trace", cfg.isIncludeStackTraceInResponseOrDefault(), is(false));
		assertThat("incorrect headers", cfg.isIgnoreIPHeaders(), is(ConfigItem.set(false)));
		assertThat("incorrect def headers", cfg.isIgnoreIPHeadersOrDefault(), is(false));
		assertThat("incorrect envs", cfg.getEnvironments(), is(set("env1", "env2")));
		final URLSet<Action> remove = new URLSet<>(
				ConfigItem.remove(),
				ConfigItem.remove(),
				ConfigItem.remove(),
				ConfigItem.remove());
		assertThat("incorrect url set", cfg.getURLSet(), is(remove));
		assertThat("incorrect url set", cfg.getURLSetOrDefault(null), is(URLSet.remove()));
		assertThat("incorrect url set", cfg.getURLSet("env1"), is(remove));
		assertThat("incorrect url set", cfg.getURLSet("env2"), is(remove));
		assertThat("incorrect url set", cfg.getURLSetOrDefault("env1"), is(URLSet.remove()));
		assertThat("incorrect url set", cfg.getURLSetOrDefault("env2"), is(URLSet.remove()));
		
		assertThat("incorrect toMap", cfg.toMap(),
				is(MapBuilder.<String, ConfigItem<String, Action>>newHashMap()
						.with("allowedPostLoginRedirectPrefix", ConfigItem.remove())
						.with("completeLoginRedirect", ConfigItem.remove())
						.with("postLinkRedirect", ConfigItem.remove())
						.with("completeLinkRedirect", ConfigItem.remove())
						.with("env1-allowedPostLoginRedirectPrefix", ConfigItem.remove())
						.with("env1-completeLoginRedirect", ConfigItem.remove())
						.with("env1-postLinkRedirect", ConfigItem.remove())
						.with("env1-completeLinkRedirect", ConfigItem.remove())
						.with("env2-allowedPostLoginRedirectPrefix", ConfigItem.remove())
						.with("env2-completeLoginRedirect", ConfigItem.remove())
						.with("env2-postLinkRedirect", ConfigItem.remove())
						.with("env2-completeLinkRedirect", ConfigItem.remove())
						.with("ignoreIPHeaders", ConfigItem.set("false"))
						.with("includeStackTraceInResponse", ConfigItem.set("false"))
						.build()));
	}
	
	@Test
	public void startBuildFail() throws Exception {
		final ConfigItem<URL, Action> setU = ConfigItem.set(new URL("http://f.com"));
		final ConfigItem<URL, State> staU = ConfigItem.state(new URL("http://f.com"));
		final ConfigItem<Boolean, Action> setB = ConfigItem.set(true);
		final ConfigItem<Boolean, State> staB = ConfigItem.state(true);
		
		final URLSet<Action> setURL = new URLSet<>(setU, setU, setU, setU);
		final URLSet<State> staURL = new URLSet<>(staU, staU, staU, staU);
		
		failStartBuild(null, setB, setB,
				new NullPointerException("urlSet"));
		failStartBuild(setURL, null, setB,
				new NullPointerException("ignoreIPHeaders"));
		failStartBuild(staURL, staB, null,
				new NullPointerException("includeStackTraceInResponse"));
	}
	
	private <T extends ConfigAction> void failStartBuild(
			final URLSet<T> urlSet,
			final ConfigItem<Boolean, T> ignoreIPHeaders,
			final ConfigItem<Boolean, T> includeStackTraceInResponse,
			final Exception expected) {
		try {
			AuthExternalConfig.getBuilder(urlSet, ignoreIPHeaders, includeStackTraceInResponse);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void withEnvironmentFail() throws Exception {
		failWithEnvironment(null, URLSet.remove(), new IllegalArgumentException(
				"environment cannot be null or empty"));
		failWithEnvironment("   \t   ", URLSet.remove(), new IllegalArgumentException(
				"environment cannot be null or empty"));
		failWithEnvironment("e", null, new NullPointerException("urlSet"));
	}
	
	private void failWithEnvironment(
			final String env,
			final URLSet<Action> urlSet,
			final Exception expected) {
		try {
			AuthExternalConfig.getBuilder(
					URLSet.remove(), ConfigItem.remove(), ConfigItem.remove())
					.withEnvironment(env, urlSet);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void getURLSetFail() throws Exception {
		final AuthExternalConfig<Action> cfg = AuthExternalConfig.getBuilder(
				URLSet.remove(), ConfigItem.remove(), ConfigItem.remove())
				.withEnvironment("e", URLSet.noAction())
				.build();

		failGetURLSet(cfg, null, new NoSuchEnvironmentException(null));
		failGetURLSet(cfg, "   \t  ", new NoSuchEnvironmentException("   \t  "));
		failGetURLSet(cfg, "f", new NoSuchEnvironmentException("f"));
		
		failGetURLSetOrDefault(cfg, "   \t  ", new NoSuchEnvironmentException("   \t  "));
		failGetURLSetOrDefault(cfg, "f", new NoSuchEnvironmentException("f"));
	}
	
	private void failGetURLSet(
			final AuthExternalConfig<Action> cfg,
			final String environment,
			final Exception expected) {
		try {
			cfg.getURLSet(environment);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	private void failGetURLSetOrDefault(
			final AuthExternalConfig<Action> cfg,
			final String environment,
			final Exception expected) {
		try {
			cfg.getURLSetOrDefault(environment);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void getDefaultFail() {
		failDefault(null, new NullPointerException("environments"));
		failDefault(set("e", null), new NullPointerException("null item in environments"));
	}
	
	private void failDefault(final Set<String> envs, final Exception expected) {
		try {
			AuthExternalConfig.getDefaultConfig(envs);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void fromMapEmpty() throws Exception {
		final AuthExternalConfig<State> cfg = new AuthExternalConfigMapper()
				.fromMap(Collections.emptyMap());
		
		assertThat("incorrect config", cfg, is(AuthExternalConfig.getBuilder(
				new URLSet<>(
						ConfigItem.emptyState(),
						ConfigItem.emptyState(),
						ConfigItem.emptyState(),
						ConfigItem.emptyState()),
				ConfigItem.emptyState(),
				ConfigItem.emptyState())
				.build()));
	}
	
	@Test
	public void fromMapEmptyWithEnvironments() throws Exception {
		final AuthExternalConfig<State> cfg = new AuthExternalConfigMapper(set("e1", "e2"))
				.fromMap(Collections.emptyMap());
		
		assertThat("incorrect config", cfg, is(AuthExternalConfig.getBuilder(
				new URLSet<>(
						ConfigItem.emptyState(),
						ConfigItem.emptyState(),
						ConfigItem.emptyState(),
						ConfigItem.emptyState()),
				ConfigItem.emptyState(),
				ConfigItem.emptyState())
				.withEnvironment("e1", URLSet.emptyState())
				.withEnvironment("e2", URLSet.emptyState())
				.build()));
	}
	
	@Test
	public void fromMapMinimal() throws Exception {
		final AuthExternalConfig<State> cfg = new AuthExternalConfigMapper()
				.fromMap(MapBuilder.<String, ConfigItem<String, State>>newHashMap()
						.with("allowedPostLoginRedirectPrefix", ConfigItem.emptyState())
						.with("completeLoginRedirect", ConfigItem.emptyState())
						.with("postLinkRedirect", ConfigItem.emptyState())
						.with("completeLinkRedirect", ConfigItem.emptyState())
						.with("ignoreIPHeaders", ConfigItem.emptyState())
						.with("includeStackTraceInResponse", ConfigItem.emptyState())
						.build());
		
		assertThat("incorrect config", cfg, is(AuthExternalConfig.getBuilder(
				new URLSet<>(
						ConfigItem.emptyState(),
						ConfigItem.emptyState(),
						ConfigItem.emptyState(),
						ConfigItem.emptyState()),
				ConfigItem.emptyState(),
				ConfigItem.emptyState())
				.build()));
	}
	
	@Test
	public void fromMapMinimalWithEnvironments() throws Exception {
		final AuthExternalConfig<State> cfg = new AuthExternalConfigMapper(set("e1", "e3"))
				.fromMap(MapBuilder.<String, ConfigItem<String, State>>newHashMap()
						.with("allowedPostLoginRedirectPrefix", ConfigItem.emptyState())
						.with("completeLoginRedirect", ConfigItem.emptyState())
						.with("postLinkRedirect", ConfigItem.emptyState())
						.with("completeLinkRedirect", ConfigItem.emptyState())
						
						.with("e1-allowedPostLoginRedirectPrefix", ConfigItem.emptyState())
						.with("e1-completeLoginRedirect", ConfigItem.emptyState())
						.with("e1-postLinkRedirect", ConfigItem.emptyState())
						.with("e1-completeLinkRedirect", ConfigItem.emptyState())
						
						.with("e3-allowedPostLoginRedirectPrefix", ConfigItem.emptyState())
						.with("e3-completeLoginRedirect", ConfigItem.emptyState())
						.with("e3-postLinkRedirect", ConfigItem.emptyState())
						.with("e3-completeLinkRedirect", ConfigItem.emptyState())
						
						.with("ignoreIPHeaders", ConfigItem.emptyState())
						.with("includeStackTraceInResponse", ConfigItem.emptyState())
						.build());
		
		assertThat("incorrect config", cfg, is(AuthExternalConfig.getBuilder(
				new URLSet<>(
						ConfigItem.emptyState(),
						ConfigItem.emptyState(),
						ConfigItem.emptyState(),
						ConfigItem.emptyState()),
				ConfigItem.emptyState(),
				ConfigItem.emptyState())
				.withEnvironment("e1", URLSet.emptyState())
				.withEnvironment("e3", URLSet.emptyState())
				.build()));
	}
	
	@Test
	public void fromMapMaximal() throws Exception {
		final AuthExternalConfig<State> cfg = new AuthExternalConfigMapper()
				.fromMap(MapBuilder.<String, ConfigItem<String, State>>newHashMap()
						.with("allowedPostLoginRedirectPrefix", ConfigItem.state("http://u1.com"))
						.with("completeLoginRedirect", ConfigItem.state("http://u2.com"))
						.with("postLinkRedirect", ConfigItem.state("http://u3.com"))
						.with("completeLinkRedirect", ConfigItem.state("http://u4.com"))
						.with("ignoreIPHeaders", ConfigItem.state("true"))
						.with("includeStackTraceInResponse", ConfigItem.state("false"))
						.build());
		
		assertThat("incorrect config", cfg, is(AuthExternalConfig.getBuilder(
				new URLSet<>(
						ConfigItem.state(new URL("http://u1.com")),
						ConfigItem.state(new URL("http://u2.com")),
						ConfigItem.state(new URL("http://u3.com")),
						ConfigItem.state(new URL("http://u4.com"))),
				ConfigItem.state(true),
				ConfigItem.state(false))
				.build()));
	}
	
	@Test
	public void fromMapMaximalWithEnvironments() throws Exception {
		final AuthExternalConfig<State> cfg = new AuthExternalConfigMapper(set("e2", "e4"))
				.fromMap(MapBuilder.<String, ConfigItem<String, State>>newHashMap()
						.with("allowedPostLoginRedirectPrefix", ConfigItem.state("http://u1.com"))
						.with("completeLoginRedirect", ConfigItem.state("http://u2.com"))
						.with("postLinkRedirect", ConfigItem.state("http://u3.com"))
						.with("completeLinkRedirect", ConfigItem.state("http://u4.com"))
						
						.with("e2-allowedPostLoginRedirectPrefix",
								ConfigItem.state("http://u5.com"))
						.with("e2-completeLoginRedirect", ConfigItem.state("http://u6.com"))
						.with("e2-postLinkRedirect", ConfigItem.state("http://u7.com"))
						.with("e2-completeLinkRedirect", ConfigItem.state("http://u8.com"))
						
						.with("e4-allowedPostLoginRedirectPrefix",
								ConfigItem.state("http://u9.com"))
						.with("e4-completeLoginRedirect", ConfigItem.state("http://u10.com"))
						.with("e4-postLinkRedirect", ConfigItem.state("http://u11.com"))
						.with("e4-completeLinkRedirect", ConfigItem.state("http://u12.com"))
						
						.with("ignoreIPHeaders", ConfigItem.state("true"))
						.with("includeStackTraceInResponse", ConfigItem.state("false"))
						.build());
		
		assertThat("incorrect config", cfg, is(AuthExternalConfig.getBuilder(
				new URLSet<>(
						ConfigItem.state(new URL("http://u1.com")),
						ConfigItem.state(new URL("http://u2.com")),
						ConfigItem.state(new URL("http://u3.com")),
						ConfigItem.state(new URL("http://u4.com"))),
				ConfigItem.state(true),
				ConfigItem.state(false))
				.withEnvironment("e2", new URLSet<>(
						ConfigItem.state(new URL("http://u5.com")),
						ConfigItem.state(new URL("http://u6.com")),
						ConfigItem.state(new URL("http://u7.com")),
						ConfigItem.state(new URL("http://u8.com"))))
				.withEnvironment("e4", new URLSet<>(
						ConfigItem.state(new URL("http://u9.com")),
						ConfigItem.state(new URL("http://u10.com")),
						ConfigItem.state(new URL("http://u11.com")),
						ConfigItem.state(new URL("http://u12.com"))))
				.build()));
	}
	
	@Test
	public void constructMapperFail() {
		failConstructMapper(null, new NullPointerException("environments"));
		failConstructMapper(set("e", null), new NullPointerException("null item in environments"));
	}
	
	private void failConstructMapper(final Set<String> envs, final Exception expected) {
		try {
			new AuthExternalConfigMapper(envs);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void fromMapFailBadURL() {
		failFromMap(ImmutableMap.of("allowedPostLoginRedirectPrefix",
				ConfigItem.state("htp://u.com")), new ExternalConfigMappingException(
						"Bad URL for parameter allowedPostLoginRedirectPrefix: " +
						"unknown protocol: htp"));
		failFromMap(ImmutableMap.of("completeLoginRedirect",
				ConfigItem.state("htp://u.com")), new ExternalConfigMappingException(
						"Bad URL for parameter completeLoginRedirect: unknown protocol: htp"));
		failFromMap(ImmutableMap.of("postLinkRedirect",
				ConfigItem.state("htp://u.com")), new ExternalConfigMappingException(
						"Bad URL for parameter postLinkRedirect: unknown protocol: htp"));
		failFromMap(ImmutableMap.of("completeLinkRedirect",
				ConfigItem.state("htp://u.com")), new ExternalConfigMappingException(
						"Bad URL for parameter completeLinkRedirect: unknown protocol: htp"));
		
		failFromMap(set("e1"), ImmutableMap.of("e1-allowedPostLoginRedirectPrefix",
				ConfigItem.state("htp://u.com")), new ExternalConfigMappingException(
						"Bad URL for parameter e1-allowedPostLoginRedirectPrefix: " +
						"unknown protocol: htp"));
		failFromMap(set("e1"), ImmutableMap.of("e1-completeLoginRedirect",
				ConfigItem.state("htp://u.com")), new ExternalConfigMappingException(
						"Bad URL for parameter e1-completeLoginRedirect: unknown protocol: htp"));
		failFromMap(set("e1"), ImmutableMap.of("e1-postLinkRedirect",
				ConfigItem.state("htp://u.com")), new ExternalConfigMappingException(
						"Bad URL for parameter e1-postLinkRedirect: unknown protocol: htp"));
		failFromMap(set("e1"), ImmutableMap.of("e1-completeLinkRedirect",
				ConfigItem.state("htp://u.com")), new ExternalConfigMappingException(
						"Bad URL for parameter e1-completeLinkRedirect: unknown protocol: htp"));
	}
	
	@Test
	public void fromMapFailBadURI() {
		failFromMap(ImmutableMap.of("allowedPostLoginRedirectPrefix",
				ConfigItem.state("http://u^u.com")), new ExternalConfigMappingException(
						"Bad URL for parameter allowedPostLoginRedirectPrefix: Illegal " +
						"character in authority at index 7: http://u^u.com"));
		failFromMap(ImmutableMap.of("completeLoginRedirect",
				ConfigItem.state("http://u^u.com")), new ExternalConfigMappingException(
						"Bad URL for parameter completeLoginRedirect: Illegal " +
						"character in authority at index 7: http://u^u.com"));
		failFromMap(ImmutableMap.of("postLinkRedirect",
				ConfigItem.state("http://u^u.com")), new ExternalConfigMappingException(
						"Bad URL for parameter postLinkRedirect: Illegal " +
						"character in authority at index 7: http://u^u.com"));
		failFromMap(ImmutableMap.of("completeLinkRedirect",
				ConfigItem.state("http://u^u.com")), new ExternalConfigMappingException(
						"Bad URL for parameter completeLinkRedirect: Illegal " +
						"character in authority at index 7: http://u^u.com"));
		
		failFromMap(set("e1"), ImmutableMap.of("e1-allowedPostLoginRedirectPrefix",
				ConfigItem.state("http://u^u.com")), new ExternalConfigMappingException(
						"Bad URL for parameter e1-allowedPostLoginRedirectPrefix: Illegal " +
						"character in authority at index 7: http://u^u.com"));
		failFromMap(set("e1"), ImmutableMap.of("e1-completeLoginRedirect",
				ConfigItem.state("http://u^u.com")), new ExternalConfigMappingException(
						"Bad URL for parameter e1-completeLoginRedirect: Illegal " +
						"character in authority at index 7: http://u^u.com"));
		failFromMap(set("e1"), ImmutableMap.of("e1-postLinkRedirect",
				ConfigItem.state("http://u^u.com")), new ExternalConfigMappingException(
						"Bad URL for parameter e1-postLinkRedirect: Illegal " +
						"character in authority at index 7: http://u^u.com"));
		failFromMap(set("e1"), ImmutableMap.of("e1-completeLinkRedirect",
				ConfigItem.state("http://u^u.com")), new ExternalConfigMappingException(
						"Bad URL for parameter e1-completeLinkRedirect: Illegal " +
						"character in authority at index 7: http://u^u.com"));
	}
	
	@Test
	public void fromMapFailBadBoolean() {
		failFromMap(ImmutableMap.of("ignoreIPHeaders", ConfigItem.state("foo")),
				new ExternalConfigMappingException(
						"Expected value of true or false for parameter ignoreIPHeaders"));
		failFromMap(ImmutableMap.of("includeStackTraceInResponse", ConfigItem.state("foo")),
				new ExternalConfigMappingException(
						"Expected value of true or false for parameter " +
						"includeStackTraceInResponse"));
	}
	
	private void failFromMap(
			final Map<String, ConfigItem<String, State>> map,
			final Exception expected) {
		failFromMap(null, map, expected);
	}
	
	private void failFromMap(
			final Set<String> envs,
			final Map<String, ConfigItem<String, State>> map,
			final Exception expected) {
		try {
			if (envs == null) {
				new AuthExternalConfigMapper().fromMap(map);
			} else {
				new AuthExternalConfigMapper(envs).fromMap(map);
			}
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
		
	}
	
}
