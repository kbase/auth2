package us.kbase.test.auth2.service;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.net.URL;
import java.util.Collections;
import java.util.Map;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.config.ConfigAction;
import us.kbase.auth2.lib.config.ConfigAction.Action;
import us.kbase.auth2.lib.config.ConfigAction.State;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.auth2.service.AuthExternalConfig.AuthExternalConfigMapper;
import us.kbase.auth2.service.AuthExternalConfig.URLSet;
import us.kbase.test.auth2.MapBuilder;
import us.kbase.test.auth2.TestCommon;

public class AuthExternalConfigTest {
	
	@Test
	public void equals() {
		EqualsVerifier.forClass(AuthExternalConfig.class).usingGetClass().verify();
		EqualsVerifier.forClass(URLSet.class).usingGetClass().verify();
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
		assertThat("incorrect link redirect", urlSet.getCompleteLinkRedirect(),
				is(ConfigItem.remove()));
		assertThat("incorrect login redirect", urlSet.getCompleteLoginRedirect(),
				is(ConfigItem.remove()));
		assertThat("incorrect post link redirect", urlSet.getPostLinkRedirect(),
				is(ConfigItem.set(new URL("http://u.com"))));
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
		assertThat("incorrect link redirect", urlSet.getCompleteLinkRedirect(),
				is(ConfigItem.emptyState()));
		assertThat("incorrect login redirect", urlSet.getCompleteLoginRedirect(),
				is(ConfigItem.state(new URL("http://u2.com"))));
		assertThat("incorrect post link redirect", urlSet.getPostLinkRedirect(),
				is(ConfigItem.state(new URL("http://u.com"))));
	}
	
	@Test
	public void constructNoAction() throws Exception {
		final AuthExternalConfig<Action> cfg = new AuthExternalConfig<>(
				new URLSet<>(
						ConfigItem.noAction(),
						ConfigItem.noAction(),
						ConfigItem.noAction(),
						ConfigItem.noAction()),
				ConfigItem.noAction(),
				ConfigItem.noAction());
		
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
		assertThat("incorrect toMap", cfg.toMap(), is(Collections.emptyMap()));
	}
	
	@Test
	public void constructRemove() throws Exception {
		final AuthExternalConfig<Action> cfg = new AuthExternalConfig<>(
				new URLSet<>(
						ConfigItem.remove(),
						ConfigItem.remove(),
						ConfigItem.remove(),
						ConfigItem.remove()),
				ConfigItem.remove(),
				ConfigItem.remove());
		
		assertThat("incorrect trace", cfg.isIncludeStackTraceInResponse(),
				is(ConfigItem.remove()));
		assertThat("incorrect def trace", cfg.isIncludeStackTraceInResponseOrDefault(), is(false));
		assertThat("incorrect headers", cfg.isIgnoreIPHeaders(),
				is(ConfigItem.remove()));
		assertThat("incorrect def headers", cfg.isIgnoreIPHeadersOrDefault(), is(false));
		assertThat("incorrect url set", cfg.getURLSet(), is(new URLSet<>(
				ConfigItem.remove(),
				ConfigItem.remove(),
				ConfigItem.remove(),
				ConfigItem.remove())));
		
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
		final AuthExternalConfig<Action> cfg = new AuthExternalConfig<>(
				new URLSet<>(
						ConfigItem.set(new URL("http://u1.com")),
						ConfigItem.set(new URL("http://u2.com")),
						ConfigItem.set(new URL("http://u3.com")),
						ConfigItem.set(new URL("http://u4.com"))),
				ConfigItem.set(true),
				ConfigItem.set(false));
		
		assertThat("incorrect trace", cfg.isIncludeStackTraceInResponse(),
				is(ConfigItem.set(false)));
		assertThat("incorrect def trace", cfg.isIncludeStackTraceInResponseOrDefault(), is(false));
		assertThat("incorrect headers", cfg.isIgnoreIPHeaders(),
				is(ConfigItem.set(true)));
		assertThat("incorrect def headers", cfg.isIgnoreIPHeadersOrDefault(), is(false));
		assertThat("incorrect url set", cfg.getURLSet(), is(new URLSet<>(
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
		final AuthExternalConfig<State> cfg = new AuthExternalConfig<>(
				new URLSet<>(ConfigItem.emptyState(),
						ConfigItem.state(new URL("http://u2.com")),
						ConfigItem.state(new URL("http://u3.com")),
						ConfigItem.emptyState()),
				ConfigItem.emptyState(),
				ConfigItem.state(true));
		
		assertThat("incorrect trace", cfg.isIncludeStackTraceInResponse(),
				is(ConfigItem.state(true)));
		assertThat("incorrect def trace", cfg.isIncludeStackTraceInResponseOrDefault(), is(true));
		assertThat("incorrect headers", cfg.isIgnoreIPHeaders(), is(ConfigItem.emptyState()));
		assertThat("incorrect def headers", cfg.isIgnoreIPHeadersOrDefault(), is(false));
		assertThat("incorrect url set", cfg.getURLSet(), is(new URLSet<>(
				ConfigItem.emptyState(),
				ConfigItem.state(new URL("http://u2.com")),
				ConfigItem.state(new URL("http://u3.com")),
				ConfigItem.emptyState())));
		
		assertThat("incorrect toMap", cfg.toMap(), is(Collections.emptyMap()));
		
		// swap the boolean states
		final AuthExternalConfig<State> cfg2 = new AuthExternalConfig<>(
				new URLSet<>(
						ConfigItem.emptyState(),
						ConfigItem.state(new URL("http://u2.com")),
						ConfigItem.state(new URL("http://u3.com")),
						ConfigItem.emptyState()),
				ConfigItem.state(true),
				ConfigItem.emptyState());
		
		assertThat("incorrect trace", cfg2.isIncludeStackTraceInResponse(),
				is(ConfigItem.emptyState()));
		assertThat("incorrect def trace", cfg2.isIncludeStackTraceInResponseOrDefault(), is(false));
		assertThat("incorrect headers", cfg2.isIgnoreIPHeaders(), is(ConfigItem.state(true)));
		assertThat("incorrect def headers", cfg2.isIgnoreIPHeadersOrDefault(), is(true));
	}
	
	@Test
	public void constructMixed() throws Exception {
		final AuthExternalConfig<Action> cfg = new AuthExternalConfig<>(
				new URLSet<>(
						ConfigItem.remove(),
						ConfigItem.set(new URL("http://u2.com")),
						ConfigItem.noAction(),
						ConfigItem.set(new URL("http://u4.com"))),
				ConfigItem.remove(),
				ConfigItem.set(false));
		
		assertThat("incorrect trace", cfg.isIncludeStackTraceInResponse(),
				is(ConfigItem.set(false)));
		assertThat("incorrect def trace", cfg.isIncludeStackTraceInResponseOrDefault(), is(false));
		assertThat("incorrect headers", cfg.isIgnoreIPHeaders(), is(ConfigItem.remove()));
		assertThat("incorrect def headers", cfg.isIgnoreIPHeadersOrDefault(), is(false));
		assertThat("incorrect url set", cfg.getURLSet(), is(new URLSet<>(
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
	public void defaultConfig() throws Exception{
		final AuthExternalConfig<Action> cfg = AuthExternalConfig.SET_DEFAULT;
		
		assertThat("incorrect trace", cfg.isIncludeStackTraceInResponse(),
				is(ConfigItem.set(false)));
		assertThat("incorrect def trace", cfg.isIncludeStackTraceInResponseOrDefault(), is(false));
		assertThat("incorrect headers", cfg.isIgnoreIPHeaders(), is(ConfigItem.set(false)));
		assertThat("incorrect def headers", cfg.isIgnoreIPHeadersOrDefault(), is(false));
		assertThat("incorrect url set", cfg.getURLSet(), is(new URLSet<>(
				ConfigItem.remove(),
				ConfigItem.remove(),
				ConfigItem.remove(),
				ConfigItem.remove())));
		
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
	public void constructFail() throws Exception {
		final ConfigItem<URL, Action> setU = ConfigItem.set(new URL("http://f.com"));
		final ConfigItem<URL, State> staU = ConfigItem.state(new URL("http://f.com"));
		final ConfigItem<Boolean, Action> setB = ConfigItem.set(true);
		final ConfigItem<Boolean, State> staB = ConfigItem.state(true);
		
		failConstruct(null, setU, setU, setU, setB, setB,
				new NullPointerException("allowedPostLoginRedirectPrefix"));
		failConstruct(staU, null, staU, staU, staB, staB,
				new NullPointerException("completeLoginRedirect"));
		failConstruct(setU, setU, null, setU, setB, setB,
				new NullPointerException("postLinkRedirect"));
		failConstruct(staU, staU, staU, null, staB, staB,
				new NullPointerException("completeLinkRedirect"));
		failConstruct(setU, setU, setU, setU, null, setB,
				new NullPointerException("ignoreIPHeaders"));
		failConstruct(staU, staU, staU, staU, staB, null,
				new NullPointerException("includeStackTraceInResponse"));
		
		final ConfigItem<URL, Action> setUB = ConfigItem.set(new URL("http://f^.com"));
		final ConfigItem<URL, State> staUB = ConfigItem.state(new URL("http://g^.com"));
		
		failConstruct(setUB, setU, setU, setU, setB, setB,
				new IllegalParameterException("Illegal URL http://f^.com: Illegal character " +
						"in authority at index 7: http://f^.com"));
		failConstruct(staU, staUB, staU, staU, staB, staB,
				new IllegalParameterException("Illegal URL http://g^.com: Illegal character " +
						"in authority at index 7: http://g^.com"));
		failConstruct(setU, setU, setUB, setU, setB, setB,
				new IllegalParameterException("Illegal URL http://f^.com: Illegal character " +
						"in authority at index 7: http://f^.com"));
		failConstruct(staU, staU, staU, staUB, staB, staB,
				new IllegalParameterException("Illegal URL http://g^.com: Illegal character " +
						"in authority at index 7: http://g^.com"));
	}
	
	private <T extends ConfigAction> void failConstruct(
			final ConfigItem<URL, T> allowedPostLoginRedirectPrefix,
			final ConfigItem<URL, T> completeLoginRedirect,
			final ConfigItem<URL, T> postLinkRedirect,
			final ConfigItem<URL, T> completeLinkRedirect,
			final ConfigItem<Boolean, T> ignoreIPHeaders,
			final ConfigItem<Boolean, T> includeStackTraceInResponse,
			final Exception expected) {
		try {
			new AuthExternalConfig<>(
					new URLSet<>(
							allowedPostLoginRedirectPrefix,
							completeLoginRedirect,
							postLinkRedirect,
							completeLinkRedirect),
					ignoreIPHeaders,
					includeStackTraceInResponse);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
		
	}
	
	@Test
	public void fromMapEmpty() throws Exception {
		final AuthExternalConfig<State> cfg = new AuthExternalConfigMapper()
				.fromMap(Collections.emptyMap());
		
		assertThat("incorrect config", cfg, is(new AuthExternalConfig<>(
				new URLSet<>(
						ConfigItem.emptyState(),
						ConfigItem.emptyState(),
						ConfigItem.emptyState(),
						ConfigItem.emptyState()),
				ConfigItem.emptyState(),
				ConfigItem.emptyState())));
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
		
		assertThat("incorrect config", cfg, is(new AuthExternalConfig<>(
				new URLSet<>(
						ConfigItem.emptyState(),
						ConfigItem.emptyState(),
						ConfigItem.emptyState(),
						ConfigItem.emptyState()),
				ConfigItem.emptyState(),
				ConfigItem.emptyState())));
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
		
		assertThat("incorrect config", cfg, is(new AuthExternalConfig<>(
				new URLSet<>(
						ConfigItem.state(new URL("http://u1.com")),
						ConfigItem.state(new URL("http://u2.com")),
						ConfigItem.state(new URL("http://u3.com")),
						ConfigItem.state(new URL("http://u4.com"))),
				ConfigItem.state(true),
				ConfigItem.state(false))));
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
	}
	
	@Test
	public void fromMapFilBadBoolean() {
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
		try {
			new AuthExternalConfigMapper().fromMap(map);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
		
	}
	
}