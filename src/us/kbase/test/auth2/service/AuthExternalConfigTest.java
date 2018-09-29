package us.kbase.test.auth2.service;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.net.URL;
import java.util.Collections;

import org.junit.Test;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.config.ConfigAction;
import us.kbase.auth2.lib.config.ConfigAction.Action;
import us.kbase.auth2.lib.config.ConfigAction.State;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.test.auth2.MapBuilder;
import us.kbase.test.auth2.TestCommon;

public class AuthExternalConfigTest {
	
	@Test
	public void equals() {
		EqualsVerifier.forClass(AuthExternalConfig.class).usingGetClass().verify();
	}
	
	@Test
	public void constructNoAction() throws Exception {
		final AuthExternalConfig<Action> cfg = new AuthExternalConfig<>(
				ConfigItem.noAction(),
				ConfigItem.noAction(),
				ConfigItem.noAction(),
				ConfigItem.noAction(),
				ConfigItem.noAction(),
				ConfigItem.noAction());
		
		assertThat("incorrect trace", cfg.isIncludeStackTraceInResponse(),
				is(ConfigItem.noAction()));
		assertThat("incorrect def trace", cfg.isIncludeStackTraceInResponseOrDefault(), is(false));
		assertThat("incorrect headers", cfg.isIgnoreIPHeaders(),
				is(ConfigItem.noAction()));
		assertThat("incorrect def headers", cfg.isIgnoreIPHeadersOrDefault(), is(false));
		assertThat("incorrect log prefix", cfg.getAllowedLoginRedirectPrefix(),
				is(ConfigItem.noAction()));
		assertThat("incorrect link redirect", cfg.getCompleteLinkRedirect(),
				is(ConfigItem.noAction()));
		assertThat("incorrect login redirect", cfg.getCompleteLoginRedirect(),
				is(ConfigItem.noAction()));
		assertThat("incorrect post link redirect", cfg.getPostLinkRedirect(),
				is(ConfigItem.noAction()));
		
		assertThat("incorrect toMap", cfg.toMap(), is(Collections.emptyMap()));
	}
	
	@Test
	public void constructRemove() throws Exception {
		final AuthExternalConfig<Action> cfg = new AuthExternalConfig<>(
				ConfigItem.remove(),
				ConfigItem.remove(),
				ConfigItem.remove(),
				ConfigItem.remove(),
				ConfigItem.remove(),
				ConfigItem.remove());
		
		assertThat("incorrect trace", cfg.isIncludeStackTraceInResponse(),
				is(ConfigItem.remove()));
		assertThat("incorrect def trace", cfg.isIncludeStackTraceInResponseOrDefault(), is(false));
		assertThat("incorrect headers", cfg.isIgnoreIPHeaders(),
				is(ConfigItem.remove()));
		assertThat("incorrect def headers", cfg.isIgnoreIPHeadersOrDefault(), is(false));
		assertThat("incorrect log prefix", cfg.getAllowedLoginRedirectPrefix(),
				is(ConfigItem.remove()));
		assertThat("incorrect link redirect", cfg.getCompleteLinkRedirect(),
				is(ConfigItem.remove()));
		assertThat("incorrect login redirect", cfg.getCompleteLoginRedirect(),
				is(ConfigItem.remove()));
		assertThat("incorrect post link redirect", cfg.getPostLinkRedirect(),
				is(ConfigItem.remove()));
		
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
				ConfigItem.set(new URL("http://u1.com")),
				ConfigItem.set(new URL("http://u2.com")),
				ConfigItem.set(new URL("http://u3.com")),
				ConfigItem.set(new URL("http://u4.com")),
				ConfigItem.set(true),
				ConfigItem.set(false));
		
		assertThat("incorrect trace", cfg.isIncludeStackTraceInResponse(),
				is(ConfigItem.set(false)));
		assertThat("incorrect def trace", cfg.isIncludeStackTraceInResponseOrDefault(), is(false));
		assertThat("incorrect headers", cfg.isIgnoreIPHeaders(),
				is(ConfigItem.set(true)));
		assertThat("incorrect def headers", cfg.isIgnoreIPHeadersOrDefault(), is(false));
		assertThat("incorrect log prefix", cfg.getAllowedLoginRedirectPrefix(),
				is(ConfigItem.set(new URL("http://u1.com"))));
		assertThat("incorrect link redirect", cfg.getCompleteLinkRedirect(),
				is(ConfigItem.set(new URL("http://u4.com"))));
		assertThat("incorrect login redirect", cfg.getCompleteLoginRedirect(),
				is(ConfigItem.set(new URL("http://u2.com"))));
		assertThat("incorrect post link redirect", cfg.getPostLinkRedirect(),
				is(ConfigItem.set(new URL("http://u3.com"))));
		
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
				ConfigItem.emptyState(),
				ConfigItem.state(new URL("http://u2.com")),
				ConfigItem.state(new URL("http://u3.com")),
				ConfigItem.emptyState(),
				ConfigItem.emptyState(),
				ConfigItem.state(true));
		
		assertThat("incorrect trace", cfg.isIncludeStackTraceInResponse(),
				is(ConfigItem.state(true)));
		assertThat("incorrect def trace", cfg.isIncludeStackTraceInResponseOrDefault(), is(true));
		assertThat("incorrect headers", cfg.isIgnoreIPHeaders(), is(ConfigItem.emptyState()));
		assertThat("incorrect def headers", cfg.isIgnoreIPHeadersOrDefault(), is(false));
		assertThat("incorrect log prefix", cfg.getAllowedLoginRedirectPrefix(),
				is(ConfigItem.emptyState()));
		assertThat("incorrect link redirect", cfg.getCompleteLinkRedirect(),
				is(ConfigItem.emptyState()));
		assertThat("incorrect login redirect", cfg.getCompleteLoginRedirect(),
				is(ConfigItem.state(new URL("http://u2.com"))));
		assertThat("incorrect post link redirect", cfg.getPostLinkRedirect(),
				is(ConfigItem.state(new URL("http://u3.com"))));
		
		assertThat("incorrect toMap", cfg.toMap(), is(Collections.emptyMap()));
		
		// swap the boolean states
		final AuthExternalConfig<State> cfg2 = new AuthExternalConfig<>(
				ConfigItem.emptyState(),
				ConfigItem.state(new URL("http://u2.com")),
				ConfigItem.state(new URL("http://u3.com")),
				ConfigItem.emptyState(),
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
				ConfigItem.remove(),
				ConfigItem.set(new URL("http://u2.com")),
				ConfigItem.noAction(),
				ConfigItem.set(new URL("http://u4.com")),
				ConfigItem.remove(),
				ConfigItem.set(false));
		
		assertThat("incorrect trace", cfg.isIncludeStackTraceInResponse(),
				is(ConfigItem.set(false)));
		assertThat("incorrect def trace", cfg.isIncludeStackTraceInResponseOrDefault(), is(false));
		assertThat("incorrect headers", cfg.isIgnoreIPHeaders(), is(ConfigItem.remove()));
		assertThat("incorrect def headers", cfg.isIgnoreIPHeadersOrDefault(), is(false));
		assertThat("incorrect log prefix", cfg.getAllowedLoginRedirectPrefix(),
				is(ConfigItem.remove()));
		assertThat("incorrect link redirect", cfg.getCompleteLinkRedirect(),
				is(ConfigItem.set(new URL("http://u4.com"))));
		assertThat("incorrect login redirect", cfg.getCompleteLoginRedirect(),
				is(ConfigItem.set(new URL("http://u2.com"))));
		assertThat("incorrect post link redirect", cfg.getPostLinkRedirect(),
				is(ConfigItem.noAction()));
		
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
	public void defaultConfig() {
		final AuthExternalConfig<Action> cfg = AuthExternalConfig.SET_DEFAULT;
		
		assertThat("incorrect trace", cfg.isIncludeStackTraceInResponse(),
				is(ConfigItem.set(false)));
		assertThat("incorrect def trace", cfg.isIncludeStackTraceInResponseOrDefault(), is(false));
		assertThat("incorrect headers", cfg.isIgnoreIPHeaders(), is(ConfigItem.set(false)));
		assertThat("incorrect def headers", cfg.isIgnoreIPHeadersOrDefault(), is(false));
		assertThat("incorrect log prefix", cfg.getAllowedLoginRedirectPrefix(),
				is(ConfigItem.remove()));
		assertThat("incorrect link redirect", cfg.getCompleteLinkRedirect(),
				is(ConfigItem.remove()));
		assertThat("incorrect login redirect", cfg.getCompleteLoginRedirect(),
				is(ConfigItem.remove()));
		assertThat("incorrect post link redirect", cfg.getPostLinkRedirect(),
				is(ConfigItem.remove()));
		
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
					allowedPostLoginRedirectPrefix,
					completeLoginRedirect,
					postLinkRedirect,
					completeLinkRedirect,
					ignoreIPHeaders,
					includeStackTraceInResponse);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
		
	}
}
