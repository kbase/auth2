package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.net.InetAddress;
import java.util.Collections;

import org.junit.Test;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableMap;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.test.auth2.TestCommon;

public class TokenCreationContextTest {
	
	@Test
	public void equals() throws Exception {
		EqualsVerifier.forClass(TokenCreationContext.class).usingGetClass().verify();
	}

	@Test
	public void buildMinimal() throws Exception {
		final TokenCreationContext tcc = TokenCreationContext.getBuilder().build();
		assertThat("incorrect device", tcc.getDevice(), is(Optional.absent()));
		assertThat("incorrect os", tcc.getOS(), is(Optional.absent()));
		assertThat("incorrect os ver", tcc.getOSVersion(), is(Optional.absent()));
		assertThat("incorrect agent", tcc.getAgent(), is(Optional.absent()));
		assertThat("incorrect agent ver", tcc.getAgentVersion(), is(Optional.absent()));
		assertThat("incorrect ip", tcc.getIpAddress(), is(Optional.absent()));
		assertThat("incorrect custom", tcc.getCustomContext(), is(Collections.emptyMap()));
	}
	
	@Test
	public void buildMaximal() throws Exception {
		final TokenCreationContext tcc = TokenCreationContext.getBuilder()
				.withNullableDevice("d")
				.withNullableAgent("a", "av")
				.withNullableOS("o", "ov")
				.withIpAddress(InetAddress.getByName("1.1.1.1"))
				.withCustomContext("a", "1")
				.withCustomContext("b", "2").build();
		assertThat("incorrect device", tcc.getDevice(), is(Optional.of("d")));
		assertThat("incorrect os", tcc.getOS(), is(Optional.of("o")));
		assertThat("incorrect os ver", tcc.getOSVersion(), is(Optional.of("ov")));
		assertThat("incorrect agent", tcc.getAgent(), is(Optional.of("a")));
		assertThat("incorrect agent ver", tcc.getAgentVersion(), is(Optional.of("av")));
		assertThat("incorrect ip", tcc.getIpAddress(),
				is(Optional.of(InetAddress.getByName("1.1.1.1"))));
		assertThat("incorrect custom", tcc.getCustomContext(), is(ImmutableMap.of(
				"a", "1", "b", "2")));
	}
	
	@Test
	public void buildWithNulls() throws Exception {
		final TokenCreationContext tcc = TokenCreationContext.getBuilder()
				.withNullableDevice(null)
				.withNullableAgent(null, "av")
				.withNullableOS(null, "ov")
				.withNullableIpAddress(null)
				.build();
		assertThat("incorrect device", tcc.getDevice(), is(Optional.absent()));
		assertThat("incorrect os", tcc.getOS(), is(Optional.absent()));
		assertThat("incorrect os ver", tcc.getOSVersion(), is(Optional.absent()));
		assertThat("incorrect agent", tcc.getAgent(), is(Optional.absent()));
		assertThat("incorrect agent ver", tcc.getAgentVersion(), is(Optional.absent()));
		assertThat("incorrect ip", tcc.getIpAddress(), is(Optional.absent()));
		assertThat("incorrect custom", tcc.getCustomContext(), is(Collections.emptyMap()));
	}
	
	@Test
	public void buildWithEmptyStrings() throws Exception {
		final TokenCreationContext tcc = TokenCreationContext.getBuilder()
				.withNullableDevice("   \t  ")
				.withNullableAgent("   \t  ", "av")
				.withNullableOS("   \t  ", "ov")
				.withNullableIpAddress(InetAddress.getByName("2.2.2.2"))
				.build();
		assertThat("incorrect device", tcc.getDevice(), is(Optional.absent()));
		assertThat("incorrect os", tcc.getOS(), is(Optional.absent()));
		assertThat("incorrect os ver", tcc.getOSVersion(), is(Optional.absent()));
		assertThat("incorrect agent", tcc.getAgent(), is(Optional.absent()));
		assertThat("incorrect agent ver", tcc.getAgentVersion(), is(Optional.absent()));
		assertThat("incorrect ip", tcc.getIpAddress(),
				is(Optional.of(InetAddress.getByName("2.2.2.2"))));
		assertThat("incorrect custom", tcc.getCustomContext(), is(Collections.emptyMap()));
	}
	
	@Test
	public void buildWithVersionNulls() throws Exception {
		final TokenCreationContext tcc = TokenCreationContext.getBuilder()
				.withNullableAgent("a", null)
				.withNullableOS("o", null)
				.build();
		assertThat("incorrect device", tcc.getDevice(), is(Optional.absent()));
		assertThat("incorrect os", tcc.getOS(), is(Optional.of("o")));
		assertThat("incorrect os ver", tcc.getOSVersion(), is(Optional.absent()));
		assertThat("incorrect agent", tcc.getAgent(), is(Optional.of("a")));
		assertThat("incorrect agent ver", tcc.getAgentVersion(), is(Optional.absent()));
		assertThat("incorrect ip", tcc.getIpAddress(), is(Optional.absent()));
		assertThat("incorrect custom", tcc.getCustomContext(), is(Collections.emptyMap()));
	}
	
	@Test
	public void buildWithVersionEmptyStrings() throws Exception {
		final TokenCreationContext tcc = TokenCreationContext.getBuilder()
				.withNullableAgent("a", "   \t  ")
				.withNullableOS("o", "   \t  ")
				.build();
		assertThat("incorrect device", tcc.getDevice(), is(Optional.absent()));
		assertThat("incorrect os", tcc.getOS(), is(Optional.of("o")));
		assertThat("incorrect os ver", tcc.getOSVersion(), is(Optional.absent()));
		assertThat("incorrect agent", tcc.getAgent(), is(Optional.of("a")));
		assertThat("incorrect agent ver", tcc.getAgentVersion(), is(Optional.absent()));
		assertThat("incorrect ip", tcc.getIpAddress(), is(Optional.absent()));
		assertThat("incorrect custom", tcc.getCustomContext(), is(Collections.emptyMap()));
	}
	
	@Test
	public void contextIsImmutable() throws Exception {
		final TokenCreationContext tcc = TokenCreationContext.getBuilder()
				.withCustomContext("k", "v").build();
		try {
			tcc.getCustomContext().put("v", "k");
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new UnsupportedOperationException());
		}
	}
	
	@Test
	public void buildFailNullsAndEmpties() throws Exception {
		final InetAddress ia = InetAddress.getByName("1.1.1.1");
		final String k = "k";
		final String v = "v";
		failBuild(null, k, v, new NullPointerException("ipAddress"));
		failBuild(ia, null, v, new MissingParameterException("key"));
		failBuild(ia, "    \t   ", v, new MissingParameterException("key"));
		failBuild(ia, k, null, new MissingParameterException("value"));
		failBuild(ia, k, "   \n  ", new MissingParameterException("value"));
	}
	
	@Test
	public void buildFailLongStrings() throws Exception {
		final InetAddress ia = InetAddress.getByName("1.1.1.1");
		failBuild(ia, TestCommon.LONG101.substring(0, 21), "v",
				new IllegalParameterException("key size greater than limit 20"));
		failBuild(ia, "k", TestCommon.LONG101.substring(0, 81),
				new IllegalParameterException("value size greater than limit 80"));
	}
	
	@Test
	public void buildFailTooManyKeys() throws Exception {
		final TokenCreationContext.Builder b = TokenCreationContext.getBuilder();
		for (int i = 0; i < 100; i++) {
			b.withCustomContext("k" + i, "v");
		}
		try {
			b.withCustomContext("final", "value");
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new IllegalParameterException(
					"Exceeded max size of custom context: 100 items"));
		}
	}
	
	private void failBuild(
			final InetAddress ia,
			final String key,
			final String value,
			final Exception e) {
		try {
			TokenCreationContext.getBuilder().withIpAddress(ia).withCustomContext(key, value);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
}
