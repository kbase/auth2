package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.util.Map;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.CollectingExternalConfig;
import us.kbase.auth2.lib.CollectingExternalConfig.CollectingExternalConfigMapper;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;

public class CollectingExternalConfigTest {

	@Test
	public void configEquals() {
		EqualsVerifier.forClass(CollectingExternalConfig.class).usingGetClass().verify();
	}
	
	@Test
	public void construct() {
		final CollectingExternalConfig cfg = new CollectingExternalConfig(
				ImmutableMap.of("foo", "bar"));
		assertThat("incorrect config", cfg.toMap(), is(ImmutableMap.of("foo", "bar")));
		
		final CollectingExternalConfig cfg2 = new CollectingExternalConfig(null);
		assertThat("incorrect config", cfg2.toMap(), is((Map<String, String>) null));
	}
	
	@Test
	public void map() throws ExternalConfigMappingException {
		final CollectingExternalConfig cfg = new CollectingExternalConfigMapper().fromMap(
				ImmutableMap.of("baz", "bat"));
		assertThat("incorrect config", cfg.toMap(), is(ImmutableMap.of("baz", "bat")));
	}
	
}
