package us.kbase.auth2.service.ui;

import java.time.Instant;
import java.util.Map;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.glassfish.jersey.server.mvc.Template;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.GitCommit;
import us.kbase.auth2.service.common.Fields;

@Path(UIPaths.ROOT)
public class Root {
	
	//TODO ZLATER ROOT add configurable server name
	//TODO ZLATER ROOT add paths to endpoints
	//TODO ZLATER ROOT add configurable contact email or link
	//TODO ZLATER ROOT move version to file?
	
	private static final String VERSION = "0.1.0-prerelease";
	
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> rootJSON() {
		return root();
	}
	
	@GET
	@Template(name = "/root")
	@Produces(MediaType.TEXT_HTML)
	public Map<String, Object> rootHTML() {
		return root();
	}
	
	private Map<String, Object> root() {
		return ImmutableMap.of(
				Fields.VERSION, VERSION,
				Fields.SERVER_TIME, Instant.now().toEpochMilli(),
				Fields.GIT_HASH, GitCommit.COMMIT);
	}

}
