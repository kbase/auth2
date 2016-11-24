package us.kbase.auth2.service.ui;

import java.net.URI;
import java.net.URISyntaxException;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

@Path("/thing/redirecttest")
public class RedirectTest {
	
	@GET
	public String rt() {
		return "at root\n";
	}
	
	@GET
	@Path("/relative")
	public Response rel(@Context UriInfo uriinfo) {
		System.out.println(uriinfo.getAbsolutePath());
		System.out.println(uriinfo.getBaseUri());
		System.out.println(uriinfo.getRequestUri());
		return Response.temporaryRedirect(toURI("..")).build();
	}
	
	@GET
	@Path("/abs")
	public Response abs() {
		return Response.temporaryRedirect(toURI("/thing/redirecttest")).build();
	}
	
	@GET
	@Path("/relabs")
	public Response relabs() {
		return Response.temporaryRedirect(toURI("/thing/redirecttest/abs/.."))
				.build();
	}
	
	private URI toURI(final String uri) {
		try {
			return new URI(uri);
		} catch (URISyntaxException e) {
			throw new RuntimeException("This should be impossible", e);
		}
	}

}
