package us.kbase.test.auth2;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.DefaultServlet;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.glassfish.jersey.servlet.ServletContainer;

import us.kbase.auth2.service.AuthenticationService;
import us.kbase.auth2.service.kbase.KBaseAuthConfig;

public class StartAuthServer {

	public static void main(String[] args) throws Exception {

		
		AuthenticationService.setConfig(new KBaseAuthConfig());
		final Server server = new Server(Integer.valueOf(args[0]));

		final ServletContextHandler context = new ServletContextHandler();
		context.setContextPath("/");
		context.setResourceBase("./webapps/");
		server.setHandler(context);

		final ServletHolder jerseyServlet = context.addServlet(
				ServletContainer.class, "/*");
		jerseyServlet.setInitOrder(1);
		jerseyServlet.setInitParameter("javax.ws.rs.Application",
				"us.kbase.auth2.service.AuthenticationService");
		context.addServlet(
				DefaultServlet.class, "/assets/*");
		server.start();
		server.join();
	}
}
