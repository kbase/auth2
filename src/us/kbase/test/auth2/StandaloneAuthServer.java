package us.kbase.test.auth2;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.glassfish.jersey.servlet.ServletContainer;

//import us.kbase.auth2.kbase.KBaseAuthConfig;
import us.kbase.auth2.service.AuthenticationService;

public class StandaloneAuthServer {

	private Integer port = null;
	private Server server;
	
	public StandaloneAuthServer(final String configClass) throws Exception {
		
		AuthenticationService.setConfig(configClass);
	}
	
	// pass 0 for random port
	public void start(final int port) throws Exception {
		server = new Server(port);

		final ServletContextHandler context = new ServletContextHandler();
		context.setContextPath("/");
		server.setHandler(context);

		final ServletHolder jerseyServlet = context.addServlet(ServletContainer.class, "/*");
		jerseyServlet.setInitOrder(1);
		jerseyServlet.setInitParameter("javax.ws.rs.Application",
				"us.kbase.auth2.service.AuthenticationService");
		server.start();
		this.port = ((ServerConnector) server.getConnectors()[0]).getLocalPort();
		server.join();
	}
	
	public void stop() throws Exception {
		server.stop();
		port = null;
	}
	
	public Integer getPort() {
		return port;
	}
	
	public static class ServerThread extends Thread {
		private final StandaloneAuthServer server;
		
		public ServerThread(final StandaloneAuthServer server) {
			this.server = server;
		}
		
		public void run() {
			try {
				server.start(0);
			} catch (Exception e) {
				System.err.println("Can't start server:");
				e.printStackTrace();
			}
		}
	}
	
	public static void main(String[] args) throws Exception {
		// option 1: use a config file to start the server
//		new StandaloneAuthServer(KBaseAuthConfig.class.getName()).start(Integer.valueOf(args[0]));
		
		// option 2: use the test configurator class
		TestConfigurator.setConfig("localhost:27017", "auth_test_db");
		new StandaloneAuthServer(TestConfigurator.class.getName()).start(Integer.valueOf(args[0]));
	}
}
