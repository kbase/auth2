package us.kbase.auth2.service;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class AppEventListener implements ServletContextListener {
	
	@Override
	public void contextInitialized(final ServletContextEvent arg0) {
		// may want to make this configurable with the -D switch later
		AuthenticationService.setConfig("us.kbase.auth2.kbase.KBaseAuthConfig");
	}
	
	@Override
	public void contextDestroyed(final ServletContextEvent arg0) {
		//TODO TEST manually test this shuts down the mongo connection.
		//this seems very wrong, but for now I'm not sure how else to do it.
		AuthenticationService.shutdown();
	}
}