package us.kbase.auth2.service;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import us.kbase.auth2.service.exceptions.AuthConfigurationException;
import us.kbase.auth2.service.kbase.KBaseAuthConfig;

public class AppEventListener implements ServletContextListener {
	
	@Override
	public void contextInitialized(ServletContextEvent arg0) {
		try {
			AuthenticationService.setConfig(new KBaseAuthConfig());
		} catch (AuthConfigurationException e) {
			e.printStackTrace();
			//server will fail to start since there's no config
		}
	}
	
	@Override
	public void contextDestroyed(ServletContextEvent arg0) {
		//TODO TEST manually test this shuts down the mongo connection.
		//this seems very wrong, but for now I'm not sure how else to do it.
		AuthenticationService.shutdown();
	}
}