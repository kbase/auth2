package us.kbase.auth2.service;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import us.kbase.auth2.kbase.KBaseAuthConfig;
import us.kbase.auth2.service.exceptions.AuthConfigurationException;

public class AppEventListener implements ServletContextListener {
	
	@Override
	public void contextInitialized(final ServletContextEvent arg0) {
		try {
			AuthenticationService.setConfig(new KBaseAuthConfig());
		} catch (AuthConfigurationException e) {
			e.printStackTrace();
			//TODO NOW this is crappy, server will start anyway and then throw a dumb exception.
			//TODO NOW pass in config class to load.
			//server will fail to start since there's no config
		}
	}
	
	@Override
	public void contextDestroyed(final ServletContextEvent arg0) {
		//TODO TEST manually test this shuts down the mongo connection.
		//this seems very wrong, but for now I'm not sure how else to do it.
		AuthenticationService.shutdown();
	}
}