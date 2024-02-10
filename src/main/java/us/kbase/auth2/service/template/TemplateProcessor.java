package us.kbase.auth2.service.template;

public interface TemplateProcessor {

	//TODO JAVADOC
	
	// this is only suitable for small objects and templates
	String process(String template, Object model);

}