package us.kbase.auth2.service.template.mustache;

import static java.util.Objects.requireNonNull;

import java.io.StringWriter;
import java.nio.file.Path;

import com.github.mustachejava.DefaultMustacheFactory;
import com.github.mustachejava.MustacheFactory;

import us.kbase.auth2.service.template.TemplateProcessor;

/* It's completely stupid that I have to create this class, but there doesn't
 * seem to be any way to get my hands on the jersey mustache processor once
 * it's registered.
 */
public class MustacheProcessor implements TemplateProcessor {

	//TODO TEST unit tests
	//TODO JAVADOC
	
	private static final String SUFFIX = ".mustache";
	
	private final MustacheFactory mf = new DefaultMustacheFactory();
	private final Path templates;
	
	public MustacheProcessor(final Path templateDir) {
		requireNonNull(templateDir, "templateDir");
		templates = templateDir;
	}
	
	// this is only suitable for small objects and templates
	@Override
	public String process(final String template, final Object model) {
		final Path t = templates.resolve(template);
		final StringWriter sw = new StringWriter();
		mf.compile(t.toString() + SUFFIX).execute(sw, model);
		return sw.toString();
	}
	
}
