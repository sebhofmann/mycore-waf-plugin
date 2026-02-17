package org.mycore.waf;


import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterRegistration;
import jakarta.servlet.ServletContext;
import java.util.EnumSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.mycore.common.events.MCRStartupHandler.AutoExecutable;

public class FilterRegistrationStartupHandler implements AutoExecutable {

  private static final Logger LOGGER = LogManager.getLogger();

  @Override
  public String getName() {
    return "FilterRegistrationStartupHandler";
  }

  @Override
  public int getPriority() {
    return 0;
  }

  @Override
  public void startUp(ServletContext servletContext) {
    LOGGER.info("Registering WAFFilter for all URLs");

    // Create and register the WAFFilter
    FilterRegistration.Dynamic filterRegistration = servletContext.addFilter("WAFFilter", WAFFilter.class);

    if (filterRegistration != null) {
      // Map the filter to all URLs
      filterRegistration.addMappingForUrlPatterns(
          EnumSet.of(DispatcherType.REQUEST, DispatcherType.FORWARD),
          false, // isMatchAfter - false means this filter runs before others
          "/*"
      );

      LOGGER.info("WAFFilter successfully registered for all URLs");
    } else {
      LOGGER.warn("WAFFilter registration returned null - filter might already be registered");
    }
  }
}
