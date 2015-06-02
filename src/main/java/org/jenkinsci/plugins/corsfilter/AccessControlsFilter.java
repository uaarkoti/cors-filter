package org.jenkinsci.plugins.corsfilter;

import com.google.inject.Injector;
import hudson.Extension;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.model.*;
import hudson.util.PluginServletFilter;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.StaplerRequest;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Filter to support <a href="http://en.wikipedia.org/wiki/Cross-origin_resource_sharing">CORS</a>
 * to access Jenkins API's from a dynamic web application using frameworks like AngularJS
 *
 * @author Udaypal Aarkoti
 * @author Steven Christou
 */
@Extension
public class AccessControlsFilter implements Filter, Describable<AccessControlsFilter> {

    private static final String PREFLIGHT_REQUEST = "OPTIONS";
    private List<String> allowedOriginsList = null;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    /**
     * Handle CORS Access Controls
     */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (response instanceof HttpServletResponse) {

            final HttpServletResponse resp = (HttpServletResponse) response;
            if(request instanceof HttpServletRequest && getDescriptor().isEnabled()) {
                HttpServletRequest req = (HttpServletRequest)request;

                /**
                 * If the request is GET, set allow origin
                 * If its pre-flight request, set allow methods
                 */
                processAccessControls(req, resp);

                /**
                 * If this is a preflight request, set the response to 200 OK.
                 */
                if(req.getMethod().equals(PREFLIGHT_REQUEST)) {
                    resp.setStatus(200);
                    return;
                }
            }
        }
        chain.doFilter(request, response);
    }

    /**
     * Apply access controls
     */
    private void processAccessControls(HttpServletRequest req, HttpServletResponse resp) {
        String origin = req.getHeader("Origin");
        if (origin != null && isAllowed(origin.trim())) {
            resp.addHeader("Access-Control-Allow-Methods", getDescriptor().getAllowedMethods());
            resp.addHeader("Access-Control-Allow-Credentials", "true");
            resp.addHeader("Access-Control-Allow-Origin", origin);
        }
    }

    /**
     * Check if the origin is allowed
     * @param origin
     * @return
     */
    private boolean isAllowed(String origin) {

        if (allowedOriginsList == null) {
            String allowedOrigins = getDescriptor().getAllowedOrigins();

            if (allowedOrigins != null && !allowedOrigins.trim().isEmpty()) {
                allowedOriginsList = Arrays.asList(allowedOrigins.split(","));
            }
            else {
                allowedOriginsList = Collections.EMPTY_LIST;
            }
        }

        /**
         * Asterix (*) means that the resource can be accessed by any domain in a cross-site manner.
         * Should be used with caution.
         */
        if (allowedOriginsList.contains("*")) {
            return true;
        }

        for (int i = 0; i < allowedOriginsList.size(); i++) {
            if (allowedOriginsList.get(i).equals(origin)) {
                return true;
            }
        }

        return false;
    }

    @Override
    public void destroy() {

    }

    @Initializer (after = InitMilestone.JOB_LOADED)
    public static void init() throws ServletException {
        Injector inj = Jenkins.getInstance().getInjector();
        if (inj == null) {
            return;
        }
        PluginServletFilter.addFilter(inj.getInstance(AccessControlsFilter.class));
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return new DescriptorImpl();
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<AccessControlsFilter> {

        private boolean enabled;
        private String allowedOrigins;
        private String allowedMethods;

        public DescriptorImpl() {
            load();
        }

        @Override
        public String getDisplayName() {
            return "CORS Filter";
        }

        public boolean configure(StaplerRequest req, JSONObject json) throws FormException {

            enabled = json.getBoolean("enabled");
            allowedOrigins = json.getString("allowedOrigins");
            allowedMethods = json.getString("allowedMethods");

            save();
            return super.configure(req, json);
        }

        public boolean isEnabled() {
          return enabled;
        }

        public String getAllowedOrigins() {
          return allowedOrigins;
        }

        public String getAllowedMethods() {
          return allowedMethods;
        }
    }
}
