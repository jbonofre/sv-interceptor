package com.sv.interceptor;

import org.apache.camel.CamelContext;

import org.apache.camel.Route;
import org.apache.camel.component.cxf.CxfConsumer;
import org.apache.camel.component.cxf.jaxrs.CxfRsConsumer;
import org.apache.camel.impl.DefaultCamelContext;
import org.apache.cxf.Bus;
import org.apache.cxf.endpoint.Server;
import org.apache.cxf.interceptor.Interceptor;
import org.osgi.framework.*;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;
import org.osgi.service.cm.ConfigurationException;
import org.osgi.service.cm.ManagedService;
import org.osgi.service.component.ComponentException;
import org.osgi.util.tracker.ServiceTracker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.NamingException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Dictionary;
import java.util.Hashtable;

public class Activator implements BundleActivator {

    private final static Logger LOGGER = LoggerFactory.getLogger(Activator.class);

    private final static String CONFIG_PID = "com.sv.interceptor.security";
    private final static String CONFIG_AUTH_PID = "com.sv.interceptor.security.ldap";

    private ServiceTracker<Bus, ServiceRegistration> cxfBusesTracker;
    private ServiceTracker<CamelContext, ServiceRegistration> camelContextsTracker;
    private ServiceRegistration managedServiceRegistration;
    private Dictionary properties;
    private Dictionary LDAPProperties;

    private void inject(Bus bus, String symbolicName) throws Exception {
        LOGGER.debug("Check rules before adding LDAP interceptor (bus {})", symbolicName);
        InterceptorsUtil util = new InterceptorsUtil(properties);
        Dictionary matchingRules = util.getMatchingRules(symbolicName);
        if (matchingRules.size() > 0) {
            LOGGER.info("Matching rules found for bus {}, start LDAPInterceptor injection", symbolicName);
            LOGGER.debug("Creating LDAP interceptor for bus {}", symbolicName);
            LDAPInterceptor svInterceptor = new LDAPInterceptor();
            svInterceptor.setRules(matchingRules);
            svInterceptor.setOptions(LDAPProperties);

            LOGGER.debug("Injecting LDAP interceptor in bus {}", symbolicName);
            bus.getInInterceptors().add(svInterceptor);
            LOGGER.info("LDAP interceptor injected in bus {}", symbolicName);
        } else {
            LOGGER.debug("No matching rules found for bus {}, skip it", symbolicName);
        }
    }

    private void inject(org.apache.cxf.endpoint.Endpoint endpoint, String symbolicName) throws Exception {
        LOGGER.debug("Check rules before adding LDAP interceptor (endpoint {})", symbolicName);
        InterceptorsUtil util = new InterceptorsUtil(properties);
        Dictionary matchingRules = util.getMatchingRules(symbolicName);
        if (matchingRules.size() > 0) {
            LOGGER.debug("Matching rules found for endpoint {}, start LDAPInterceptor injection", symbolicName);
            LOGGER.debug("Creating LDAP interceptor for endpoint {}", symbolicName);
            LDAPInterceptor svInterceptor = new LDAPInterceptor();
            svInterceptor.setRules(matchingRules);
            svInterceptor.setOptions(LDAPProperties);

            LOGGER.debug("Injecting LDAP interceptor in endpoint {}", symbolicName);
            endpoint.getInInterceptors().add(svInterceptor);
        } else {
            LOGGER.debug("No matching rules found for endpoint {}, skip it", symbolicName);
        }
    }

    private void remove(Bus bus) {
        for (Interceptor interceptor : bus.getInInterceptors()) {
            if (interceptor instanceof LDAPInterceptor) {
                LOGGER.debug("Removing old sv interceptor from bus {}", bus.getId());
                bus.getInInterceptors().remove(interceptor);
            }
        }
    }

    private void remove(org.apache.cxf.endpoint.Endpoint endpoint) {
        for (Interceptor interceptor : endpoint.getInInterceptors()) {
            if (interceptor instanceof LDAPInterceptor) {
                LOGGER.debug("Removing old sv interceptor from endpoint");
                endpoint.getInInterceptors().remove(interceptor);
            }
        }
    }

    public void start(final BundleContext bundleContext) throws Exception {
        LOGGER.debug("Bundle start");
        Dictionary<String, String> properties = new Hashtable<>();
        properties.put(Constants.SERVICE_PID, CONFIG_PID);

        // Get LDAP configuration and test it
        ServiceReference configAdminServiceRef = bundleContext.getServiceReference(ConfigurationAdmin.class.getName());
        ConfigurationAdmin configAdminService = (ConfigurationAdmin) bundleContext.getService( configAdminServiceRef );

        try {
            Configuration configuration = configAdminService.getConfiguration(CONFIG_AUTH_PID);
            if (configuration.getProperties() == null) {
                throw new FileNotFoundException(CONFIG_AUTH_PID);
            }
            LDAPProperties = configuration.getProperties();
            LDAPOptions options = new LDAPOptions(LDAPProperties);
            LDAPCache cache = LDAPCache.getCache(options);
            cache.open();
            cache.close();
            LOGGER.info("Successfully connect to LDAP server");
        } catch(IOException e) {
            LOGGER.error("FATAL : Cannot read LDAP configuration file (check {}.cfg)", CONFIG_AUTH_PID);
            LOGGER.error("FATAL: Interceptor will block everything, need bundle restart.");
        } catch (javax.naming.AuthenticationException ex) {
            LOGGER.error("FATAL : " + ex.toString());
            LOGGER.error("FATAL : Credentials seems to be wrong (check {}.cfg)", CONFIG_AUTH_PID);
            LOGGER.error("FATAL: Interceptor will block everything, need bundle restart.");
        } catch(javax.naming.ConfigurationException ex) {
            LOGGER.error("FATAL : " + ex.toString() + " (check {}.cfg)", CONFIG_AUTH_PID);
            LOGGER.error("FATAL: Interceptor will block everything, need bundle restart.");
        } catch(NamingException ex) {
            LOGGER.warn(ex.toString());
            LOGGER.warn("Cannot connect to LDAP server;");
            LOGGER.warn("HINT : Check LDAP configuration file (default location : etc/{}.cfg) and LDAP server accessibility", CONFIG_AUTH_PID);
        }
        //LDAP configuration seems OK

        managedServiceRegistration = bundleContext.registerService(ManagedService.class.getName(), new ConfigUpdater(bundleContext), properties);

        LOGGER.debug("Starting CXF buses cxfBusesTracker");
        cxfBusesTracker = new ServiceTracker<Bus, ServiceRegistration>(bundleContext, Bus.class, null) {
            public ServiceRegistration<?> addingService(ServiceReference<Bus> reference) {
                Bus bus = bundleContext.getService(reference);
                LOGGER.debug("New bus service added, check it ({})", bus.getId());
                try {
                    inject(bus, reference.getBundle().getSymbolicName());
                } catch (Exception e) {
                    LOGGER.error("Can't inject sv interceptor", e);
                }
                return null;
            }

            public void removedService(ServiceReference<Bus> reference, ServiceRegistration reg) {
                reg.unregister();
                super.removedService(reference, reg);
            }
        };
        cxfBusesTracker.open();
        LOGGER.debug("Starting CamelContexts tracker");
        camelContextsTracker = new ServiceTracker<CamelContext, ServiceRegistration>(bundleContext, CamelContext.class, null) {
            public ServiceRegistration<?> addingService(ServiceReference<CamelContext> reference) {
                DefaultCamelContext camelContext = (DefaultCamelContext) bundleContext.getService(reference);
                LOGGER.debug("New camel service added, check its endpoints");
                for (Route route : camelContext.getRoutes()) {
                    if (route.getConsumer() instanceof CxfRsConsumer) {
                        Server server = ((CxfRsConsumer) route.getConsumer()).getServer();
                        LOGGER.debug("Look at endpoint {}", reference.getBundle().getSymbolicName());
                        try {
                            inject(server.getEndpoint(), reference.getBundle().getSymbolicName());
                        } catch (Exception e) {
                            LOGGER.error("Can't inject sv interceptor on CxfRsConsumer", e);
                        }
                    } else if (route.getConsumer() instanceof CxfConsumer) {
                        Server server = ((CxfConsumer) route.getConsumer()).getServer();
                        LOGGER.debug("Look at endpoint {}", reference.getBundle().getSymbolicName());
                        try {
                            inject(server.getEndpoint(), reference.getBundle().getSymbolicName());
                        } catch (Exception e) {
                            LOGGER.error("Can't inject sv interceptor on CxfConsumer", e);
                        }
                    }
                }
                return null;
            }

            public void removedService(ServiceReference<CamelContext> reference, ServiceRegistration reg) {
                reg.unregister();
                super.removedService(reference, reg);
            }
        };
        camelContextsTracker.open();
    }

    private void cleanInterceptors(BundleContext bundleContext) throws Exception{
        LOGGER.info("Cleaning LDAPInterceptor from services");
        ServiceReference[] references = bundleContext.getServiceReferences(Bus.class.getName(), null);
        if (references != null) {
            for (ServiceReference reference : references) {
                Bus bus = (Bus) bundleContext.getService(reference);
                remove(bus);
            }
        }
        references = bundleContext.getServiceReferences(CamelContext.class.getName(), null);
        if (references != null) {
            for (ServiceReference reference : references) {
                CamelContext camelContext = (CamelContext) bundleContext.getService(reference);
                for (Route route : camelContext.getRoutes()) {
                    if (route.getConsumer() instanceof CxfRsConsumer) {
                        Server server = ((CxfRsConsumer) route.getConsumer()).getServer();
                        try {
                            remove(server.getEndpoint());
                        } catch (Exception e) {
                            LOGGER.error("Can't inject sv interceptor on CxfRsConsumer", e);
                        }
                    } else if (route.getConsumer() instanceof CxfConsumer) {
                        Server server = ((CxfConsumer) route.getConsumer()).getServer();
                        try {
                            remove(server.getEndpoint());
                        } catch (Exception e) {
                            LOGGER.error("Can't inject sv interceptor on CxfConsumer", e);
                        }
                    }
                }
            }
        }
    }

    public void stop(BundleContext bundleContext) throws Exception {
        LOGGER.info("Stopping LDAPInterceptor tracker");
        if (cxfBusesTracker != null)
            cxfBusesTracker.close();
        if (camelContextsTracker != null)
            camelContextsTracker.close();
        if (managedServiceRegistration != null)
            managedServiceRegistration.unregister();

        cleanInterceptors(bundleContext);
        LOGGER.info("LDAPInterceptor tracker stopped");
    }

    private final class ConfigUpdater implements ManagedService {
        private BundleContext bundleContext;

        public ConfigUpdater(BundleContext bundleContext) {
            this.bundleContext = bundleContext;
        }

        public void updated(Dictionary<String, ?> config) throws ConfigurationException {
            properties = config;
            LOGGER.debug("Configuration updated");
            try {
                ServiceReference[] references = bundleContext.getServiceReferences(Bus.class.getName(), null);
                if (references != null) {
                    for (ServiceReference reference : references) {
                        Bus bus = (Bus) bundleContext.getService(reference);
                        remove(bus);
                        inject(bus, reference.getBundle().getSymbolicName());
                    }
                }
                references = bundleContext.getServiceReferences(CamelContext.class.getName(), null);
                if (references != null) {
                    for (ServiceReference reference : references) {
                        CamelContext camelContext = (CamelContext) bundleContext.getService(reference);
                        for (Route route : camelContext.getRoutes()) {
                            if (route.getConsumer() instanceof CxfRsConsumer) {
                                Server server = ((CxfRsConsumer) route.getConsumer()).getServer();
                                try {
                                    remove(server.getEndpoint());
                                    inject(server.getEndpoint(), reference.getBundle().getSymbolicName());
                                } catch (Exception e) {
                                    LOGGER.error("Can't inject sv interceptor on CxfRsConsumer", e);
                                }
                            } else if (route.getConsumer() instanceof CxfConsumer) {
                                Server server = ((CxfConsumer) route.getConsumer()).getServer();
                                try {
                                    remove(server.getEndpoint());
                                    inject(server.getEndpoint(), reference.getBundle().getSymbolicName());
                                } catch (Exception e) {
                                    LOGGER.error("Can't inject sv interceptor on CxfConsumer", e);
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                throw new ConfigurationException("", "Can't update configuration", e);
            }
        }
    }
}
