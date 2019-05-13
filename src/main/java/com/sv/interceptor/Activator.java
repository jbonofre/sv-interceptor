package com.sv.interceptor;

import org.apache.camel.CamelContext;
import org.apache.camel.Endpoint;
import org.apache.camel.Route;
import org.apache.camel.component.cxf.CxfConsumer;
import org.apache.camel.component.cxf.CxfEndpoint;
import org.apache.camel.component.cxf.jaxrs.CxfRsConsumer;
import org.apache.camel.component.cxf.jaxrs.CxfRsEndpoint;
import org.apache.camel.impl.DefaultCamelContext;
import org.apache.cxf.Bus;
import org.apache.cxf.endpoint.Server;
import org.apache.cxf.interceptor.Interceptor;
import org.osgi.framework.*;
import org.osgi.service.cm.ConfigurationException;
import org.osgi.service.cm.ManagedService;
import org.osgi.util.tracker.ServiceTracker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Dictionary;
import java.util.Hashtable;

public class Activator implements BundleActivator {

    private final static Logger LOGGER = LoggerFactory.getLogger(Activator.class);

    private final static String CONFIG_PID = "com.sv.interceptor.security";

    private ServiceTracker<Bus, ServiceRegistration> cxfBusesTracker;
    private ServiceTracker<CamelContext, ServiceRegistration> camelContextsTracker;
    private ServiceRegistration managedServiceRegistration;
    private Dictionary properties;

    private void inject(Bus bus, String symbolicName, Dictionary properties) throws Exception {
        LOGGER.debug("Injecting LDAP interceptor ({})", symbolicName);
        InterceptorsUtil util = new InterceptorsUtil(properties);
        if (util.symbolicNameDefined(symbolicName)) {
            LOGGER.debug("Symbolic name found");

            LOGGER.debug("Create LDAP interceptor");
            LDAPInterceptor svInterceptor = new LDAPInterceptor();
            svInterceptor.setProperties(properties);

            LOGGER.debug("Injecting LDAP interceptor in bus {}", bus.getId());
            bus.getInInterceptors().add(svInterceptor);
        }
    }

    private void remove(Bus bus) {
        for (Interceptor interceptor : bus.getInInterceptors()) {
            if (interceptor instanceof LDAPInterceptor) {
                LOGGER.debug("Removing old sv interceptor");
                bus.getInInterceptors().remove(interceptor);
            }
        }
    }

    public void start(final BundleContext bundleContext) throws Exception {
        Dictionary<String, String> properties = new Hashtable<>();
        properties.put(Constants.SERVICE_PID, CONFIG_PID);
        managedServiceRegistration = bundleContext.registerService(ManagedService.class.getName(), new ConfigUpdater(bundleContext), properties);

        LOGGER.debug("Starting CXF buses cxfBusesTracker");
        cxfBusesTracker = new ServiceTracker<Bus, ServiceRegistration>(bundleContext, Bus.class, null) {

            public ServiceRegistration<?> addingService(ServiceReference<Bus> reference) {
                Bus bus = bundleContext.getService(reference);
                try {
                    inject(bus, reference.getBundle().getSymbolicName(), properties);
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
                for (Route route : camelContext.getRoutes()) {
                    if (route.getConsumer() instanceof CxfRsConsumer) {
                        Server server = ((CxfRsConsumer) route.getConsumer()).getServer();
                        LDAPInterceptor svInterceptor = new LDAPInterceptor();
                        svInterceptor.setProperties(properties);
                        server.getEndpoint().getInInterceptors().add(svInterceptor);
                    } else if (route.getConsumer() instanceof CxfConsumer) {
                        Server server = ((CxfConsumer) route.getConsumer()).getServer();
                        LDAPInterceptor svInterceptor = new LDAPInterceptor();
                        svInterceptor.setProperties(properties);
                        server.getEndpoint().getInInterceptors().add(svInterceptor);
                    }
                }
                /*
                LOGGER.debug("Tracking CamelContext {}", camelContext.getName());
                for (Endpoint endpoint : camelContext.getEndpoints()) {
                    LOGGER.debug("Checking endpoint {}", endpoint.getEndpointUri());
                    if (endpoint instanceof CxfEndpoint) {
                        try {
                            inject(((CxfEndpoint) endpoint).getBus(), reference.getBundle().getSymbolicName(), properties);
                        } catch (Exception e) {
                            LOGGER.error("Can't inject sv interceptor", e);
                        }
                    } else if (endpoint instanceof CxfRsEndpoint) {
                        try {
                            inject(((CxfRsEndpoint) endpoint).getBus(), reference.getBundle().getSymbolicName(), properties);
                        } catch (Exception e) {
                            LOGGER.error("Can't inject sv interceptor", e);
                        }
                    }
                }
                */
                return null;
            }

            public void removedService(ServiceReference<CamelContext> reference, ServiceRegistration reg) {
                reg.unregister();
                super.removedService(reference, reg);
            }
        };
        camelContextsTracker.open();
    }

    public void stop(BundleContext bundleContext) throws Exception {
        if (cxfBusesTracker != null)
            cxfBusesTracker.close();
        if (camelContextsTracker != null)
            camelContextsTracker.close();
        if (managedServiceRegistration != null)
            managedServiceRegistration.unregister();
    }

    private final class ConfigUpdater implements ManagedService {

        private BundleContext bundleContext;

        public ConfigUpdater(BundleContext bundleContext) {
            this.bundleContext = bundleContext;
        }

        public void updated(Dictionary<String, ?> config) throws ConfigurationException {
            properties = config;
            try {
                ServiceReference[] references = bundleContext.getServiceReferences(Bus.class.getName(), null);
                for (ServiceReference reference : references) {
                    Bus bus = (Bus) bundleContext.getService(reference);

                    InterceptorsUtil util = new InterceptorsUtil(properties);
                    remove(bus);
                    if (util.symbolicNameDefined(reference.getBundle().getSymbolicName())) {
                        inject(bus, reference.getBundle().getSymbolicName(), properties);
                    }
                }
                references = bundleContext.getServiceReferences(CamelContext.class.getName(), null);
                for (ServiceReference reference : references) {
                    CamelContext camelContext = (CamelContext) bundleContext.getService(reference);
                    for (Endpoint endpoint : camelContext.getEndpoints()) {
                        if (endpoint instanceof CxfEndpoint) {
                            remove(((CxfEndpoint) endpoint).getBus());
                            InterceptorsUtil util = new InterceptorsUtil(properties);
                            if (util.symbolicNameDefined(reference.getBundle().getSymbolicName())) {
                                inject(((CxfEndpoint) endpoint).getBus(), reference.getBundle().getSymbolicName(), properties);
                            }
                        }
                        if (endpoint instanceof CxfEndpoint) {
                            remove(((CxfRsEndpoint) endpoint).getBus());
                            InterceptorsUtil util = new InterceptorsUtil(properties);
                            if (util.symbolicNameDefined(reference.getBundle().getSymbolicName())) {
                                inject(((CxfRsEndpoint) endpoint).getBus(), reference.getBundle().getSymbolicName(), properties);
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
