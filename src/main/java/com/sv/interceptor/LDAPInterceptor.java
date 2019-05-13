package com.sv.interceptor;

import org.apache.cxf.common.security.SimpleGroup;
import org.apache.cxf.configuration.security.AuthorizationPolicy;
import org.apache.cxf.endpoint.Endpoint;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.interceptor.security.DefaultSecurityContext;
import org.apache.cxf.message.Exchange;
import org.apache.cxf.message.Message;
import org.apache.cxf.message.MessageImpl;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.security.SecurityContext;
import org.apache.cxf.transport.Conduit;
import org.apache.cxf.transport.http.Headers;
import org.apache.cxf.ws.addressing.EndpointReferenceType;
import org.apache.wss4j.common.principal.WSUsernameTokenPrincipalImpl;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.token.UsernameToken;
import org.apache.wss4j.dom.validate.Credential;
import org.apache.wss4j.dom.validate.Validator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import javax.naming.Context;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.security.auth.Subject;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.security.Principal;
import java.util.*;

/**
 * This interceptor just get a base authorization, and create a UsernameToken delegated to the Syncope interceptor
 */
public class LDAPInterceptor extends AbstractPhaseInterceptor<Message> {

    private final Logger LOGGER = LoggerFactory.getLogger(LDAPInterceptor.class);

    private Validator validator;

    private Dictionary properties;

    public LDAPInterceptor() {
        this(Phase.READ);
    }

    public LDAPInterceptor(String phase) {
        super(phase);
    }

    public void sendErrorResponse(Message message, int errorCode) {

        // no authentication provided, send error response
        Exchange exchange = message.getExchange();
        Message outMessage = exchange.getOutMessage();
        if (outMessage == null) {
            Endpoint endpoint = exchange.get(Endpoint.class);
            outMessage = new MessageImpl();
            outMessage.putAll(message);
            outMessage.remove(Message.PROTOCOL_HEADERS);
            outMessage.setExchange(exchange);
            outMessage = endpoint.getBinding().createMessage(outMessage);
            exchange.setOutMessage(outMessage);
        }
        outMessage.put(Message.RESPONSE_CODE, errorCode);
        Map<String, List<String>> responseHeaders = Headers.getSetProtocolHeaders(outMessage);
        responseHeaders.put("WWW-Authenticate", Arrays.asList(new String[] {"Basic realm=realm"}));
        message.getInterceptorChain().abort();

        try {
            EndpointReferenceType target = exchange.get(EndpointReferenceType.class);
            if (exchange.getDestination() == null) {
                LOGGER.debug("Exchange destination is null");
                return;
            }
            Conduit conduit = exchange.getDestination().getBackChannel(message);
            exchange.setConduit(conduit);
            conduit.prepare(outMessage);
            OutputStream os = outMessage.getContent(OutputStream.class);
            os.flush();
            os.close();
        } catch (Exception e) {
            LOGGER.error("Can't prepare response", e);
        }
    }

    public void handleMessage(Message message) throws Fault {
        AuthorizationPolicy policy = message.get(AuthorizationPolicy.class);

        if (policy == null || policy.getUserName() == null || policy.getPassword() == null) {
            // no authentication provided, send error response
            sendErrorResponse(message, HttpURLConnection.HTTP_UNAUTHORIZED);
            return;
        }

        try {
            LOGGER.info("Get authorization policy, converting to username token");

            UsernameToken token = convertPolicyToToken(policy);
            Credential credential = new Credential();
            credential.setUsernametoken(token);

            RequestData data = new RequestData();
            data.setMsgContext(message);

            // Create a Principal/SecurityContext
            Principal p = null;
            if (credential != null && credential.getPrincipal() != null) {
                p = credential.getPrincipal();
            } else {
                p = new WSUsernameTokenPrincipalImpl(policy.getUserName(), false);
                ((WSUsernameTokenPrincipalImpl)p).setPassword(policy.getPassword());
            }

            // 1. validate authentication with token
            //       LDAP auth(token.getName(), token.getPassword());
            String user = token.getName();
            String password = token.getPassword();
            LDAPOptions options = new LDAPOptions(properties);
            LDAPCache cache = LDAPCache.getCache(options);
            // step 1.1, get DN
            final String[] userDnAndNamespace;
            try {
                LOGGER.debug("Get the user DN.");
                userDnAndNamespace = cache.getUserDnAndNamespace(user);
                if (userDnAndNamespace == null) {
                    throw new SecurityException("Can't authenticate user");
                }
            } catch (Exception e) {
                LOGGER.warn("Can't connect to the LDAP server: {}", e.getMessage(), e);
                throw new Fault(e);
            }
            // step 1.2, bind the user using DN
            DirContext context = null;
            try {
                // switch the credentials to the Karaf login user so that we can verify his password is correct
                LOGGER.debug("Bind user (authentication).");
                Hashtable<String, Object> env = options.getEnv();
                env.put(Context.SECURITY_AUTHENTICATION, options.getAuthentication());
                LOGGER.debug("Set the security principal for " + userDnAndNamespace[0] + "," + options.getUserBaseDn());
                env.put(Context.SECURITY_PRINCIPAL, userDnAndNamespace[0] + "," + options.getUserBaseDn());
                env.put(Context.SECURITY_CREDENTIALS, password);
                LOGGER.debug("Binding the user.");
                context = new InitialDirContext(env);
                LOGGER.debug("User " + user + " successfully bound.");
                context.close();
            } catch (Exception e) {
                LOGGER.warn("User " + user + " authentication failed.", e);
                throw new Fault(e);
            } finally {
                if (context != null) {
                    try {
                        context.close();
                    } catch (Exception e) {
                        // ignore
                    }
                }
            }
            // here user is authenticated

            // 2. get the roles from LDAP
            //    Get the role from LDAP
            String[] roles = cache.getUserRoles(user, userDnAndNamespace[0], userDnAndNamespace[1]);

            Subject subject = new Subject();
            subject.getPrincipals().add(p);
            for (String role : roles) {
                subject.getPrincipals().add(new SimpleGroup(role, token.getName()));
            }
            subject.setReadOnly();

            // put principal and subject (with the roles) in message DefaultSecurityContext
            message.put(DefaultSecurityContext.class, new DefaultSecurityContext(p, subject));

        } catch (Exception ex) {
            throw new Fault(ex);
        }
    }

    protected UsernameToken convertPolicyToToken(AuthorizationPolicy policy)
            throws Exception {

        Document doc = DOMUtils.createDocument();
        UsernameToken token = new UsernameToken(false, doc, WSConstants.PASSWORD_TEXT);
        token.setName(policy.getUserName());
        token.setPassword(policy.getPassword());
        return token;
    }

    protected SecurityContext createSecurityContext(final Principal p) {
        return new SecurityContext() {

            public Principal getUserPrincipal() {
                return p;
            }

            public boolean isUserInRole(String arg0) {
                return false;
            }
        };
    }

    public void setValidator(Validator validator) {
        this.validator = validator;
    }

    public void setProperties(Dictionary properties) {
        this.properties = properties;
    }

}
