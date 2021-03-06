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
import org.apache.wss4j.common.principal.WSUsernameTokenPrincipalImpl;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.token.UsernameToken;
import org.apache.wss4j.dom.validate.Credential;
import org.apache.wss4j.dom.validate.Validator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.w3c.dom.Document;

import javax.naming.Context;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.security.auth.Subject;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.security.Principal;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This interceptor just get a base authorization, and create a UsernameToken delegated to the Syncope interceptor
 */
public class LDAPInterceptor extends AbstractPhaseInterceptor<Message> {

    private final Logger LOGGER = LogManager.getLogger(LDAPInterceptor.class);

    private Validator validator;

    private Dictionary options;

    private Dictionary rules;

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

    class Sortbylength implements Comparator<String>
    {
        // Used for sorting in ascending order of
        // roll number
        public int compare(String a, String b)
        {
            return b.length() - a.length();
        }
    }

    private String getFirstMatchingRule(Message message) {
        if (rules != null) {
            Enumeration keys = rules.keys();
            List<String> list = Collections.list(keys);
            Collections.sort(list, new Sortbylength());
            for (String key: list) {
                String [] parts = key.split(":");
                if (parts.length == 1) {
                    LOGGER.debug("Rule {} found with no condition", key);
                    return (String)rules.get(key);
                }

                String verbs = parts[1];
                String operations = null;
                if (parts.length == 3) {
                    operations = parts[2];
                }

                String verb = (String)message.get("org.apache.cxf.request.method");
                if (!"".equals(verbs.trim())) {
                    if (verbs.toLowerCase().indexOf(verb.toLowerCase()) == -1) {
                        LOGGER.debug("Verb {} does not match any verbs {}, continue", verb, verbs);
                        continue;
                    }
                    LOGGER.debug("Verb {} matches with verbs range ({})", verb, verbs);
                } else {
                    LOGGER.debug("Skip verb check, ({})", verb);
                }

                if (operations != null && !"".equals(operations.trim()) && message.containsKey("org.apache.cxf.binding.soap.SoapVersion")) {
                    TreeMap headers= (TreeMap)message.get("org.apache.cxf.message.Message.PROTOCOL_HEADERS");
                    ArrayList actions = (ArrayList)headers.get("SOAPAction");
                    if (actions.size() == 0) {
                        LOGGER.warn("Message should have a SOAPAction but is not found, throw exception");
                    }

                    String operation = ((String)actions.get(0)).replaceAll("\"", "");

                    Pattern pattern = Pattern.compile(operations);
                    Matcher matcher = pattern.matcher(operation);
                    if (!matcher.matches()) {
                        LOGGER.debug("Operation {} does not match any operations {}, continue", operation, operations);
                        continue;
                    }
                    LOGGER.debug("Operation {} matches with operations range ({})", operation, operations);
                } else {
                    LOGGER.debug("Skip operation check");
                }
                return (String)rules.get(key);
            }
        }
        return null;
    }


    public void handleMessage(Message message) throws Fault {
        LOGGER.info("Handling new message");
        AuthorizationPolicy policy = message.get(AuthorizationPolicy.class);

        String expectedGroups = getFirstMatchingRule(message);

        if (expectedGroups == null) {
            LOGGER.info("Message matches no rule, continue.");
            return;
        }

        LOGGER.info("Expected groups user : {}", expectedGroups );
        if (policy == null || policy.getUserName() == null || policy.getPassword() == null) {
            // no authentication provided, send error response
            LOGGER.info("No authorization policy, send HttpURLConnection.HTTP_UNAUTHORIZED");
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
            LDAPOptions ldapOptions;
            try {
                ldapOptions = new LDAPOptions(options);
            } catch (java.lang.NullPointerException ex) {
                LOGGER.fatal("Cannot read LDAP configuration file, send HttpURLConnection.HTTP_INTERNAL_ERROR");
                sendErrorResponse(message, HttpURLConnection.HTTP_INTERNAL_ERROR);
                return;
            }
            LDAPCache cache = LDAPCache.getCache(ldapOptions);
            // step 1.1, get DN
            final String[] userDnAndNamespace;
            try {
                LOGGER.debug("Get the user DN.");
                userDnAndNamespace = cache.getUserDnAndNamespace(user);
                if (userDnAndNamespace == null) {
                    LOGGER.warn("Can't authenticate user to the LDAP server, send HttpURLConnection.HTTP_UNAUTHORIZED");
                    sendErrorResponse(message, HttpURLConnection.HTTP_UNAUTHORIZED);
                    return;
                }
            } catch (javax.naming.AuthenticationException e) {
                LOGGER.fatal(e.toString());
                LOGGER.fatal("Credentials seems to be wrong, send HttpURLConnection.HTTP_INTERNAL_ERROR");
                sendErrorResponse(message, HttpURLConnection.HTTP_INTERNAL_ERROR);
                return;
            } catch (Exception e) {
                LOGGER.warn(e.toString());
                LOGGER.warn("Can't connect to the LDAP server: {}, send HttpURLConnection.HTTP_INTERNAL_ERROR", e.getMessage());
                sendErrorResponse(message, HttpURLConnection.HTTP_INTERNAL_ERROR);
                return;
            }
            // step 1.2, bind the user using DN
            DirContext context = null;
            try {
                // switch the credentials to the Karaf login user so that we can verify his password is correct
                LOGGER.debug("Bind user (authentication).");
                Hashtable<String, Object> env = ldapOptions.getEnv();
                LOGGER.debug("Set the security principal for " + userDnAndNamespace[0] + "," + ldapOptions.getUserBaseDn());
                env.put(Context.SECURITY_PRINCIPAL, userDnAndNamespace[0] + "," + ldapOptions.getUserBaseDn());
                env.put(Context.SECURITY_CREDENTIALS, password);
                LOGGER.debug("Binding the user.");
                context = new InitialDirContext(env);
                LOGGER.debug("User " + user + " successfully bound.");
                context.close();
            } catch (Exception e) {
                LOGGER.warn("User " + user + " authentication failed, send HttpURLConnection.HTTP_UNAUTHORIZED.", e);
                sendErrorResponse(message, HttpURLConnection.HTTP_UNAUTHORIZED);
                return;
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
            String group = cache.getFirstMatchingGroup(user, Arrays.stream(expectedGroups.split(",")).map(String::trim).toArray(String[]::new));
            if(group == null) {
                LOGGER.warn("No group found, send HttpURLConnection.HTTP_FORBIDDEN");
                sendErrorResponse(message, HttpURLConnection.HTTP_FORBIDDEN);
                return;
            }
            LOGGER.info("User authorized via group {}, continue.", group);

            Subject subject = new Subject();
            subject.getPrincipals().add(p);
            subject.getPrincipals().add(new SimpleGroup(group, token.getName()));
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

    public void setOptions(Dictionary options) {
        this.options = options;
    }

    public void setRules(Dictionary rules) {
        this.rules = rules;
    }

}
