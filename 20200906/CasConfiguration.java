package io.transwarp.guardian.federation.delegation.cas;

import org.jasig.cas.client.validation.*;
import org.pac4j.cas.client.CasProxyReceptor;
import org.pac4j.cas.config.CasProtocol;
import org.pac4j.cas.logout.CasLogoutHandler;
import org.pac4j.cas.logout.DefaultCasLogoutHandler;
import org.pac4j.cas.store.ProxyGrantingTicketStore;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.core.http.DefaultUrlResolver;
import org.pac4j.core.http.UrlResolver;
import org.pac4j.core.util.CommonHelper;
import org.pac4j.core.util.InitializableWebObject;

public class CasConfiguration extends InitializableWebObject {
  public static final String TICKET_PARAMETER = "ticket";
  public static final String SERVICE_PARAMETER = "service";
  public static final String LOGOUT_REQUEST_PARAMETER = "logoutRequest";
  public static final String SESSION_INDEX_TAG = "SessionIndex";
  public static final String RELAY_STATE_PARAMETER = "RelayState";
  private String encoding = "UTF-8";
  private String loginUrl;
  private String prefixUrl;
  private String restUrl;
  private long timeTolerance = 1000L;
  private CasProtocol protocol;
  private boolean renew;
  private boolean gateway;
  private boolean acceptAnyProxy;
  private ProxyList allowedProxyChains;
  private CasLogoutHandler logoutHandler;
  private TicketValidator defaultTicketValidator;
  private CasProxyReceptor proxyReceptor;
  private UrlResolver urlResolver;
  private String postLogoutUrlParameter;
  
  public CasConfiguration() {
    this.protocol = CasProtocol.CAS30;
    this.renew = false;
    this.gateway = false;
    this.acceptAnyProxy = false;
    this.allowedProxyChains = new ProxyList();
    this.urlResolver = new DefaultUrlResolver();
    this.postLogoutUrlParameter = "service";
  }
  
  public CasConfiguration(String loginUrl) {
    this.protocol = CasProtocol.CAS30;
    this.renew = false;
    this.gateway = false;
    this.acceptAnyProxy = false;
    this.allowedProxyChains = new ProxyList();
    this.urlResolver = new DefaultUrlResolver();
    this.postLogoutUrlParameter = "service";
    this.loginUrl = loginUrl;
  }
  
  public CasConfiguration(String loginUrl, CasProtocol protocol) {
    this.protocol = CasProtocol.CAS30;
    this.renew = false;
    this.gateway = false;
    this.acceptAnyProxy = false;
    this.allowedProxyChains = new ProxyList();
    this.urlResolver = new DefaultUrlResolver();
    this.postLogoutUrlParameter = "service";
    this.loginUrl = loginUrl;
    this.protocol = protocol;
  }
  
  public CasConfiguration(String loginUrl, String prefixUrl) {
    this.protocol = CasProtocol.CAS30;
    this.renew = false;
    this.gateway = false;
    this.acceptAnyProxy = false;
    this.allowedProxyChains = new ProxyList();
    this.urlResolver = new DefaultUrlResolver();
    this.postLogoutUrlParameter = "service";
    this.loginUrl = loginUrl;
    this.prefixUrl = prefixUrl;
  }
  
  protected void internalInit(WebContext context) {
    if (CommonHelper.isBlank(this.loginUrl) && CommonHelper.isBlank(this.prefixUrl) && CommonHelper.isBlank(this.restUrl)) {
      throw new TechnicalException("loginUrl, prefixUrl and restUrl cannot be all blank");
    } else {
      CommonHelper.assertNotNull("urlResolver", this.urlResolver);
      this.initializeClientConfiguration(context);
      this.initializeLogoutHandler();
    }
  }
  
  protected void initializeClientConfiguration(WebContext context) {
    if (this.prefixUrl != null && !this.prefixUrl.endsWith("/")) {
      this.prefixUrl = this.prefixUrl + "/";
    }
    
    if (CommonHelper.isBlank(this.prefixUrl)) {
      this.prefixUrl = this.loginUrl.replaceFirst("/login$", "/");
    } else if (CommonHelper.isBlank(this.loginUrl)) {
      this.loginUrl = this.prefixUrl + "login";
    }
    
    if (CommonHelper.isBlank(this.restUrl)) {
      this.restUrl = this.prefixUrl;
      if (!this.restUrl.endsWith("/")) {
        this.restUrl = this.restUrl + "/";
      }
      
      this.restUrl = this.restUrl + "v1/tickets";
    }
    
  }
  
  protected void initializeLogoutHandler() {
    if (this.logoutHandler == null) {
      this.logoutHandler = new DefaultCasLogoutHandler();
    }
    
  }
  
  public TicketValidator retrieveTicketValidator(WebContext context) {
    if (this.defaultTicketValidator != null) {
      return this.defaultTicketValidator;
    } else if (this.protocol == CasProtocol.CAS10) {
      return this.buildCas10TicketValidator(context);
    } else if (this.protocol == CasProtocol.CAS20) {
      return this.buildCas20TicketValidator(context);
    } else if (this.protocol == CasProtocol.CAS20_PROXY) {
      return this.buildCas20ProxyTicketValidator(context);
    } else if (this.protocol == CasProtocol.CAS30) {
      return this.buildCas30TicketValidator(context);
    } else if (this.protocol == CasProtocol.CAS30_PROXY) {
      return this.buildCas30ProxyTicketValidator(context);
    } else if (this.protocol == CasProtocol.SAML) {
      return this.buildSAMLTicketValidator(context);
    } else {
      throw new TechnicalException("Unable to initialize the TicketValidator for protocol: " + this.protocol);
    }
  }
  
  protected TicketValidator buildSAMLTicketValidator(WebContext context) {
    Saml11TicketValidator saml11TicketValidator = new Saml11TicketValidator(this.computeFinalPrefixUrl(context));
    saml11TicketValidator.setTolerance(this.getTimeTolerance());
    saml11TicketValidator.setEncoding(this.encoding);
    return saml11TicketValidator;
  }
  
  protected TicketValidator buildCas30ProxyTicketValidator(WebContext context) {
    Cas30ProxyTicketValidator cas30ProxyTicketValidator = new Cas30ProxyTicketValidator(this.computeFinalPrefixUrl(context));
    cas30ProxyTicketValidator.setEncoding(this.encoding);
    cas30ProxyTicketValidator.setAcceptAnyProxy(this.acceptAnyProxy);
    cas30ProxyTicketValidator.setAllowedProxyChains(this.allowedProxyChains);
    if (this.proxyReceptor != null) {
      cas30ProxyTicketValidator.setProxyCallbackUrl(this.proxyReceptor.computeFinalCallbackUrl(context));
      cas30ProxyTicketValidator.setProxyGrantingTicketStorage(new ProxyGrantingTicketStore(this.proxyReceptor.getStore()));
    }
    
    return cas30ProxyTicketValidator;
  }
  
  protected TicketValidator buildCas30TicketValidator(WebContext context) {
    Cas30ServiceTicketValidator cas30ServiceTicketValidator = new Cas30ServiceTicketValidator(this.computeFinalPrefixUrl(context));
    cas30ServiceTicketValidator.setEncoding(this.encoding);
    if (this.proxyReceptor != null) {
      cas30ServiceTicketValidator.setProxyCallbackUrl(this.proxyReceptor.computeFinalCallbackUrl(context));
      cas30ServiceTicketValidator.setProxyGrantingTicketStorage(new ProxyGrantingTicketStore(this.proxyReceptor.getStore()));
    }
    
    return cas30ServiceTicketValidator;
  }
  
  protected TicketValidator buildCas20ProxyTicketValidator(WebContext context) {
    Cas20ProxyTicketValidator cas20ProxyTicketValidator = new Cas20ProxyTicketValidator(this.computeFinalPrefixUrl(context));
    cas20ProxyTicketValidator.setEncoding(this.encoding);
    cas20ProxyTicketValidator.setAcceptAnyProxy(this.acceptAnyProxy);
    cas20ProxyTicketValidator.setAllowedProxyChains(this.allowedProxyChains);
    if (this.proxyReceptor != null) {
      cas20ProxyTicketValidator.setProxyCallbackUrl(this.proxyReceptor.computeFinalCallbackUrl(context));
      cas20ProxyTicketValidator.setProxyGrantingTicketStorage(new ProxyGrantingTicketStore(this.proxyReceptor.getStore()));
    }
    
    return cas20ProxyTicketValidator;
  }
  
  protected TicketValidator buildCas20TicketValidator(WebContext context) {
    Cas20ServiceTicketValidator cas20ServiceTicketValidator = new Cas20ServiceTicketValidator(this.computeFinalPrefixUrl(context));
    cas20ServiceTicketValidator.setEncoding(this.encoding);
    if (this.proxyReceptor != null) {
      cas20ServiceTicketValidator.setProxyCallbackUrl(this.proxyReceptor.computeFinalCallbackUrl(context));
      cas20ServiceTicketValidator.setProxyGrantingTicketStorage(new ProxyGrantingTicketStore(this.proxyReceptor.getStore()));
    }
    
    return cas20ServiceTicketValidator;
  }
  
  protected TicketValidator buildCas10TicketValidator(WebContext context) {
    Cas10TicketValidator cas10TicketValidator = new Cas10TicketValidator(this.computeFinalPrefixUrl(context));
    cas10TicketValidator.setEncoding(this.encoding);
    return cas10TicketValidator;
  }
  
  public String getEncoding() {
    return this.encoding;
  }
  
  public void setEncoding(String encoding) {
    this.encoding = encoding;
  }
  
  public String computeFinalLoginUrl(WebContext context) {
    return this.urlResolver.compute(this.loginUrl, context);
  }
  
  public String getLoginUrl() {
    return this.loginUrl;
  }
  
  public void setLoginUrl(String loginUrl) {
    this.loginUrl = loginUrl;
  }
  
  public String getPrefixUrl() {
    return this.prefixUrl;
  }
  
  public String computeFinalPrefixUrl(WebContext context) {
    return this.urlResolver.compute(this.prefixUrl, context);
  }
  
  public void setPrefixUrl(String prefixUrl) {
    this.prefixUrl = prefixUrl;
  }
  
  public long getTimeTolerance() {
    return this.timeTolerance;
  }
  
  public void setTimeTolerance(long timeTolerance) {
    this.timeTolerance = timeTolerance;
  }
  
  public CasProtocol getProtocol() {
    return this.protocol;
  }
  
  public void setProtocol(CasProtocol protocol) {
    this.protocol = protocol;
  }
  
  public boolean isRenew() {
    return this.renew;
  }
  
  public void setRenew(boolean renew) {
    this.renew = renew;
  }
  
  public boolean isGateway() {
    return this.gateway;
  }
  
  public void setGateway(boolean gateway) {
    this.gateway = gateway;
  }
  
  public boolean isAcceptAnyProxy() {
    return this.acceptAnyProxy;
  }
  
  public void setAcceptAnyProxy(boolean acceptAnyProxy) {
    this.acceptAnyProxy = acceptAnyProxy;
  }
  
  public ProxyList getAllowedProxyChains() {
    return this.allowedProxyChains;
  }
  
  public void setAllowedProxyChains(ProxyList allowedProxyChains) {
    this.allowedProxyChains = allowedProxyChains;
  }
  
  public CasLogoutHandler getLogoutHandler() {
    return this.logoutHandler;
  }
  
  public void setLogoutHandler(CasLogoutHandler logoutHandler) {
    this.logoutHandler = logoutHandler;
  }
  
  public TicketValidator getDefaultTicketValidator() {
    return this.defaultTicketValidator;
  }
  
  public void setDefaultTicketValidator(TicketValidator defaultTicketValidator) {
    this.defaultTicketValidator = defaultTicketValidator;
  }
  
  public CasProxyReceptor getProxyReceptor() {
    return this.proxyReceptor;
  }
  
  public void setProxyReceptor(CasProxyReceptor proxyReceptor) {
    this.proxyReceptor = proxyReceptor;
  }
  
  public String computeFinalUrl(String url, WebContext context) {
    return this.urlResolver.compute(url, context);
  }
  
  public String getPostLogoutUrlParameter() {
    return this.postLogoutUrlParameter;
  }
  
  public void setPostLogoutUrlParameter(String postLogoutUrlParameter) {
    this.postLogoutUrlParameter = postLogoutUrlParameter;
  }
  
  public String getRestUrl() {
    return this.restUrl;
  }
  
  public void setRestUrl(String restUrl) {
    this.restUrl = restUrl;
  }
  
  public String computeFinalRestUrl(WebContext context) {
    return this.urlResolver.compute(this.restUrl, context);
  }
  
  public UrlResolver getUrlResolver() {
    return this.urlResolver;
  }
  
  public void setUrlResolver(UrlResolver urlResolver) {
    this.urlResolver = urlResolver;
  }
  
  public String toString() {
    return CommonHelper.toString(this.getClass(), new Object[]{"loginUrl", this.loginUrl, "prefixUrl", this.prefixUrl, "restUrl", this.restUrl, "protocol", this.protocol, "renew", this.renew, "gateway", this.gateway, "encoding", this.encoding, "logoutHandler", this.logoutHandler, "acceptAnyProxy", this.acceptAnyProxy, "allowedProxyChains", this.allowedProxyChains, "proxyReceptor", this.proxyReceptor, "timeTolerance", this.timeTolerance, "postLogoutUrlParameter", this.postLogoutUrlParameter, "defaultTicketValidator", this.defaultTicketValidator, "urlResolver", this.urlResolver});
  }
}
