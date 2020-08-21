package io.transwarp.guardian.federation.delegation.cas;

import org.pac4j.cas.authorization.DefaultCasAuthorizationGenerator;
import org.pac4j.cas.config.CasConfiguration;
import org.pac4j.cas.credentials.authenticator.CasAuthenticator;
import org.pac4j.cas.credentials.extractor.TicketAndLogoutRequestExtractor;
import org.pac4j.cas.logout.CasLogoutHandler;
import org.pac4j.cas.redirect.CasRedirectActionBuilder;
import org.pac4j.core.client.IndirectClient;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.credentials.TokenCredentials;
import org.pac4j.core.logout.CasLogoutActionBuilder;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.util.CommonHelper;

public class CasClient extends IndirectClient<TokenCredentials, CommonProfile> {
  private CasConfiguration configuration = new CasConfiguration();
  
  public CasClient() {
  }
  
  public CasClient(CasConfiguration configuration) {
    this.setConfiguration(configuration);
  }
  
  protected void clientInit(WebContext context) {
    CommonHelper.assertNotNull("configuration", this.configuration);
    this.configuration.setUrlResolver(this.getUrlResolver());
    this.configuration.init(context);
    this.defaultRedirectActionBuilder(new CasRedirectActionBuilder(this.configuration, this.callbackUrl));
    this.defaultCredentialsExtractor(new TicketAndLogoutRequestExtractor(this.configuration, this.getName()));
    this.defaultAuthenticator(new CasAuthenticator(this.configuration, this.callbackUrl));
    this.defaultLogoutActionBuilder(new CasLogoutActionBuilder(this.configuration.getPrefixUrl() + "logout", this.configuration.getPostLogoutUrlParameter()));
    this.addAuthorizationGenerator(new DefaultCasAuthorizationGenerator());
  }
  
  public void notifySessionRenewal(String oldSessionId, WebContext context) {
    CasLogoutHandler casLogoutHandler = this.configuration.getLogoutHandler();
    if (casLogoutHandler != null) {
      casLogoutHandler.renewSession(oldSessionId, context);
    }
    
  }
  
  public CasConfiguration getConfiguration() {
    return this.configuration;
  }
  
  public void setConfiguration(CasConfiguration configuration) {
    this.configuration = configuration;
  }
  
  public String toString() {
    return CommonHelper.toString(this.getClass(), "name", this.getName(), "callbackUrl", this.callbackUrl, "urlResolver", this.urlResolver,
      "ajaxRequestResolver", this.getAjaxRequestResolver(), "redirectActionBuilder", this.getRedirectActionBuilder(),
      "credentialsExtractor", this.getCredentialsExtractor(), "authenticator", this.getAuthenticator(), "profileCreator", this.getProfileCreator(),
      "logoutActionBuilder", this.getLogoutActionBuilder(), "configuration", this.configuration);
  }
}
