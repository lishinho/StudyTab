package io.transwarp.guardian.federation.persistence.model;

public class SLOClientInfo {

  private String sessionId;
  private String clientId;
  private String authorizationCode;
  private String resolveLogoutUrl;

  private SLOClientInfo(Builder builder) {
    sessionId = builder.sessionId;
    clientId = builder.clientId;
    authorizationCode = builder.authorizationCode;
    resolveLogoutUrl = builder.resolveLogoutUrl;
  }

  public String getSessionId() {
    return sessionId;
  }

  public void setSessionId(String sessionId) {
    this.sessionId = sessionId;
  }

  public String getClientId() {
    return clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  public String getAuthorizationCode() {
    return authorizationCode;
  }

  public void setAuthorizationCode(String authorizationCode) {
    this.authorizationCode = authorizationCode;
  }

  public String getResolveLogoutUrl() {
    return resolveLogoutUrl;
  }

  public void setResolveLogoutUrl(String resolveLogoutUrl) {
    this.resolveLogoutUrl = resolveLogoutUrl;
  }

  public static class Builder {
    private String sessionId;
    private String clientId;
    private String authorizationCode;
    private String resolveLogoutUrl;

    public SLOClientInfo.Builder clientId(String clientId) {
      this.clientId = clientId;
      return this;
    }

    public SLOClientInfo.Builder authorizationCode(String authorizationCode) {
      this.authorizationCode = authorizationCode;
      return this;
    }

    public SLOClientInfo.Builder resolveLogoutUrl(String resolveLogoutUrl) {
      this.resolveLogoutUrl = resolveLogoutUrl;
      return this;
    }

    public SLOClientInfo.Builder sessionId(String sessionId) {
      this.sessionId = sessionId;
      return this;
    }

    public SLOClientInfo build() {
      return new SLOClientInfo(this);
    }

  }

}
