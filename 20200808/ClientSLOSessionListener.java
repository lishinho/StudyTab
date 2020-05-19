package io.transwarp.guardian.federation.utils.common.logout;

import org.springframework.context.annotation.Configuration;

import javax.servlet.annotation.WebListener;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

import static io.transwarp.guardian.federation.utils.oauth2.UtilConstants.SLO_SESSION_ID_ATTRIBUTE;

@Configuration
@WebListener
public class ClientSLOSessionListener implements HttpSessionListener {
  private ClientSessionMappingStorage clientSessionMappingStorage;

  @Override
  public void sessionCreated(HttpSessionEvent se) {
    // nothing to do at the moment
  }

  @Override
  public void sessionDestroyed(HttpSessionEvent event) {
    if (clientSessionMappingStorage == null) {
      clientSessionMappingStorage = getSessionMappingStorage();
    }
    final HttpSession session = event.getSession();
    String sessionId = session.getAttribute(SLO_SESSION_ID_ATTRIBUTE) == null ?
      session.getId() : (String) session.getAttribute(SLO_SESSION_ID_ATTRIBUTE);
    clientSessionMappingStorage.removeBySessionId(sessionId);

  }

  /**
   * Obtains a {@link ClientSessionMappingStorage} object. Assumes this method will always return the same
   * instance of the object.  It assumes this because it generally lazily calls the method.
   *
   * @return the SessionMappingStorage
   */
  protected static ClientSessionMappingStorage getSessionMappingStorage() {
    return ClientSingleLogoutFilter.getSingleSignOutHandler().getClientSessionMappingStorage();
  }
}
