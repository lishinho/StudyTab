package io.transwarp.guardian.federation.utils.common.logout;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;

import static io.transwarp.guardian.federation.utils.oauth2.UtilConstants.SLO_SESSION_ID_ATTRIBUTE;

public class HashMapClientSessionMappingStorage implements ClientSessionMappingStorage {

  /** Logger instance */
  private static final Logger LOG = LoggerFactory.getLogger(HashMapClientSessionMappingStorage.class);

  /** Maps the grant code from the OAuth2 server to the Session. */
  private final Map<String, HttpSession> codeToSessionMap = new HashMap<>();

  /** Maps the Session ID to the grant code from the OAuth2 Server. */
  private final Map<String, String> sessionIdToCodeMap = new HashMap<>();

  @Override
  public synchronized HttpSession removeByMappingId(String mappingId) {
    final HttpSession session = codeToSessionMap.get(mappingId);

    if (null != session) {
      removeBySessionId(transferSessionId(session));
    }

    return session;
  }

  @Override
  public synchronized void removeBySessionId(String sessionId) {
    LOG.debug("Attempting to remove Session=[{}]", sessionId);

    String key = sessionIdToCodeMap.get(sessionId);

    if (!StringUtils.isEmpty(key)) {
      LOG.debug("Found mapping for session.  Session Removed.");
      codeToSessionMap.remove(key);
      sessionIdToCodeMap.remove(sessionId);
    }
  }

  @Override
  public synchronized void addSessionByMappingId(String mappingId, HttpSession session) {
    session.setAttribute(SLO_SESSION_ID_ATTRIBUTE, session.getId());
    sessionIdToCodeMap.put((String) session.getAttribute(SLO_SESSION_ID_ATTRIBUTE), mappingId);
    codeToSessionMap.put(mappingId, session);
  }

  // In case of changing session id in other filters
  protected String transferSessionId(HttpSession session) {
    String sessionId = session.getId();
    try {
      sessionId = StringUtils.isEmpty(session.getAttribute(SLO_SESSION_ID_ATTRIBUTE)) ?
        sessionId : (String) session.getAttribute(SLO_SESSION_ID_ATTRIBUTE);
    } catch (final Exception e) {
      // let session id go and do nothing to avoid invalidated session
    }
    return sessionId;
  }
}
