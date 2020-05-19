package io.transwarp.guardian.federation.logout;

import io.transwarp.guardian.federation.persistence.model.SLOClientInfoRo;

import javax.servlet.http.HttpSession;
import java.util.List;

public interface ServerSessionMappingStorage {

  /**
   * put a session with its produced mappingId.
   * @param mappingId the mappingId is the grant code sent to client.
   * @param sloClient
   * @param session the id of the HttpSession.   */
  void registerSession(String mappingId, SLOClientInfoRo sloClient, HttpSession session);

  /**
   * get mappingId by destroyed session.
   * @param sessionId sessionId to get mapping Id from.
   */
  List<String> getMappingIds(String sessionId);

  /**
   * get clientId by mappingId to create determine url.
   * @param mappingId the token mapping to the clientId.
   */
  SLOClientInfoRo getClientInfo(String mappingId);

  /**
   * Remove data by sessionId.
   * @param sessionId the id of the session.
   */
  void removeBySessionId(String sessionId);

}
