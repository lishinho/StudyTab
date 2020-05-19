package io.transwarp.guardian.federation.logout;

import io.transwarp.guardian.federation.persistence.model.SLOClientInfoRo;

import javax.servlet.http.HttpSession;
import java.util.ArrayList;
import java.util.List;

public class AttributeSessionMappingStorage implements ServerSessionMappingStorage {

  public static final String SESSION_MAPPING_ID_ATTR = "sessionMappingIds";

  @Override
  public void registerSession(String mappingId, SLOClientInfoRo sloClient, HttpSession session) {
    List<String> list = new ArrayList<>();
    if (session.getAttribute(SESSION_MAPPING_ID_ATTR) != null) {
      list = (List<String>) session.getAttribute(SESSION_MAPPING_ID_ATTR);
    }
    list.add(mappingId);
    session.setAttribute(SESSION_MAPPING_ID_ATTR, list);
    session.setAttribute(mappingId, sloClient);
  }

  @Override
  public List<String> getMappingIds(HttpSession session) {
    // find grant codes
    return (List<String>) session.getAttribute(SESSION_MAPPING_ID_ATTR);
  }

  @Override
  public SLOClientInfoRo getClientInfo(String mappingId) {
    return null;
  }

  @Override
  public void removeBySessionId(String sessionId) {

  }
}
