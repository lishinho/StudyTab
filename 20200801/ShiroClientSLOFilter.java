package io.transwarp.guardian.federation.utils.common.logout;

import org.apache.commons.lang.StringUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionException;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.servlet.AdviceFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ShiroClientSLOFilter extends AdviceFilter {
  private final Logger LOG = LoggerFactory.getLogger(ShiroClientSLOFilter.class);
  private static final ClientSingleLogoutHandler HANDLER = new ClientSingleLogoutHandler();

  private SessionManager sessionManager;

  public void setSessionManager(SessionManager sessionManager) {
    this.sessionManager = sessionManager;
  }

  @Override
  protected boolean preHandle(ServletRequest req, ServletResponse res) throws Exception {
    final HttpServletRequest request = (HttpServletRequest) req;
    final HttpServletResponse response = (HttpServletResponse) res;

    if (HANDLER.process(request, response)) {
      return true;
    }
    Subject subject = SecurityUtils.getSubject();
    Session session = subject.getSession(false);
    if (session != null) {
      try {
        subject.logout();
      } catch (SessionException se) {
        LOG.debug("Caught session exception during logout", se);
      }
    }
    return false;
  }
}
