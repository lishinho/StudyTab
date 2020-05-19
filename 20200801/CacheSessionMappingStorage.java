package io.transwarp.guardian.federation.logout;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import io.transwarp.guardian.federation.persistence.model.SLOClientInfoRo;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.CollectionUtils;

import javax.servlet.http.HttpSession;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class CacheSessionMappingStorage implements ServerSessionMappingStorage {
  private static final Logger LOG = LoggerFactory.getLogger(CacheSessionMappingStorage.class);

  private String name;
  private long maximumSize;
  private long expireAfterAccess;
  private long expireAfterWrite;
  private boolean keyCaseSensitive;
  private Cache<String, List<String>> sessionMappingIdCache;
  private Cache<String, SLOClientInfoRo> mappingIdClientCache;

  private CacheSessionMappingStorage(CacheSessionMappingStorage.Builder builder) {
    this.name = builder.name;
    this.maximumSize = builder.maximumSize;
    this.expireAfterAccess = builder.expireAfterAccess;
    this.expireAfterWrite = builder.expireAfterWrite;
    this.keyCaseSensitive = builder.keyCaseSensitive;
    buildCache();
  }

  @Override
  public synchronized void registerSession(String mappingId, SLOClientInfoRo sloClient, HttpSession session) {
    String sessionId = session.getId();
    if (CollectionUtils.isEmpty(sessionMappingIdCache.getIfPresent(sessionId))) {
      List<String> mappingIds = new ArrayList<>();
      mappingIds.add(mappingId);
      sessionMappingIdCache.put(sessionId, mappingIds);
    } else {
      sessionMappingIdCache.getIfPresent(sessionId).add(mappingId);
    }

    mappingIdClientCache.put(mappingId, sloClient);
  }

  @Override
  public synchronized List<String> getMappingIds(String sessionId) {
    if (null != sessionId) {
      return sessionMappingIdCache.getIfPresent(sessionId);
    }
    return Collections.emptyList();
  }

  @Override
  public synchronized SLOClientInfoRo getClientInfo(String grantCode) {
    if (null != grantCode) {
      LOG.debug("mappingId is not null");
      return mappingIdClientCache.getIfPresent(grantCode);
    }
    return null;
  }

  @Override
  public synchronized void removeBySessionId(String sessionId) {
    for (String token: sessionMappingIdCache.getIfPresent(sessionId)) {
      mappingIdClientCache.invalidate(token);
    }
    sessionMappingIdCache.invalidate(sessionId);
  }

  private void buildCache() {
    sessionMappingIdCache = CacheBuilder.newBuilder()
      .maximumSize(maximumSize)
      .expireAfterAccess(expireAfterAccess, TimeUnit.SECONDS)
      .expireAfterWrite(expireAfterWrite, TimeUnit.SECONDS)
      .build();

    mappingIdClientCache = CacheBuilder.newBuilder()
      .maximumSize(maximumSize)
      .expireAfterAccess(expireAfterAccess, TimeUnit.SECONDS)
      .expireAfterWrite(expireAfterWrite, TimeUnit.SECONDS)
      .build();

    String cacheInfo = new StringBuilder()
      .append(name)
      .append(" info: maximumSize=")
      .append(maximumSize)
      .append(", expireAfterAccess=")
      .append(expireAfterAccess)
      .append("s, expireAfterWrite=")
      .append(expireAfterWrite)
      .append("s, keyCaseSensitive=")
      .append(keyCaseSensitive)
      .toString();
    LOG.info(cacheInfo);
  }

  public static class Builder {
    private long maximumSize = 300L;
    private long expireAfterAccess = 30L;
    private long expireAfterWrite = 60L;
    private boolean keyCaseSensitive = true;
    private String name = "Cache";

    public CacheSessionMappingStorage.Builder name(String name) {
      if (!StringUtils.isEmpty(name)) {
        this.name = name;
      }
      return this;
    }

    public CacheSessionMappingStorage.Builder maximumSize(long maximumSize) {
      if (maximumSize > 0) {
        this.maximumSize = maximumSize;
      }
      return this;
    }

    public CacheSessionMappingStorage.Builder expireAfterAccess(long expireAfterAccess) {
      if (expireAfterAccess > 0) {
        this.expireAfterAccess = expireAfterAccess;
      }
      return this;
    }

    public CacheSessionMappingStorage.Builder expireAfterWrite(long expireAfterWrite) {
      if (expireAfterWrite > 0) {
        this.expireAfterWrite = expireAfterWrite;
      }
      return this;
    }

    public CacheSessionMappingStorage.Builder keyCaseSensitive(boolean keyCaseSensitive) {
      this.keyCaseSensitive = keyCaseSensitive;
      return this;
    }

    public CacheSessionMappingStorage build() {
      return new CacheSessionMappingStorage(this);
    }
  }

}
