package io.transwarp.guardian.federation.logout;

import org.jetbrains.annotations.NotNull;

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

public class ServerSLOThreadFactory implements ThreadFactory {

  private final AtomicInteger threadNumber = new AtomicInteger(1);

  private final String namePrefix;

  ServerSLOThreadFactory(String namePrefix) {
    this.namePrefix = namePrefix + "-";
  }


  @Override
  public Thread newThread(@NotNull Runnable runnable) {
    Thread t = new Thread(runnable, namePrefix + threadNumber.getAndIncrement());
    t.setDaemon(true);
    return t;
  }
}
