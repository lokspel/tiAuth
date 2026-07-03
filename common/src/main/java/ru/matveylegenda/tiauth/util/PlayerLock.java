package ru.matveylegenda.tiauth.util;

import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

public class PlayerLock {

    private final Set<String> locked = ConcurrentHashMap.newKeySet();

    public void unlock(String name) {
        locked.remove(name);
    }

    public CompletableFuture<Void> execute(String name, Supplier<CompletableFuture<Void>> action) {
        if (!locked.add(name)) {
            return CompletableFuture.completedFuture(null);
        }
        try {
            return action.get().whenComplete((r, t) -> locked.remove(name));
        } catch (Exception e) {
            locked.remove(name);
            throw e;
        }
    }
}
