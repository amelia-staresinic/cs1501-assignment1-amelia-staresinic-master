import java.util.*;

public final class ChainValidator {

    /**
     * Validate a proposed chain of hops against the scenario and rules.
     */
    public static boolean validateChain(
            ScenarioFactory.Scenario scenario,
            SystemInfo start,
            SystemInfo target,
            List<Hop> chain) {
        return validateChainReason(scenario, start, target, chain).isEmpty();
    }

    /**
     * Same as validateChain, but returns an Optional<String> with a reason when
     * invalid.
     */
    public static Optional<String> validateChainReason(
            ScenarioFactory.Scenario scenario,
            SystemInfo start,
            SystemInfo target,
            List<Hop> chain) {

        Objects.requireNonNull(scenario, "scenario");
        Objects.requireNonNull(start, "start");
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(chain, "chain");

        // Lookup helpers
        Map<String, SystemInfo> byName = new HashMap<>();
        for (SystemInfo s : scenario.systems)
            byName.put(s.name, s);

        Map<String, Exploit> exploitByName = new HashMap<>();
        for (Exploit e : scenario.exploits)
            exploitByName.put(e.name, e);

        // Clone mutable state so we don't mutate the original scenario objects
        Map<String, Priv> priv = new HashMap<>();
        for (SystemInfo s : scenario.systems)
            priv.put(s.name, s.priv);

        // Attacker inventory starts empty (system creds are NOT in inventory until
        // looted)
        Set<String> inventory = new HashSet<>();

        // Reuse accounting
        Map<String, Integer> globalUseCount = new HashMap<>(); // for LIMITED(n)
        Map<String, Set<String>> usedOncePerSystem = new HashMap<>(); // exploitName -> set of system names

        // Track lateral visits to enforce "no revisit" for different systems
        Set<String> visitedSystems = new HashSet<>();
        visitedSystems.add(start.name);

        // Current system (we simulate forward)
        SystemInfo current = start;

        // Must not already be at target unless chain is empty (allowed: start==target
        // and chain empty)
        if (current == target && !chain.isEmpty()) {
            return Optional.of("Target is already at start; chain must be empty per stop-at-target rule.");
        }

        for (int i = 0; i < chain.size(); i++) {
            Hop h = chain.get(i);

            // 1) Hop endpoints must match current position
            if (!h.from.equals(current.name)) {
                return Optional.of("Hop " + i + " starts at '" + h.from +
                        "', but current system is '" + current.name + "'.");
            }

            // Determine local vs lateral by endpoints
            boolean isLocal = h.from.equals(h.to);
            if (isLocal && !"LOCAL".equals(h.viaService)) {
                return Optional.of("Hop " + i + " is local; viaService must be 'LOCAL'.");
            }
            if (!isLocal && "LOCAL".equals(h.viaService)) {
                return Optional.of("Hop " + i + " is lateral; viaService must not be 'LOCAL'.");
            }

            // 2) Exploit must exist
            Exploit ex = exploitByName.get(h.viaExploit);
            if (ex == null) {
                return Optional.of("Hop " + i + " uses unknown exploit '" + h.viaExploit + "'.");
            }

            // 3) If local, requiredService must be null/empty; if lateral, must match
            // viaService
            if (isLocal) {
                if (ex.requiredService != null && !ex.requiredService.isEmpty()) {
                    return Optional.of("Hop " + i + " is local but exploit requires a service: " + ex.requiredService);
                }
            } else {
                if (ex.requiredService == null || ex.requiredService.isEmpty()) {
                    return Optional.of("Hop " + i + " is lateral but exploit is local-only (no requiredService).");
                }
                if (!ex.requiredService.equals(h.viaService)) {
                    return Optional.of("Hop " + i + " viaService '" + h.viaService +
                            "' does not match exploit requiredService '" + ex.requiredService + "'.");
                }
            }

            // 4) Resolve target system of hop
            SystemInfo toSys = byName.get(h.to);
            if (toSys == null) {
                return Optional.of("Hop " + i + " references unknown system '" + h.to + "'.");
            }

            // 5) Preconditions
            // Privilege on source
            if (!hasPrivAtLeast(priv.get(current.name), ex.requiredPrivOnSource)) {
                return Optional.of("Hop " + i + " fails privilege precondition on source system '" +
                        current.name + "'.");
            }

            // Credential tag check against attacker inventory (not system store)
            if (ex.requiredCredTag != null && !ex.requiredCredTag.isEmpty()) {
                boolean ok = inventory.stream().anyMatch(c -> c.startsWith(ex.requiredCredTag));
                if (!ok) {
                    return Optional.of("Hop " + i + " requires a credential starting with '" +
                            ex.requiredCredTag + "' in attacker inventory.");
                }
            }

            // OS substring check
            if (ex.osContains != null && !ex.osContains.isEmpty()) {
                String osStr = (isLocal ? current.os : toSys.os);
                if (osStr == null || !osStr.contains(ex.osContains)) {
                    return Optional.of("Hop " + i + " fails OS substring check '" + ex.osContains + "'.");
                }
            }

            if (!isLocal) {
                // Route must exist from current -> toSys with service allowed
                Route route = findRouteAllowing(current, toSys, h.viaService);
                if (route == null) {
                    return Optional.of("Hop " + i + " has no route allowing service '" +
                            h.viaService + "' from '" + current.name + "' to '" + toSys.name + "'.");
                }
                // Target system must run that service
                if (!toSys.services.contains(h.viaService)) {
                    return Optional.of("Hop " + i + " requires service '" + h.viaService +
                            "' on target '" + toSys.name + "', but it is not running.");
                }
            }

            // Reuse policy check
            String exName = ex.name;
            switch (ex.reusePolicy.kind) {
                case UNLIMITED:
                    break;
                case LIMITED: {
                    int used = globalUseCount.getOrDefault(exName, 0);
                    if (used >= ex.reusePolicy.limit) {
                        return Optional.of("Hop " + i + " exceeds LIMITED(" + ex.reusePolicy.limit + ") for exploit '"
                                + exName + "'.");
                    }
                    break;
                }
                case ONCE_PER_SYSTEM: {
                    Set<String> usedOn = usedOncePerSystem.computeIfAbsent(exName, k -> new HashSet<>());
                    String scope = isLocal ? current.name : toSys.name; // count per target system
                    if (usedOn.contains(scope)) {
                        return Optional.of("Hop " + i + " violates ONCE_PER_SYSTEM for exploit '" + exName +
                                "' on system '" + scope + "'.");
                    }
                    break;
                }
            }

            // 6) Effects (apply)
            // Reuse counters
            if (ex.reusePolicy.kind == ReusePolicy.Kind.LIMITED) {
                globalUseCount.put(exName, 1 + globalUseCount.getOrDefault(exName, 0));
            } else if (ex.reusePolicy.kind == ReusePolicy.Kind.ONCE_PER_SYSTEM) {
                String scope = isLocal ? current.name : toSys.name;
                usedOncePerSystem.computeIfAbsent(exName, k -> new HashSet<>()).add(scope);
            }

            // Priv gain
            if (ex.gainPrivOnTarget != null) {
                String targetName = isLocal ? current.name : toSys.name;
                Priv newPriv = max(priv.get(targetName), ex.gainPrivOnTarget);
                priv.put(targetName, newPriv);
            }

            // Loot creds (copy ALL creds from the (target) system store into inventory)
            if (ex.addCredsOnTarget) {
                List<String> lootFrom = isLocal ? current.creds : toSys.creds;
                inventory.addAll(lootFrom);
            }

            // 7) Move current (for lateral), enforce no-revisit for lateral nodes
            if (!isLocal) {
                if (visitedSystems.contains(toSys.name)) {
                    return Optional.of("Hop " + i + " revisits system '" + toSys.name + "', which is not allowed.");
                }
                visitedSystems.add(toSys.name);
                current = toSys;
            }

            // 8) Stop-at-target rule: if we reached target before last hop, that's okay
            // only if this is the last hop
            if (current == target && i != chain.size() - 1) {
                return Optional.of("Target '" + target.name + "' reached at hop " + i +
                        " but chain continues. Must stop immediately upon reaching target.");
            }
        }

        // Final: must end at target
        if (current != target) {
            return Optional.of("Chain does not reach the target '" + target.name + "'.");
        }

        return Optional.empty();
    }

    // ---- helpers ----

    private static boolean hasPrivAtLeast(Priv have, Priv need) {
        if (need == null)
            return true;
        return ordinal(have) >= ordinal(need);
    }

    private static int ordinal(Priv p) {
        if (p == Priv.ADMIN)
            return 2;
        if (p == Priv.USER)
            return 1;
        return 0; // NONE
    }

    private static Priv max(Priv a, Priv b) {
        return ordinal(a) >= ordinal(b) ? a : b;
    }

    private static Route findRouteAllowing(SystemInfo from, SystemInfo to, String svc) {
        for (Route r : from.routes) {
            if (r.to.name.equals(to.name) && r.allow.contains(svc))
                return r;
        }
        return null;
    }
}
