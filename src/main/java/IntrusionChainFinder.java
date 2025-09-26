import java.util.*;

public final class IntrusionChainFinder {

  /**
   * Perform a recursive backtracking search to find all valid chains from start to target.
   * A chain stops immediately upon first reaching target.
   *
   * @param scenario the scenario containing all systems and exploits
   * @param start    the system where the attacker begins
   * @param target   the system the attacker is trying to reach
   * @param maxHops  maximum number of hops allowed in a chain
   * @return a list of valid chains (each chain is a list of Hop objects)
   */
  public static List<List<Hop>> findChains(
      ScenarioFactory.Scenario scenario,
      SystemInfo start,
      SystemInfo target,
      int maxHops) {
    
    //initialize array for all chains
    List<List<Hop>> solutions = new ArrayList<>();

    //initialize attacker's global states
    Set<String> attackerCreds = new HashSet<>();
    if(start.creds != null){
      attackerCreds.addAll(start.creds);
    }
    Map<String, Priv> attackerPriv = new HashMap<>();
    for(SystemInfo s : scenario.systems){
      attackerPriv.put(s.name, s.priv == null ? Priv.NONE : s.priv);
    }
    attackerPriv.put(start.name, start.priv == null ? Priv.NONE : start.priv);

    //initialize reuse count and  visited systems
    Map<String, Integer> exploitReuseCnt = new HashMap<>();
    Map<String, Set<String>> usedPerSystem = new HashMap<>();
    for (Exploit e : scenario.exploits) usedPerSystem.put(e.name, new HashSet<>());

    Set<String> visited = new HashSet<>();
    visited.add(start.name);

    //intial solution chain array
    ArrayList<Hop> singleChain = new ArrayList<>();

    doFindChain(scenario, start, target, start, maxHops, singleChain, solutions, attackerCreds, attackerPriv, usedPerSystem, exploitReuseCnt, visited);
    
    //sort final solutions
    solutions.sort(
      Comparator
          .comparing((List<Hop> c) -> chainKey(c))
          .thenComparingInt(List::size)
    );

    return solutions;
  }

  //recursive helper method to find all possible chains
  public static void doFindChain(ScenarioFactory.Scenario scenario, SystemInfo start, SystemInfo target, SystemInfo current, 
  int maxHops, List<Hop> singleChain, List<List<Hop>> solutions, Set<String> attackerCreds, Map<String, Priv> attackerPriv, 
  Map<String, Set<String>> usedPerSystem, Map<String, Integer> exploitReuseCnt, Set<String> visited){

    //check if target is reached
    if(current.name.equals(target.name)){
      //sort chain
      if(!singleChain.isEmpty()){
        solutions.add(new ArrayList<>(singleChain));
      }
      return;
    }
    //check if hops are maxxed out
    if(singleChain.size() >= maxHops){
      return;
    }

    for(Exploit e : scenario.exploits){
      //check if local exploit
      if (e.requiredService == ""){
        if(!checkExploit(current, e, current, attackerCreds, attackerPriv, exploitReuseCnt, usedPerSystem)){
          continue;
        }

        //save effects for recursion
        Set<String> newAttackerCreds = new HashSet<>(attackerCreds);
        Map<String, Priv> newAttackerPriv = new HashMap<>(attackerPriv);
        Map<String, Integer> newExploitReuseCnt = new HashMap<>(exploitReuseCnt);
        Map<String, Set<String>> newUsedPerSystem = deepCopyUPS(usedPerSystem);
        List<Hop> newChain = new ArrayList<>(singleChain);
        Set<String> newVisited = new HashSet<>(visited);

        //apply effects, add to chain, and recurse
        applyExploit(current, e, newAttackerCreds, newAttackerPriv);
        applyReuse(e, current.name, newExploitReuseCnt, newUsedPerSystem);
        //newExploitReuseCnt.put(e.name, newExploitReuseCnt.getOrDefault(e.name, 0)+1);

        Hop h = new Hop(current.name, current.name, e.name, "LOCAL");
        newChain.add(h);

        doFindChain(scenario, start, target, current, maxHops, newChain, solutions, newAttackerCreds, newAttackerPriv, newUsedPerSystem, newExploitReuseCnt, newVisited);
      
      }
      else{
        //lateral exploit
        //sort routes deterministically
        List<Route> routes = new ArrayList<>(current.routes);
        routes.sort(Comparator.comparing(r -> r.to.name));

        for(Route r : routes){
          SystemInfo connection = r.to;
          //skip visited or disallowed routes
          if(visited.contains(connection.name)){
            continue;
          }
          if(!r.allow.contains(e.requiredService)){
            continue;
          }
          if(!connection.services.contains(e.requiredService)){
            continue;
          }
          if(!checkExploit(current, e, connection, attackerCreds, attackerPriv, exploitReuseCnt, usedPerSystem)){
            continue;
          }

          //save effects for recursion
          Set<String> newAttackerCreds = new HashSet<>(attackerCreds);
          Map<String, Priv> newAttackerPriv = new HashMap<>(attackerPriv);
          Map<String, Integer> newExploitReuseCnt = new HashMap<>(exploitReuseCnt);
          Map<String, Set<String>> newUsedPerSystem = deepCopyUPS(usedPerSystem);
          List<Hop> newChain = new ArrayList<>(singleChain);
          Set<String> newVisited = new HashSet<>(visited);

          //apply effects, add to chain, and recurse
          applyExploit(connection, e, newAttackerCreds, newAttackerPriv); //apply exploit and save effects
          applyReuse(e, connection.name, newExploitReuseCnt, newUsedPerSystem);
          //newExploitReuseCnt.put(e.name, newExploitReuseCnt.getOrDefault(e.name, 0)+1);

          Hop h = new Hop(current.name, connection.name, e.name, e.requiredService);
          newChain.add(h);
          newVisited.add(connection.name);

          doFindChain(scenario, start, target, connection, maxHops, newChain, solutions, newAttackerCreds, newAttackerPriv, newUsedPerSystem, newExploitReuseCnt, newVisited);

          newVisited.remove(connection.name);

        }
      }
    }
  }

  public static boolean checkExploit(SystemInfo current, Exploit e, SystemInfo target, Set<String> attackerCreds, Map<String, Priv> attackerPriv, 
  Map<String, Integer> exploitReuseCnt, Map<String, Set<String>> usedPerSystem){
    
    //priv check
    Priv p = attackerPriv.getOrDefault(current.name, Priv.NONE);
    if(!comparePriv(p, e.requiredPrivOnSource)){
      return false;
    }
    //os check
    if(e.osContains != null){
      if(!target.os.contains(e.osContains)){
        return false;
      }
    }
    //creds check
    if(e.requiredCredTag != null){
      boolean credsFound = false;
      for(String cred : attackerCreds){
        if(cred.startsWith(e.requiredCredTag)){
          credsFound = true;
        }
      }
      if(!credsFound){
          return false;
      }
    }
    //reuse limit check
    if(e.reusePolicy == ReusePolicy.UNLIMITED){
      return true;
    }
    else if(e.reusePolicy == ReusePolicy.ONCE_PER_SYSTEM){
      Set<String> used = usedPerSystem.getOrDefault(e.name, Collections.emptySet());
      if(used.contains(target.name)){
        return false;
      }
      return true;
    }
    else{
      int uses = exploitReuseCnt.getOrDefault(e.name, 0);
      if(uses >= e.reusePolicy.limit){
        return false;
      }
    }
    return true;
    }
  
  public static void applyExploit(SystemInfo target, Exploit e, Set<String> attackerCreds, Map<String, Priv> attackerPriv){
    if(e.gainPrivOnTarget != null){
      Priv p = attackerPriv.getOrDefault(target.name, Priv.NONE);
      if(comparePriv(e.gainPrivOnTarget, p)){
        attackerPriv.put(target.name, e.gainPrivOnTarget);
      }
    }
    if(e.addCredsOnTarget && target.creds != null){
      attackerCreds.addAll(target.creds);
    }
  }

  public static void applyReuse(Exploit e, String sysName, Map<String, Integer> exploitReuseCnt, Map<String, Set<String>> usedPerSystem){
    if (e.reusePolicy == ReusePolicy.UNLIMITED){
      return;
    }
    if (e.reusePolicy == ReusePolicy.ONCE_PER_SYSTEM){
      usedPerSystem.computeIfAbsent(e.name, k -> new HashSet<>()).add(sysName);
      return;
    }
    exploitReuseCnt.put(e.name, exploitReuseCnt.getOrDefault(e.name, 0)+1);
  }

  public static boolean comparePriv(Priv exploitP, Priv currP){
    if(currP == null){
      return true;
    }
    if(privRank(exploitP) >= privRank(currP)){
      return true;
    }
    return false;
  }
  private static int privRank(Priv p){
    if(p == null || p == Priv.NONE){
      return 0;
    }
    if(p == Priv.USER){
      return 1;
    }
    if(p == Priv.ADMIN){
      return 2;
    }
    return 0;
  }

  private static Map<String, Set<String>> deepCopyUPS(Map<String, Set<String>> ups){
    Map<String, Set<String>> copy = new HashMap<>();
    for (Map.Entry<String, Set<String>> e : ups.entrySet()) {
      copy.put(e.getKey(), new HashSet<>(e.getValue()));
    }
    return copy;
  }

  private static String chainKey(List<Hop> chain) {
    StringBuilder sb = new StringBuilder();
    for (Hop h : chain) {
      sb.append(h.from).append('|')
        .append(h.viaService).append('|')
        .append(h.viaExploit).append('|')
        .append(h.to).append("->");
    }
    return sb.toString();
  }

}
