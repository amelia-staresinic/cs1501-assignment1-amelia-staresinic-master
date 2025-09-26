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
    Set<String> attackerState = new HashSet<>();
    if(start.creds != null){
      attackerState.addAll(start.creds);
    }
    if(start.priv != null){
      attackerState.add(start.priv.toString());
    }

    //initialize reuse count and  visited systems
    Map<String, Integer> exploitReuseCnt = new HashMap<>();
    Set<String> visited = new HashSet<>();
    visited.add(start.name);

    //intial solution chain array
    ArrayList<Hop> singleChain = new ArrayList<>();

    doFindChain(scenario, start, target, start, maxHops, singleChain, solutions, attackerState, exploitReuseCnt, visited);
    
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
  int maxHops, List<Hop> singleChain, List<List<Hop>> solutions, Set<String> attackerState, Map<String, Integer> exploitReuseCnt, 
  Set<String> visited){

    //check if target is reached
    if(current.name == target.name){
      //sort chain
      solutions.add(new ArrayList<>(singleChain));
      return;
    }
    //check if hops are maxxed out
    if(singleChain.size() >= maxHops){
      return;
    }

    for(Exploit e : scenario.exploits){
      //check if local exploit
      if (e.requiredService == ""){
        if(!checkExploit(current, e, current, attackerState, exploitReuseCnt)){
          continue;
        }
        //add exploit to reuse count
        exploitReuseCnt.put(e.name, 1);

        //save effects for recursion
        Set<String> newAttackerState = new HashSet<>(attackerState);
        Map<String, Integer> newExploitReuseCnt = new HashMap<>(exploitReuseCnt);
        List<Hop> newChain = new ArrayList<>(singleChain);
        Set<String> newVisited = new HashSet<>(visited);

        //apply effects, add to chain, and recurse
        applyExploit(current, e, newAttackerState);
        newExploitReuseCnt.put(e.name, newExploitReuseCnt.getOrDefault(e.name, 0)+1);

        Hop h = new Hop(current.name, current.name, e.name, "LOCAL");
        singleChain.add(h);

        doFindChain(scenario, start, target, current, maxHops, newChain, solutions, newAttackerState, newExploitReuseCnt, newVisited);
      
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
          if(!r.allow.contains(e.requiredService) || !connection.services.contains(e.requiredService)){
            continue;
          }
          if(!checkExploit(current, e, connection, attackerState, exploitReuseCnt)){
            continue;
          }

          //save effects for recursion
          Set<String> newAttackerState = new HashSet<>(attackerState);
          Map<String, Integer> newExploitReuseCnt = new HashMap<>(exploitReuseCnt);
          List<Hop> newChain = new ArrayList<>(singleChain);
          Set<String> newVisited = new HashSet<>(visited);

          //apply effects, add to chain, and recurse
          applyExploit(connection, e, newAttackerState); //apply exploit and save effects
          newExploitReuseCnt.put(e.name, newExploitReuseCnt.getOrDefault(e.name, 0)+1);

          Hop h = new Hop(current.name, connection.name, e.name, e.requiredService);
          newChain.add(h);
          newVisited.add(connection.name);

          doFindChain(scenario, start, target, connection, maxHops, newChain, solutions, newAttackerState, newExploitReuseCnt, newVisited);

        }
      }
    }
  }

  public static boolean checkExploit(SystemInfo current, Exploit e, SystemInfo target, Set<String> attackerState, Map<String, Integer> exploitReuseCnt){
    
    //priv check
    if(!attackerState.contains(e.requiredPrivOnSource.toString())){
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
      for(String cred : attackerState){
        if(cred.startsWith(e.requiredCredTag)){
          credsFound = true;
        }
      }
      if(!credsFound){
          return false;
      }
    }
    //reuse limit check
    if(exploitReuseCnt.containsKey(e.name) && exploitReuseCnt.get(e.name) >= e.reusePolicy.limit){
      return false;
    }
    return true;
    }
  
  public static void applyExploit(SystemInfo target, Exploit e, Set<String> attackerState){
    if(e.gainPrivOnTarget != null){
      if(!attackerState.contains(e.gainPrivOnTarget.toString())){
        attackerState.add(e.gainPrivOnTarget.toString());
      }
    }
    if(e.addCredsOnTarget && target.creds != null){
      attackerState.addAll(target.creds);
    }
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
