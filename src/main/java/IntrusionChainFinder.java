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

    // TODO: implement recursive backtracking search using a helper recursive method
    List<List<Hop>> solutions = new ArrayList<>();
    //attacker's global states
    Set<Priv> attackerPrivs = new HashSet<>();
    attackerPrivs.add(start.priv);
    Set<String> attackerState = new HashSet<>(start.creds);
    attackerState.add(start.priv.toString());

    Map<String, Integer> exploitReuseCnt = new HashMap<>();
    Set<String> visited = new HashSet<>();
    visited.add(start.name);

    //intial chain array
    ArrayList<Hop> singleChain = new ArrayList<>();

    solutions = doFindChain(scenario, start, target, start, maxHops, singleChain, solutions, attackerState, exploitReuseCnt, visited);
    
   //sort solutions

    return solutions;
  }
  public static List<List<Hop>> doFindChain(ScenarioFactory.Scenario scenario, SystemInfo start, SystemInfo target, SystemInfo current, int maxHops, List<Hop> singleChain, List<List<Hop>> solutions, 
  Set<String> attackerState, Map<String, Integer> exploitReuseCnt, Set<String> visited){
    if(current == target){
      //sort chain
      solutions.add(singleChain);
      return solutions;
    }
    if(singleChain.size() >= maxHops){
      return solutions;
    }
    for(Exploit e : scenario.exploits){
      if (e.requiredService == ""){
        if(!checkExploit(current, e, current, attackerState, exploitReuseCnt)){
          continue;
        }
        exploitReuseCnt.put(e.name, 1);
        Hop h = new Hop(current.name, current.name, e.name, "LOCAL");
        attackerState = applyExploit(current, e, attackerState); //apply exploit and save effects - return new privs, creds
        exploitReuseCnt.put(e.name, exploitReuseCnt.getOrDefault(e.name, 0)+1);
        singleChain.add(h);
        doFindChain(scenario, start, target, current, maxHops, singleChain, solutions, attackerState, exploitReuseCnt, visited);
        
        singleChain.removeLast();
        //undo effects: revert attacker creds and priv, revert exploit use counters
      }
      else{

        for(Route r : current.routes){ //for each possbile route connecting current to something else
          SystemInfo connection = r.to;
          if(!connection.services.contains(e.requiredService)){
            continue;
          }
          if(visited.contains(connection.name)){
            continue;
          }
          if(!checkExploit(current, e, connection, attackerState, exploitReuseCnt)){
            continue;
          }
          Hop h = new Hop(current.name, connection.name, e.name, "LATERAL");
          attackerState = applyExploit(connection, e, attackerState); //apply exploit and save effects
          visited.add(connection.name);
          exploitReuseCnt.put(e.name, exploitReuseCnt.getOrDefault(e.name, 0)+1);
          singleChain.add(h);
          doFindChain(scenario, start, target, connection, maxHops, singleChain, solutions, attackerState, exploitReuseCnt, visited);

          singleChain.removeLast();
          //undo effects
          

        }
      }
    }
    return solutions;

  }

  public static boolean checkExploit(SystemInfo current, Exploit e, SystemInfo target, Set<String> attackerState, Map<String, Integer> exploitReuseCnt){
    
    boolean allchecks = false;

    if(attackerState.contains(e.requiredPrivOnSource.toString())){
      allchecks = true;
    }
    if(e.osContains != null){
      if(target.os.contains(e.osContains)){
        allchecks = true;
      }
      else{
        return false;
      }
      }
    if(e.requiredCredTag != null){
      for(String cred : attackerState){
        if(cred.startsWith(e.requiredCredTag)){
          allchecks = true;
        }
      }
      if(allchecks == false){
          return false;
      }
      }
    if(exploitReuseCnt.containsKey(e.name) && exploitReuseCnt.get(e.name) >= e.reusePolicy.limit){
      return false;
    }
    return allchecks;
    }
  
  public static Set<String> applyExploit(SystemInfo current, Exploit e, Set<String> attackerState){
    if(e.gainPrivOnTarget != null){
      if(!attackerState.contains(e.gainPrivOnTarget.toString())){
        attackerState.add(e.gainPrivOnTarget.toString());
      }
    }
    if(e.addCredsOnTarget){
      for(String c : current.creds){
        attackerState.add(c);
      }
    }
    return attackerState;
  }
  public static void undoExploit(){

  }

}
