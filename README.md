# CS 1501 – Assignment 1: Intrusion Chain Finder (Backtracking with Local and Lateral Exploits)

> **Note:** This assignment was developed with the help of OpenAI ChatGPT to brainstorm and generate parts of the scaffolding and documentation files to speedup prototyping.

## Overview

In this assignment, you will build a tool called the **Intrusion Chain Finder**.
The goal is to practice **recursive backtracking**: systematically exploring all possible sequences of steps ("chains") that an attacker might use to move through a network of computer systems.

### Motivation

* In cybersecurity, defenders often ask: *“Given what an attacker starts with, can they reach the critical system?”*
* Although this assignment is not a hacking lab — the **exploits here are simplified models** and are **not accurate representations** of real attacks, they give us a structured way to practice:

  * **constraint checking** (is a move valid?),
  * **state changes** (privilege gains, new credentials),
  * **backtracking** (undoing choices when a path fails).

This assignment gives you a cybersecurity **flavor** while keeping the focus on algorithmic thinking.

---

### Core Concepts

* **Systems**: machines in the network, each with:

  * services they run (like SMB or SSH),
  * credentials *stored on that system* (what you could loot there),
  * your current privilege level there (`NONE`, `USER`, or `ADMIN`).

* **Routes**: connections between systems. Each route specifies which services are allowed across that link (like firewall rules).

* **Exploits**: actions you can take. Each has:

  * **preconditions** (what privilege you need on the source, what service must run on the target, what services are allowed on the route, and possibly a credential),
  * **effects** (what privilege you gain on the target, and/or new credentials you loot).

**Types of Exploits**  
- **Local exploits**: run on the same system you already have access to; they raise your privilege level on that system (e.g., USER → ADMIN).  
- **Lateral exploits**: move you from one system to another, requiring a service running on the target and permission on the route.  

**Exploit Reuse Limits**: Each exploit has a **reuse policy** that controls how many times it may be applied in a chain:

- **ONCE_PER_SYSTEM**: the exploit can only be used once on each system (e.g., a crash bug that disables the service after first use).  
- **LIMITED(n)**: the exploit can be used at most *n* times across the whole chain (e.g., a noisy attack that defenders will notice if repeated).  
- **UNLIMITED**: the exploit can be used any number of times without restriction.

**Privileges (priv) vs. Credentials (creds)**  
- **Privileges (priv)**: describe what level of control you currently have on a system (`NONE`, `USER`, or `ADMIN`).  
- **Credentials (creds)**: represent account information (e.g., username and password) you have discovered; they allow you to attempt lateral exploits against other systems.  

* **Hops**: one step in a chain, recorded as:

  ```
  FROM --(exploit via service)--> TO
  ```

* **Chains**: sequences of hops that start at a given system and end at the target system. Your algorithm must find **all valid chains** within the constraints.

---
### Example Scenario

**Goal:** Start at **EMP-LAPTOP** (attacker has `USER`) and reach **PAYROLL-DB**.  
As soon as **PAYROLL-DB** is reached, the chain **stops immediately** (no further local steps on the target).

---

**Systems**

- **EMP-LAPTOP**  
  - OS: Windows 10  
  - Version: 10.0.19044  
  - Services: `browser`  
  - Credentials: `emp@corp`  
  - Privilege: `USER`

- **FILE-SRV**  
  - OS: Windows Server 2019  
  - Version: 10.0.17763  
  - Services: `SMB`, `WinRM`  
  - Credentials: `svc-backup`  
  - Privilege: `NONE`

- **PAYROLL-DB** *(target)*  
  - OS: Ubuntu 20.04  
  - Version: 5.15  
  - Services: `PostgreSQL`, `SSH`  
  - Credentials: `svc-payroll`  
  - Privilege: `NONE`

---

**Routes**

- EMP-LAPTOP → FILE-SRV: allows `SMB`, `HTTP`  
- FILE-SRV → PAYROLL-DB: allows `SSH`, `WinRM`

---

**Exploits (with reuse policies)**

- **SMBGhost** (lateral)  
  - `requiredService = "SMB"`  
  - `requiredPrivOnSource = USER`  
  - `gainPrivOnTarget = ADMIN`  
  - `addCredsOnTarget = false`  
  - `reusePolicy = ONCE_PER_SYSTEM`

- **LootCreds** (local)  
  - `requiredService = ""` (local)  
  - `requiredPrivOnSource = ADMIN`  
  - `gainPrivOnTarget = ADMIN`  
  - `addCredsOnTarget = true`  *(copies all creds from that system’s store into attacker's inventory of credentials)*  
  - `reusePolicy = UNLIMITED`

- **PassTheHash** (lateral)  
  - `requiredService = "SSH"`  
  - `requiredPrivOnSource = USER`  
  - `requiredCredTag = "svc-"`  
  - `gainPrivOnTarget = USER`  
  - `addCredsOnTarget = false`  
  - `reusePolicy = LIMITED(2)`

---

**Chain Walkthrough (terminates when target is reached)**

1. From **EMP-LAPTOP (USER)**, run **SMBGhost** via `SMB` → land on **FILE-SRV** with `ADMIN`.  
   - (SMBGhost on FILE-SRV is now exhausted due to `ONCE_PER_SYSTEM`.)

2. On **FILE-SRV (ADMIN)**, run **LootCreds** (local) → copy `svc-backup` from FILE-SRV’s store into the attacker’s inventory.  
   - (LootCreds is `UNLIMITED`, but repeating won’t add new creds.)

3. From **FILE-SRV (ADMIN)**, run **PassTheHash** via `SSH` using `svc-backup` → reach **PAYROLL-DB**.  
   - **Target reached → STOP.**  
   - (PassTheHash’s `LIMITED(2)` budget is decremented by one for this chain exploration.)

---

**Result:**  
This chain is valid because each hop satisfied preconditions (source privilege, allowed service on route, service on target, credential tag).  
The chain **ends** at **PAYROLL-DB**.

Your job: write the recursive search that discovers **all such valid paths**, respecting limits like max hops and no revisits.



## Required Task

Your main job in this assignment is to **implement one method** inside `IntrusionChainFinder.java`.
This method performs a recursive backtracking search to discover all valid intrusion chains.

```java
public static List<List<Hop>> findChains(
    ScenarioFactory.Scenario scenario,
    SystemInfo start,
    SystemInfo target,
    int maxHops)
```

### Parameters

* **`ScenarioFactory.Scenario scenario`**: the complete scenario, containing all systems and exploits.
* **`SystemInfo start`**: the system where the attacker begins. The attacker may already have some privilege and credentials here.
* **`SystemInfo target`**: the system the attacker is trying to reach.
* **`int maxHops`**: maximum number of steps (hops) allowed in a chain. If a chain exceeds this length, it must be abandoned (pruned).

### Return Value

* A list of valid **chains**.
* Each chain is a list of `Hop` objects.
* Each `Hop` records:

  * the system you came **from**,
  * the system you moved **to**,
  * the **exploit** used,
  * and the **service** used on the route.

* Local exploits are recorded as **hops where `from` and `to` are the same system** and the `viaService` field should be set to `"LOCAL"`.  
* Example hop for a local exploit:  `Hop(from="FILE-SRV", to="FILE-SRV", viaExploit="LootCreds", viaService="LOCAL")`

* Example Chain (Small Scenario) from **EMP-LAPTOP** to **PAYROLL-DB** (stopping immediately upon reaching the target):

1. `Hop(from="EMP-LAPTOP", to="FILE-SRV", viaExploit="SMBGhost", viaService="SMB")`  
2. `Hop(from="FILE-SRV", to="FILE-SRV", viaExploit="LootCreds", viaService="LOCAL")`  
3. `Hop(from="FILE-SRV", to="PAYROLL-DB", viaExploit="PassTheHash", viaService="SSH")`

This chain shows both **lateral movement** (EMP-LAPTOP → FILE-SRV and FILE-SRV → PAYROLL-DB) and the **local exploit** (LootCreds on FILE-SRV).

### Rules

* A chain is valid if it starts at `start` and ends **exactly when the target is first reached**.
* Once the target is reached, the chain stops immediately (no local exploits or extra steps on the target).
* All exploit preconditions must be satisfied at the moment of use (source privilege, required service, allowed service, credential tag, OS substring).
* Exploit effects (`gainPrivOnTarget`, `addCredsOnTarget`) must be applied when the exploit succeeds.
* Exploit reuse must respect the `reusePolicy` (once per system, limited n, or unlimited).
* The attacker must **not revisit a system** in the same chain (this prevents cycles).
* Credentials looted via `addCredsOnTarget` are added to the attacker’s global inventory and persist for the rest of the chain (unless undone during backtracking).

### Output Ordering

* Chains must be generated deterministically.
* After collection, sort the chains by a **chain key** (`from|service|exploit|to->...`) so that results are consistent across runs.

#### Sample Code (Java)

```java
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

// After the backtracking collects `solutions`:
solutions.sort(
    Comparator
      .comparing((List<Hop> c) -> chainKey(c))   // primary: lexicographic key
      .thenComparingInt(List::size)              // secondary: shorter chains first
);
```

## Exploit Preconditions

Each exploit defines a set of **preconditions** that must all be satisfied before the exploit can be applied. These checks depend on whether the exploit is **local** (runs on the current system) or **lateral** (moves to a different system). If any precondition fails, the hop is invalid and must not be included in the chain.

### Local Exploit Preconditions

* **Privilege on source system**: the attacker must have at least the privilege level specified by `requiredPrivOnSource` on the current system.
* **OS check**: if `osContains` is not null, the system’s `os` string must *contain* the given substring.
* **Credential requirement**: if `requiredCredTag` is not null, the attacker’s inventory must contain at least one credential *starting with* that tag.
* **Reuse policy**: the exploit must still have available budget under its `reusePolicy`.

### Lateral Exploit Preconditions

* **Privilege on source system**: the attacker must have at least the privilege level specified by `requiredPrivOnSource` on the source system.
* **Route and service**: the exploit’s `requiredService` must be:

  * listed in the source → target route’s `allow` set, and
  * present in the target system’s `services` list.
* **OS check**: if `osContains` is not null, the target system’s `os` string must contain the given substring.
* **Credential requirement**: if `requiredCredTag` is not null, the attacker’s inventory must contain at least one credential starting with that tag.
* **Reuse policy**: the exploit must still have available budget under its `reusePolicy`.

## Exploit Effects

When an exploit succeeds, it changes the attacker’s state according to the exploit's defined **effects**. These effects apply differently for local and lateral exploits but follow the same rules. Correctly applying and undoing these effects is critical for a proper backtracking search.

### Local Exploit Effects

* **Privilege gain**: if `gainPrivOnTarget` is not null, the attacker’s privilege on the current system is raised to at least that level (e.g., USER → ADMIN). If the attacker already has higher privilege there, the higher level remains.
* **Credential looting**: if `addCredsOnTarget = true`, all credentials in the system’s local store (`SystemInfo.creds`) are copied into the attacker’s global inventory. These remain available for the rest of the chain (unless undone during backtracking).
* **Reuse accounting**: the exploit’s `reusePolicy` budget is decremented.

### Lateral Exploit Effects

* **Privilege gain**: if `gainPrivOnTarget` is not null, the attacker’s privilege on the target system is set to at least that level. If the attacker already has higher privilege there, the higher level remains.
* **Credential looting**: if `addCredsOnTarget = true`, all credentials in the target system’s local store are copied into the attacker’s global inventory.
* **Reuse accounting**: the exploit’s `reusePolicy` budget is decremented.

### Global State Updates

* **Attacker credentials inventory**: grows monotonically within a chain as new credentials are looted. During backtracking from an exploit, any creds gained in that exploit must be removed.
* **Privilege map**: each system maintains the current privilege level the attacker has there; this may increase but not decrease (except when undone during backtracking).
- **Exploit use counters**: track how many times each exploit has been applied, enforcing `reusePolicy` (ONCE_PER_SYSTEM, LIMITED(n), UNLIMITED). These counters must also be reverted during backtracking.


## 🛠️ Hints

* Use a recursive helper method for backtracking.
* Track visited systems, used exploits, and looted credentials, among others.
* **Use helper methods**: break down your implementation into small helpers, e.g., `preconditionsHold(...)`, `applyEffects(...)`, and `undoEffects(...)`. This will make it easier to reason about backtracking and undoing state changes.
* **Track state carefully**: you will need to maintain three key aspects of global state:

  1. **Privileges per system**
  2. **Attacker’s credential inventory**
  3. **Exploit use counters**

* **Backtracking discipline**: whenever you apply an effect (privilege gain, creds looted, exploit reuse counter updated), make sure you also record how to undo it. Always undo effects before returning from a recursive call.

* **Determinism**: always iterate in sorted order (routes by destination, services lexicographically, exploits by name). After collecting solutions, sort chains again by a stable key. This guarantees consistent results across runs.

* **Stop at the target**: as soon as the target system is reached, record the chain and return — do not continue applying local exploits or lateral moves beyond the target.

* **Debug with small cases**: start testing with very small scenarios (2–3 systems, 1–2 exploits) so you can trace the recursion by hand and verify the correctness of your state updates.


---
## Folder Structure

```plaintext
├─ README.md
├─ pom.xml
├─ src/
│  ├─ main/java/
│  │   ├─ SystemInfo.java
│  │   ├─ Route.java
│  │   ├─ Exploit.java
│  │   ├─ ReusePolicy.java
│  │   ├─ Hop.java
│  │   ├─ ScenarioFactory.java
│  │   └─ IntrusionChainFinder.java   # you implement the findChains method here
│  └─ test/java/
│      ├─ PublicCorpSmallMax3Test.java
│      └─ PublicCorpSmallMax4Test.java
```

---

## **⚙️ Compilation & Running Tests**

You can use GitHub Codespaces to run, compile, and test this assignment entirely in the cloud — no local setup required.

If you choose to work on your **local machine**, you must have Maven installed. If not:

### **Linux/macOS**

```
sudo apt install maven   # on Ubuntu/Debian
brew install maven       # on macOS

```

### **Windows**

1. Download from: [https://maven.apache.org/download.cgi](https://maven.apache.org/download.cgi)
2. Extract to a folder like `C:\\Program Files\\Apache\\maven`
3. Set environment variable `MAVEN_HOME` to that folder
4. Add `%MAVEN_HOME%\\bin` to your system `PATH`
5. Open a new command prompt and type `mvn -v` to verify installation

### **🔨 Compile the Project**

```
mvn compile

```

### **✅ Run Tests**

```
mvn test

```

---

## **🔍 Debugging Test Cases in VS Code with Test Runner**

To debug JUnit test cases in VS Code, follow these steps:

### **Prerequisites:**

* Install the **Java Extension Pack** in VS Code.
* You may need to install version **0.40.0** of the **Test Runner for Java** extension if debugging options do not appear.

#### **Steps:**

1. Open a test file in the editor.
2. Set breakpoints by clicking on the gutter next to the line numbers.
3. Right-click on the gutter next to the line number of the test method name and select **Debug Test**.
4. Use the debug toolbar to step through code, inspect variables, and view call stacks.

This allows you to easily verify internal state, control flow, and ensure correctness of your implementation.

### `ChainValidator`

For testing your work, we provide a helper class **`ChainValidator`** that can replay a candidate chain step by step on a scenario and verify its correctness.  
- Use it to check whether your `findChains` output produces valid chains.  
- It enforces all preconditions, effects, reuse policies, and the stop-at-target rule.  
- This can be very helpful when debugging your implementation.

---

## Additional Resources

### Maven
Maven is used to build and manage the project. You can download it from: https://maven.apache.org/

### JUnit
JUnit 4 is used for testing. It is automatically included via Maven (see `pom.xml`). You do not need to install it separately.

---

## 📤 Gradescope Autograder
- This assignment will be autograded on **Gradescope**.
- The autograder reads only your `IntrusionChainFinder.java` file.
- The autograder will:
  - Compile your code using Maven
  - Run unit tests using JUnit
  - Check for correctness and edge cases

💡 You can submit as many times as you'd like before the deadline — only the latest submission counts.

---
## **📊 Grading Rubric**

| Item.                                                   |  Points |
| ------------------------------------------------------- | ------- |
| Autograder Tests.                                       | 90      |
| Code style, comments, and modularity                    | 10      |

### **💡 Grading Guidelines**

* Test cases include both visible and hidden scenarios to assess correctness, edge handling, and boundary conditions.
* If your autograder score is below 60%, your code will be manually reviewed for partial credit.

  * However, **manual grading can award no more than 60% of the total autograder points**.
* `Code style, comments, and modularity` is graded manually and includes:

  * Clear and meaningful variable/method names
  * Proper indentation and formatting
  * Use of helper methods to reduce duplication
  * Inline comments explaining non-obvious logic
  * Adherence to Java naming conventions

---

Good luck, and happy Backtracking! 🔤✨

