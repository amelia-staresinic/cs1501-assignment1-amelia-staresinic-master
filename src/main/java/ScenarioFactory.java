import java.util.*;

public final class ScenarioFactory {

    public static Scenario corpSmall() {
        // Systems
        SystemInfo emp = new SystemInfo(
                "EMP-LAPTOP", "Windows 10",
                List.of("browser"),
                List.of("emp@corp"),
                Priv.USER);

        SystemInfo file = new SystemInfo(
                "FILE-SRV", "Windows Server 2019",
                List.of("SMB", "WinRM"),
                List.of("svc-backup"), // credential present to demonstrate LootCreds
                Priv.NONE);

        SystemInfo db = new SystemInfo(
                "PAYROLL-DB", "Ubuntu 20.04",
                List.of("PostgreSQL", "SSH"),
                List.of("svc-payroll"),
                Priv.NONE);

        // Routes (bidirectional with potentially different allow lists)
        linkBoth(emp, file,
                List.of("SMB", "HTTP"), // EMP -> FILE
                List.of("HTTP")); // FILE -> EMP

        linkBoth(file, db,
                List.of("SSH", "WinRM"), // FILE -> DB
                List.of("SSH")); // DB -> FILE

        Exploit lootCreds = new Exploit("LootCreds");
        lootCreds.requiredService = ""; // local
        lootCreds.requiredPrivOnSource = Priv.ADMIN;
        lootCreds.osContains = null;
        lootCreds.requiredCredTag = null;
        lootCreds.gainPrivOnTarget = Priv.ADMIN; // no change; ensures ADMIN or higher
        lootCreds.addCredsOnTarget = true; // copies all system creds to attacker inventory
        lootCreds.reusePolicy = ReusePolicy.UNLIMITED;

        Exploit passTheHash = new Exploit("PassTheHash");
        passTheHash.requiredService = "SSH"; // lateral (can switch to "SMB" if preferred)
        passTheHash.requiredPrivOnSource = Priv.USER;
        passTheHash.osContains = null;
        passTheHash.requiredCredTag = "svc-"; // requires any svc-* cred in attacker inventory
        passTheHash.gainPrivOnTarget = Priv.USER;
        passTheHash.addCredsOnTarget = false;
        passTheHash.reusePolicy = ReusePolicy.LIMITED(2);

        Exploit printNightmare = new Exploit("CVE-2021-34527-PrintNightmare");
        printNightmare.requiredService = ""; // local
        printNightmare.requiredPrivOnSource = Priv.USER;
        printNightmare.osContains = "Windows";
        printNightmare.requiredCredTag = null;
        printNightmare.gainPrivOnTarget = Priv.ADMIN;
        printNightmare.addCredsOnTarget = false;
        printNightmare.reusePolicy = ReusePolicy.UNLIMITED;

        Exploit smbGhost = new Exploit("CVE-2020-0796-SMBGhost");
        smbGhost.requiredService = "SMB"; // lateral
        smbGhost.requiredPrivOnSource = Priv.USER;
        smbGhost.osContains = null;
        smbGhost.requiredCredTag = null;
        smbGhost.gainPrivOnTarget = Priv.ADMIN;
        smbGhost.addCredsOnTarget = false;
        smbGhost.reusePolicy = ReusePolicy.ONCE_PER_SYSTEM;

        List<SystemInfo> systems = new ArrayList<>(List.of(emp, file, db));
        systems.sort(Comparator.comparing(s -> s.name));

        List<Exploit> exploits = new ArrayList<>(List.of(lootCreds, passTheHash, printNightmare, smbGhost));
        exploits.sort(Comparator.comparing(e -> e.name));

        return new Scenario(systems, exploits);
    }

    // A slightly larger example (optional for testing/perf)
    public static Scenario opsMid() {
        SystemInfo ws = new SystemInfo("WORKSTATION-01", "Windows 11",
                List.of("browser"), List.of("emp@corp"), Priv.USER);

        SystemInfo jump = new SystemInfo("JUMP-HOST", "Windows Server 2022",
                List.of("RDP", "WinRM"), List.of("svc-helpdesk"), Priv.NONE);

        SystemInfo files = new SystemInfo("FILES-01", "Windows Server 2019",
                List.of("SMB", "WinRM"), List.of("svc-backup", "svc-files"), Priv.NONE);

        SystemInfo app = new SystemInfo("APP-API", "Ubuntu 22.04",
                List.of("HTTP", "SSH"), List.of(), Priv.NONE);

        SystemInfo db = new SystemInfo("APP-DB", "Ubuntu 22.04",
                List.of("PostgreSQL", "SSH"), List.of("svc-db"), Priv.NONE);

        linkBoth(ws, jump, List.of("RDP", "HTTP"), List.of("HTTP"));
        linkBoth(jump, files, List.of("WinRM", "SMB"), List.of("WinRM"));
        linkBoth(files, app, List.of("HTTP", "SSH"), List.of("HTTP"));
        linkBoth(app, db, List.of("SSH"), List.of("SSH"));

        Exploit lootCreds = new Exploit("LootCreds");
        lootCreds.requiredService = "";
        lootCreds.requiredPrivOnSource = Priv.ADMIN;
        lootCreds.gainPrivOnTarget = Priv.ADMIN;
        lootCreds.addCredsOnTarget = true;
        lootCreds.reusePolicy = ReusePolicy.UNLIMITED;

        Exploit pth = new Exploit("PassTheHash");
        pth.requiredService = "WinRM";
        pth.requiredPrivOnSource = Priv.USER;
        pth.requiredCredTag = "svc-";
        pth.gainPrivOnTarget = Priv.USER;
        pth.addCredsOnTarget = false;
        pth.reusePolicy = ReusePolicy.LIMITED(3);

        Exploit sshReuse = new Exploit("SSH-Key-Reuse");
        sshReuse.requiredService = "SSH";
        sshReuse.requiredPrivOnSource = Priv.USER;
        sshReuse.requiredCredTag = "svc-";
        sshReuse.gainPrivOnTarget = Priv.USER;
        sshReuse.addCredsOnTarget = false;
        sshReuse.reusePolicy = ReusePolicy.UNLIMITED;

        Exploit printNightmare = new Exploit("CVE-2021-34527-PrintNightmare");
        printNightmare.requiredService = "";
        printNightmare.requiredPrivOnSource = Priv.USER;
        printNightmare.osContains = "Windows";
        printNightmare.gainPrivOnTarget = Priv.ADMIN;
        printNightmare.addCredsOnTarget = false;
        printNightmare.reusePolicy = ReusePolicy.UNLIMITED;

        Exploit smbGhost = new Exploit("CVE-2020-0796-SMBGhost");
        smbGhost.requiredService = "SMB";
        smbGhost.requiredPrivOnSource = Priv.USER;
        smbGhost.gainPrivOnTarget = Priv.ADMIN;
        smbGhost.addCredsOnTarget = false;
        smbGhost.reusePolicy = ReusePolicy.ONCE_PER_SYSTEM;

        Exploit rdpLogin = new Exploit("RDP-Login");
        rdpLogin.requiredService = "RDP";
        rdpLogin.requiredPrivOnSource = Priv.USER;
        rdpLogin.requiredCredTag = "emp@"; // illustrate non svc- tag
        rdpLogin.gainPrivOnTarget = Priv.USER;
        rdpLogin.addCredsOnTarget = false;
        rdpLogin.reusePolicy = ReusePolicy.LIMITED(2);

        List<SystemInfo> systems = new ArrayList<>(List.of(ws, jump, files, app, db));
        systems.sort(Comparator.comparing(s -> s.name));

        List<Exploit> exploits = new ArrayList<>(List.of(lootCreds, pth, sshReuse, printNightmare, smbGhost, rdpLogin));
        exploits.sort(Comparator.comparing(e -> e.name));

        return new Scenario(systems, exploits);
    }

    // ---------- Helpers & container types ----------

    static void linkBoth(SystemInfo a, SystemInfo b, List<String> allowAB, List<String> allowBA) {
        a.routes.add(new Route(b, new ArrayList<>(allowAB)));
        b.routes.add(new Route(a, new ArrayList<>(allowBA)));
        // Deterministic route ordering by destination name, and service lists
        // lexicographically
        sortRoutes(a);
        sortRoutes(b);
    }

    private static void sortRoutes(SystemInfo s) {
        for (Route r : s.routes) {
            r.allow.sort(Comparator.naturalOrder());
        }
        s.routes.sort(Comparator.comparing(r -> r.to.name));
    }

    // Container for a scenario (systems + exploits) with basic lookup
    public static final class Scenario {
        final List<SystemInfo> systems;
        final List<Exploit> exploits;

        Scenario(List<SystemInfo> systems, List<Exploit> exploits) {
            this.systems = systems;
            this.exploits = exploits;
        }

        SystemInfo byName(String name) {
            for (SystemInfo s : systems)
                if (s.name.equals(name))
                    return s;
            return null;
        }
    }
}
