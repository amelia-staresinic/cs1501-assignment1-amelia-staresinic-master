import static org.junit.Assert.*;
import org.junit.Test;
import java.util.*;

public class PublicCorpSmallMax4Test {

    @Test
    public void corpSmall_max4_fiveChains_valid_and_inDeterministicOrder() {
        ScenarioFactory.Scenario sc = ScenarioFactory.corpSmall();
        SystemInfo start = sc.byName("EMP-LAPTOP");
        SystemInfo target = sc.byName("PAYROLL-DB");

        // Generate
        List<List<Hop>> chains = IntrusionChainFinder.findChains(sc, start, target, 4);

        // 1) Count: expect five chains (two 4-hop variants on FILE-SRV, one
        // double-LootCreds,
        // one with PrintNightmare on EMP-LAPTOP first, and the 3-hop baseline)
        assertEquals("Expected exactly five chains with maxHops=4", 5, chains.size());

        // 2) Validate each chain via ChainValidator
        for (int i = 0; i < chains.size(); i++) {
            List<Hop> chain = chains.get(i);
            assertTrue("Chain #" + i + " failed ChainValidator",
                    ChainValidator.validateChain(sc, start, target, chain));
        }

        // 3) Deterministic order by chainKey, then by length.
        // Expected keys in order:

        // (1) PrintNightmare on EMP first
        String expectedKey1 = "EMP-LAPTOP|LOCAL|CVE-2021-34527-PrintNightmare|EMP-LAPTOP->" +
                "EMP-LAPTOP|SMB|CVE-2020-0796-SMBGhost|FILE-SRV->" +
                "FILE-SRV|LOCAL|LootCreds|FILE-SRV->" +
                "FILE-SRV|SSH|PassTheHash|PAYROLL-DB->";

        // (2) SMBGhost then PrintNightmare (FILE-SRV), LootCreds, PassTheHash
        String expectedKey2 = "EMP-LAPTOP|SMB|CVE-2020-0796-SMBGhost|FILE-SRV->" +
                "FILE-SRV|LOCAL|CVE-2021-34527-PrintNightmare|FILE-SRV->" +
                "FILE-SRV|LOCAL|LootCreds|FILE-SRV->" +
                "FILE-SRV|SSH|PassTheHash|PAYROLL-DB->";

        // (3) SMBGhost then LootCreds, then PrintNightmare (FILE-SRV), then PassTheHash
        String expectedKey3 = "EMP-LAPTOP|SMB|CVE-2020-0796-SMBGhost|FILE-SRV->" +
                "FILE-SRV|LOCAL|LootCreds|FILE-SRV->" +
                "FILE-SRV|LOCAL|CVE-2021-34527-PrintNightmare|FILE-SRV->" +
                "FILE-SRV|SSH|PassTheHash|PAYROLL-DB->";

        // (4) SMBGhost then double LootCreds, then PassTheHash
        String expectedKey4 = "EMP-LAPTOP|SMB|CVE-2020-0796-SMBGhost|FILE-SRV->" +
                "FILE-SRV|LOCAL|LootCreds|FILE-SRV->" +
                "FILE-SRV|LOCAL|LootCreds|FILE-SRV->" +
                "FILE-SRV|SSH|PassTheHash|PAYROLL-DB->";

        // (5) 3-hop baseline: SMBGhost, LootCreds, PassTheHash
        String expectedKey5 = "EMP-LAPTOP|SMB|CVE-2020-0796-SMBGhost|FILE-SRV->" +
                "FILE-SRV|LOCAL|LootCreds|FILE-SRV->" +
                "FILE-SRV|SSH|PassTheHash|PAYROLL-DB->";

        assertEquals("Chain[0] unexpected ordering/content", expectedKey1, chainKey(chains.get(0)));
        assertEquals("Chain[1] unexpected ordering/content", expectedKey2, chainKey(chains.get(1)));
        assertEquals("Chain[2] unexpected ordering/content", expectedKey3, chainKey(chains.get(2)));
        assertEquals("Chain[3] unexpected ordering/content", expectedKey4, chainKey(chains.get(3)));
        assertEquals("Chain[4] unexpected ordering/content", expectedKey5, chainKey(chains.get(4)));

        // Determinism across runs
        List<List<Hop>> chains2 = IntrusionChainFinder.findChains(sc, start, target, 4);
        assertEquals(5, chains2.size());
        for (int i = 0; i < 5; i++) {
            assertEquals(chainKey(chains.get(i)), chainKey(chains2.get(i)));
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
