import static org.junit.Assert.*;
import org.junit.Test;
import java.util.*;

public class PublicCorpSmallMax3Test {

    @Test
    public void corpSmall_max3_hasExactlyOneValidChain_inOrder() {
        ScenarioFactory.Scenario sc = ScenarioFactory.corpSmall();
        SystemInfo start = sc.byName("EMP-LAPTOP");
        SystemInfo target = sc.byName("PAYROLL-DB");

        // Generate
        List<List<Hop>> chains = IntrusionChainFinder.findChains(sc, start, target, 3);

        // 1) Count
        assertEquals("Expected exactly one chain with maxHops=3", 1, chains.size());

        // 2) Validate each chain
        for (int i = 0; i < chains.size(); i++) {
            List<Hop> chain = chains.get(i);
            assertTrue("Chain #" + i + " failed ChainValidator",
                    ChainValidator.validateChain(sc, start, target, chain));
        }

        // 3) Check order (single expected chain key)
        String expectedKey = "EMP-LAPTOP|SMB|CVE-2020-0796-SMBGhost|FILE-SRV->" +
                "FILE-SRV|LOCAL|LootCreds|FILE-SRV->" +
                "FILE-SRV|SSH|PassTheHash|PAYROLL-DB->";

        assertEquals("Unexpected chain ordering/content", expectedKey, chainKey(chains.get(0)));

        // Determinism across runs
        List<List<Hop>> chains2 = IntrusionChainFinder.findChains(sc, start, target, 3);
        assertEquals(1, chains2.size());
        assertEquals(chainKey(chains.get(0)), chainKey(chains2.get(0)));
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
