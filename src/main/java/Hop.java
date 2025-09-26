final class Hop {
    String from, to; //to == from for local exploits
    String viaExploit; //used exploit name
    String viaService; //exploited service or "LOCAL" for local exploits

    Hop(String from, String to, String viaExploit, String viaService) {
        this.from = from;
        this.to = to;
        this.viaExploit = viaExploit;
        this.viaService = viaService;
    }
}
