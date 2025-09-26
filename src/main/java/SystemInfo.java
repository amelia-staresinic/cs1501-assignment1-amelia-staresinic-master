import java.util.*;

enum Priv {
    NONE, USER, ADMIN
}

public final class SystemInfo {
    String name, os;
    List<String> services = new ArrayList<>();
    List<String> creds = new ArrayList<>();
    Priv priv = Priv.NONE;
    List<Route> routes = new ArrayList<>();

    SystemInfo(String name, String os, List<String> services,
            List<String> creds, Priv priv) {
        this.name = name;
        this.os = os;
        if (services != null)
            this.services.addAll(services);
        if (creds != null)
            this.creds.addAll(creds);
        this.priv = priv;
    }
}