import java.util.*;

public final class Route {
    SystemInfo to;
    List<String> allow = new ArrayList<>();

    Route(SystemInfo to, List<String> allow) {
        this.to = to;
        if (allow != null)
            this.allow.addAll(allow);
    }
}
