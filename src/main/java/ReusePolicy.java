public final class ReusePolicy {
    enum Kind {
        ONCE_PER_SYSTEM, LIMITED, UNLIMITED
    }

    final Kind kind;
    final int limit; // used only for LIMITED

    private ReusePolicy(Kind k, int limit) {
        this.kind = k;
        this.limit = limit;
    }

    static ReusePolicy ONCE_PER_SYSTEM = new ReusePolicy(Kind.ONCE_PER_SYSTEM, 1);

    static ReusePolicy LIMITED(int n) {
        return new ReusePolicy(Kind.LIMITED, n);
    }

    static ReusePolicy UNLIMITED = new ReusePolicy(Kind.UNLIMITED, Integer.MAX_VALUE);
}
