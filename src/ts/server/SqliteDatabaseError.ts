
class SqliteDatabaseError extends Error {
    public constructor(message: any) {
        super(message);
        this.name = "SqliteDatabaseError";
    }
}
