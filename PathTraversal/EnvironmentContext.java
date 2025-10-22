public class EnvironmentContext {
    private final java.nio.file.Path safeDirectory;
    private final String userId;

    public EnvironmentContext(java.nio.file.Path safeDirectory, String userId) {
        this.safeDirectory = safeDirectory;
        this.userId = userId;
    }

    public java.nio.file.Path getSafeDirectory() {
        return safeDirectory;
    }

    public String getUserId() {
        return userId;
    }
}
