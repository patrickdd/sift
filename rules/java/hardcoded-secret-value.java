import org.springframework.beans.factory.annotation.Value;

public class Config {
    // ruleid: java.hardcoded-secret-value
    @Value("${payments.api-key:sk_live_51HxQe2Lr}")
    private String apiKey;

    // ruleid: java.hardcoded-secret-value
    private static final String DB_PASSWORD = "hunter2hunter2";

    // ok: java.hardcoded-secret-value
    @Value("${payments.api-key}")
    private String paymentsApiKey;

    // ok: java.hardcoded-secret-value
    @Value("${app.timeout:30}")
    private int timeout;

    // ok: java.hardcoded-secret-value
    private String clientSecret = "";

    void rotate() {
        String token;
        // ruleid: java.hardcoded-secret-value
        token = "ghp_example0123456789";
        // ok: java.hardcoded-secret-value
        String displayName = "administrator";
    }
}
