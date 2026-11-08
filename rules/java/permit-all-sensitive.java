import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public class SecurityConfig {
    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
            // ok: java.permit-all-sensitive
            .requestMatchers("/public/**").permitAll()
            // ruleid: java.permit-all-sensitive
            .requestMatchers("/admin/**").permitAll()
            // ruleid: java.permit-all-sensitive
            .requestMatchers("/health", "/internal/metrics").permitAll()
            // ok: java.permit-all-sensitive
            .requestMatchers("/internal/**").hasRole("OPS")
            .anyRequest().authenticated());
        return http.build();
    }

    void legacy(HttpSecurity http) throws Exception {
        // ruleid: java.permit-all-sensitive
        http.authorizeRequests().antMatchers("/api/admin/users").permitAll();
    }
}
