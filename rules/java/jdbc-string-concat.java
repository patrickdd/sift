import java.util.List;
import java.util.Map;
import javax.persistence.EntityManager;
import org.springframework.jdbc.core.JdbcTemplate;

public class UserRepo {
    private final JdbcTemplate jdbc;
    private final EntityManager em;

    UserRepo(JdbcTemplate jdbc, EntityManager em) { this.jdbc = jdbc; this.em = em; }

    List<Map<String, Object>> byName(String name) {
        // ruleid: java.jdbc-string-concat
        return jdbc.queryForList("SELECT * FROM users WHERE name = '" + name + "'");
    }

    List<Map<String, Object>> byCity(String city) {
        String sql = String.format("SELECT * FROM users WHERE city = '%s'", city);
        // ruleid: java.jdbc-string-concat
        return jdbc.queryForList(sql);
    }

    Object byEmail(String email) {
        // ruleid: java.jdbc-string-concat
        return em.createQuery("FROM User u WHERE u.email = '" + email + "'").getSingleResult();
    }

    List<Map<String, Object>> safeByName(String name) {
        // ok: java.jdbc-string-concat
        return jdbc.queryForList("SELECT * FROM users WHERE name = ?", name);
    }

    List<Map<String, Object>> constantConcat() {
        String table = "users";
        // ok: java.jdbc-string-concat
        return jdbc.queryForList("SELECT * FROM " + table);
    }
}
