import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// ruleid: java.cors-wildcard
@CrossOrigin(origins = "*")
@RestController
public class OpenController {
    // ruleid: java.cors-wildcard
    @CrossOrigin("*")
    @GetMapping("/a")
    public String a() { return "a"; }

    // ruleid: java.cors-wildcard
    @CrossOrigin(origins = {"https://x.example", "*"}, maxAge = 3600)
    @GetMapping("/b")
    public String b() { return "b"; }

    // ok: java.cors-wildcard
    @CrossOrigin(origins = "https://app.example.com")
    @GetMapping("/c")
    public String c() { return "c"; }
}
