package info.sw0.example.example_resource_server.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SampleController {
    @GetMapping("/api/sample/get1")
    public Jwt get1(@AuthenticationPrincipal Jwt principal) {
        return principal;
    }
    @GetMapping("/api/sample/get2")
    public String[] get2() {
        return new String[]{"A2", "B2", "C2"};
    }
    @GetMapping("/api/sample/get3")
    public String[] get3() {
        return new String[]{"A3", "B3", "C3"};
    }

}
