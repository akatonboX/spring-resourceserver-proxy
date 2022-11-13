package info.sw0.example.example_proxy_server.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.RequestContextHolder;

@RestController
@RequestMapping("/api/test")
public class SampleController {
  @GetMapping("get2")
  public String[] get2() {
      return new String[]{"A2", "B2", "C2"};
  }
  @GetMapping("get3")
  public String[] get3() {
      return new String[]{"A3", "B3", "C3"};
  }

  // @GetMapping("cookie")
  // public String[] getCookie() {
  //   var request = RequestContextHolder.currentRequestAttributes().
    
  // }
}
