package com.example.jwt.controller;

import com.example.jwt.auth.PrincipalDetail;
import com.example.jwt.model.User;
import com.example.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("api/v1")
@RequiredArgsConstructor
public class RestApiController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder encoder;

   @GetMapping("/home")
   public String home(){
       return "<h1> home </h1>";
   }

    @PostMapping("/token")
    public String token(){
        return "<h1> token </h1>";
    }

    public String join(@RequestBody User user){
        user.setPassword(encoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "회원가입완료";
    }

    // 유저 혹은 매니저 혹은 어드민이 접근 가능
    // Authentication은 세션에 저장하였을때 사용가능
    @GetMapping("user")
    public String user(Authentication authentication) {
        PrincipalDetail principal = (PrincipalDetail) authentication.getPrincipal();
        System.out.println("principal : "+principal.getUser().getId());
        System.out.println("principal : "+principal.getUser().getUsername());
        System.out.println("principal : "+principal.getUser().getPassword());

        return "<h1>user</h1>";
    }

    // 매니저 혹은 어드민이 접근 가능
    @GetMapping("manager/reports")
    public String reports() {
        return "<h1>reports</h1>";
    }

    // 어드민이 접근 가능
    @GetMapping("admin/users")
    public List<User> users(){
        return userRepository.findAll();
    }

}
