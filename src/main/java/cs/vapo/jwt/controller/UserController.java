package cs.vapo.jwt.controller;

import cs.vapo.jwt.model.user.AuthenticationResponse;
import cs.vapo.jwt.model.user.CreateUserRequest;
import cs.vapo.jwt.model.user.LoginUserRequest;
import cs.vapo.jwt.service.UserService;
import java.net.URISyntaxException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/user")
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping("/create")
    public ResponseEntity<AuthenticationResponse> registerUser(@RequestBody final CreateUserRequest request)
            throws URISyntaxException {
        return ResponseEntity.ok(userService.registerUser(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> loginUser(@RequestBody final LoginUserRequest request) {
        return ResponseEntity.ok(userService.loginUser(request));
    }

}
