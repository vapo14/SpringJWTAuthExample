package cs.vapo.jwt.service;

import cs.vapo.jwt.model.user.AuthenticationResponse;
import cs.vapo.jwt.model.user.CreateUserRequest;
import cs.vapo.jwt.model.user.LoginUserRequest;
import cs.vapo.jwt.model.user.User;
import cs.vapo.jwt.model.user.UserRepository;
import cs.vapo.jwt.token.JwtService;
import java.util.HashMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authManager;

    public AuthenticationResponse registerUser(CreateUserRequest request) {
        final User user = new User();
        user.setFirstname(request.getFirstName());
        user.setLastname(request.getLastName());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        userRepository.save(user);
        final String jwt = jwtService.generateToken(new HashMap<>(), user);
        final AuthenticationResponse response = new AuthenticationResponse();
        response.setToken(jwt);
        return response;
    }

    public AuthenticationResponse loginUser(LoginUserRequest request) {
        authManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        final User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();
        final String jwt = jwtService.generateToken(new HashMap<>(), user);
        final AuthenticationResponse response = new AuthenticationResponse();
        response.setToken(jwt);
        return response;
    }
}
