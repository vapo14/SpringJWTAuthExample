package cs.vapo.jwt.token;

import cs.vapo.jwt.config.ApplicationConfiguration;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    private static final int HOUR_IN_MILLIS = 1000 * 60 * 60;

    @Autowired
    private ApplicationConfiguration configuration;

    public String generateToken(final Map<String, Object> claims, final UserDetails userDetails) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + HOUR_IN_MILLIS))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isValid(final String token, final UserDetails userDetails) {
        final String username = retrieveUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(final String token) {
        return retrieveExpirationDate(token).before(new Date());
    }

    private Date retrieveExpirationDate(final String token) {
        return retrieveClaim(token, Claims::getExpiration);
    }

    public String retrieveUsername(final String token) {
        return retrieveClaim(token, Claims::getSubject);
    }

    public <T> T retrieveClaim(final String token, final Function<Claims, T> resolver) {
        final Claims claims = retrieveClaims(token);
        return resolver.apply(claims);
    }

    private Claims retrieveClaims(final String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(configuration.getSigningKey());
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
