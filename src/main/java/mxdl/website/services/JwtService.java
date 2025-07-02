package mxdl.website.services;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {

    private final SecretKey secretKey = Jwts.SIG.HS256.key().build();

    public String generateToken(String username, UUID uuid) {
        return Jwts.builder()
                .subject(username)
                .claim("id", uuid)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + 3600000))
                .signWith(secretKey)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
            return true;
        }
        catch (Exception e) {
            return false;
        }
    }

    public boolean isExpired(String token) {
        try {
            Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
            return false;
        }
        catch (ExpiredJwtException e) {
            return true;
        }
        catch (Exception e) {
            return false;
        }
    }

    public UUID getIdFromToken(String token) {
        return UUID.fromString(Jwts.parser().verifyWith(secretKey).build()
                .parseSignedClaims(token).getPayload().get("id", String.class));
    }

    public String getJwtFromRequest(HttpServletRequest request) {
        String jwt = request.getHeader("Authorization");
        if (jwt != null && jwt.startsWith("Bearer ")) {
            return jwt.substring(7);
        }
        return null;
    }

}
