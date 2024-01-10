package com.videostream.authenticationservice.JWT;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
@Slf4j
public class JwtService {
    /**
     * Base64 encoded 256-bit key, openssl gen 32 byte key
     */
    @Value("${jwt.hmac.sign.key}")
    private String HMAC_Key;
    /**
     * Base 64 encoded
     */
    @Value("${jwt.rsa.PrivateKey}")
    private String RSA_PrivateKey;
    @Getter
    @Value("${jwt.rsa.PublicKey}")
    private String RSA_PublicKey;

    private PrivateKey rsaPrivateKey;
    private PublicKey rsaPublicKey;
    private SecretKey hmacSignKey;

    public JwtService() {

    }

    /**
     * in the case where keys are not defined from the property file, they can be loaded on runtime
     */
    public void validateKeys() {
        if (HMAC_Key == null || RSA_PrivateKey == null || RSA_PublicKey == null) {
            System.out.println("Generating Keys");
            HMAC_Key = Encoders.BASE64.encode(Jwts.SIG.HS256.key().build().getEncoded());
            KeyPair pair = Jwts.SIG.RS256.keyPair().build();
            RSA_PrivateKey = Encoders.BASE64.encode(pair.getPrivate().getEncoded());
            RSA_PublicKey = Encoders.BASE64.encode(pair.getPublic().getEncoded());
        }
    }

    /**
     * Function that builds singed jwt refresh tokens, valid for 2 hours
     *
     * @param details the user in question
     * @return a singed refresh jwt for the user in question
     */
    public String buildRefreshToken(UserDetails details) {
        //Signed with HMAC key
        return Jwts.builder()
                .claims(new HashMap<>())
                .subject(details.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(java.sql.Timestamp.valueOf(LocalDateTime.now().plusHours(2)))
                .signWith(getHmacKey()).compact();
    }

    /**
     * Function that builds a singed jwt auth access token, valid for 30 minutes
     *
     * @param details user in question
     * @param claims  these are claims for role authentication as well as other information
     * @return JWT access auth token
     */
    public String buildAccessToken(UserDetails details, Map<String, Object> claims) {
        //sings with RSA
        return Jwts.builder().claims(claims)
                .subject(details.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(java.sql.Timestamp.valueOf(LocalDateTime.now().plusMinutes(30)))
                .signWith(getRsaSignKey())
                .compact();
    }

    /**
     * Returns Decoded Hmac key, needs to be kept secrete
     * @return Decoded Hmac key
     */
    private SecretKey getHmacKey() {
        if(hmacSignKey != null){
            return hmacSignKey;
        }
        hmacSignKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(HMAC_Key));
        return hmacSignKey;
    }

    private PublicKey getRSAPublicKey() {
        if (rsaPublicKey != null) {
            return rsaPublicKey;
        }
        try {
            rsaPublicKey =
                    KeyFactory.getInstance("RSA").generatePublic(
                            new X509EncodedKeySpec(Decoders.BASE64.decode(RSA_PublicKey))
                    );
            return rsaPublicKey;
        } catch (Exception e) {
            return null;
        }
    }

    private Key getRsaSignKey() {
        if (rsaPrivateKey != null) {
            return rsaPrivateKey;
        }
        try {
            rsaPrivateKey =
                    KeyFactory.getInstance("RSA").generatePrivate(
                            new PKCS8EncodedKeySpec(Decoders.BASE64.decode(RSA_PrivateKey))
                    );
            return rsaPrivateKey;
        } catch (Exception e) {
            return null;
        }
    }

    public String resolveToken(String token) {
        if (StringUtils.hasText(token) && token.startsWith("Bearer ")) {
            return token.substring(7);
        }
        log.atWarn()
                .log(StringUtils.hasText(token) ? "Token did not start with Bearer: {}" : "Token was empty: {}", token);
        return null;
    }

    /**
     * Boolean to verify auth token using RSA public key
     *
     * @param token of user in question
     * @return boolean
     */
    public boolean validAuthToken(String token) {
        //validate token
        try {
            Jwts.parser().verifyWith(getRSAPublicKey()).build()
                    .parseSignedClaims(token);
        } catch (Exception e) {
            log.atWarn().log("JWT Failed to parse: {} : {}", e.getCause(), e.getMessage());
            return false;
        }
        return true;
    }

    /**
     * Boolean to verify auth token using RSA public key
     *
     * @param token of user in question
     * @return boolean
     */
    public boolean validRefreshToken(String token) {
        //validate token
        try {
            Jwts.parser().verifyWith(getHmacKey()).build()
                    .parseSignedClaims(token);
        } catch (Exception e) {
            log.atWarn().log("JWT Failed to parse: {} : {}", e.getCause(), e.getMessage());
            return false;
        }
        return true;
    }

    /**
     * Returns all claims found in jwt payload, if token signature is valid
     *
     * @param token the token in question
     * @return claims found within JWT token
     */
    public Map<String, String> extractClaimsFromAuthToken(String token) {
        HashMap<String, String> map = new HashMap<>();
        Jwts.parser().verifyWith(getRSAPublicKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .forEach((k, v) -> map.put(k, v.toString()));
        log.info("Token Values: {}", map);
        return map;
    }

    /**
     * extracts the username found within the token iff token signature is valid
     *
     * @param token JWT token in question
     * @return username if token is valid
     */
    public String getUserNameAuthToken(String token) {
        try {
            return Jwts.parser().verifyWith(getRSAPublicKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getSubject();
        } catch (Exception e) {
            log.atInfo().log("Token could not be parsed, cause: {} : message: {}", e.getCause(), e.getMessage());
            return null;
        }
    }
    /**
     * extracts the username found within the token iff token signature is valid
     *
     * @param token JWT token in question
     * @return username if token is valid
     */
    public String getUserNameRefreshToken(String token) {
        try {
            return Jwts.parser().verifyWith(getHmacKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getSubject();
        } catch (Exception e) {
            log.atInfo().log("Token could not be parsed, cause: {} : message: {}", e.getCause(), e.getMessage());
            return null;
        }
    }
}
