package com.videostream.authenticationservice.JWT;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {
    /**
     * Base64 encoded 256-bit key, openssl gen 32 byte key
     */
    @Value("${jwt.hmac.sign.key}")
    private static String HMAC_Key;
    /**
     * Base 64 encoded
     */
    @Value("${jwt.rsa.PrivateKey}")
    private String RSA_PrivateKey;
    @Value("${jwt.rsa.PublicKey}")
    private String RSA_PublicKey;

    //todo load strings into actual key pairs --> https://github.com/jwtk/jjwt/issues/131#issuecomment-1003065051


    public JwtService(){

    }
    public void validateKeys(){
        if(HMAC_Key == null || RSA_PrivateKey == null || RSA_PublicKey == null ){
            System.out.println("Generating Keys");
            HMAC_Key = Encoders.BASE64.encode(Jwts.SIG.HS256.key().build().getEncoded());
            KeyPair pair = Jwts.SIG.RS256.keyPair().build();
            RSA_PrivateKey = Encoders.BASE64.encode(pair.getPrivate().getEncoded());
            RSA_PublicKey = Encoders.BASE64.encode(pair.getPublic().getEncoded());
        }
    }
    public String getRSA_PublicKey() {
        System.out.println(RSA_PublicKey);
        return RSA_PublicKey;
    }
    private String buildRefreshToken(UserDetails details){
        //Signed with HMAC key
        return Jwts.builder()
                .claims(new HashMap<>())
                .subject(details.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(java.sql.Timestamp.valueOf(LocalDateTime.now().plusHours(2)))
                .signWith(getHmacKey()).compact();
    }
    private String buildAccessToken(UserDetails details, Map<String,Object> claims){
        //sings with RSA
        return Jwts.builder().claims(claims)
                .subject(details.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(java.sql.Timestamp.valueOf(LocalDateTime.now().plusMinutes(30)))
                .signWith(getRsaSignKey())
                .compact();
    }
    private Key getHmacKey(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(HMAC_Key));
    }
    private Key getRsaSignKey(){
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(
                new PKCS8EncodedKeySpec(Decoders.BASE64.decode(RSA_PrivateKey)));
        }catch (Exception e){
            return null;
        }
    }
}
