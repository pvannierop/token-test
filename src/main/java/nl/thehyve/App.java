package nl.thehyve;

import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Map;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;

import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;

/**
 * Hello world!
 *
 */
public class App 
{

    static String tokenString = "eyJhbGciOiJSUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJFcHZjeG1jU01Na1lSbnl2dU5BWWRfX1ZQsecretRk11YzRyd3dTUXNuY1RqUDhrIn0.eyJqdGkiOiJiNjBmNTUyYS1iYjMxLTRiZTQtYTlhMS0wOGE1N2RiYzZmMDQiLCJleHAiOjE1NzE5OTUzMTAsIm5iZiI6MCwiaWF0IjoxNTcxOTk1MDEwLCJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo4NDQzL2F1dGgvcmVhbG1zL2NiaW8iLCJhdWQiOlsiY2Jpb3BvcnRhbCIsImFjY291bnQiXSwic3ViIjoiZWFhNTg4N2YtYTM5My00NWIxLWExMjktYjE3MTYxZTJjYTljIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiY2Jpb3BvcnRhbF9hcGkiLCJhdXRoX3RpbWUiOjE1NzE5OTQ2NjgsInNlc3Npb25fc3RhdGUiOiJjMWZiM2U3Yy1lYjgwLTQ1NmMtOTc4Ni1mYmVlOGYwZDQ5NTEiLCJhY3IiOiIwIiwicmVzb3VyY2VfYWNjZXNzIjp7ImNiaW9wb3J0YWxfYXBpIjp7InJvbGVzIjpbIlVTRVIiXX0sImNiaW9wb3J0YWwiOnsicm9sZXMiOlsiYnJjYV90Y2dhIiwic3R1ZHlfZXNfMCJdfSwiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJvcGVuaWQgZW1haWwgcHJvZmlsZSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwidXNlcl9uYW1lIjoicGltLnZhbi5uaWVyb3AiLCJuYW1lIjoiUGltIHZhbiBOaWVyb3AiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJwaW0udmFuLm5pZXJvcCIsImdpdmVuX25hbWUiOiJQaW0iLCJmYW1pbHlfbmFtZSI6InZhbiBOaWVyb3AiLCJlbWFpbCI6InBpbUB0aGVoeXZlLm5sIn0.HYTZZTarN52DgMt3u_pM1cELbTp3XQ24Cjo6B7B4POYicqOdRnjLqQlED6HAtmxttF1zxJUbX80GNOmGuLeTocGDXYjIfbIhfrphYoRthXc2ev8IqFZtCB4vFYs4ZA81rTYr53kLV5ewGAA3PybkgPCvyBZwk2e6Vxc-zyjA4jmbiyxURO9F_j4uM4hKA15aBWU2-m8G_1XMuJNPO7nzhBuwj-NuBk2BjFuB0DzRIlLD6TDp-qq8oUSKG7k0507ygo-Mmr3Rmd6KCHx_hghXHQeHavneauoU2eRvrdAgFwfUzL_3ky1Jz6Vj2lq-rLEp6qmT5H5u8ikA3o8zQCNgzQ";
    static DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(tokenString);
    // static String secret = "7431fb2c\\-a8ba\\-4e9e\\-8d2e\\-b0026da2a8f0";
    // static String secretB64 = "NzQzMWZiMmNcLWE4YmFcLTRlOWVcLThkMmVcLWIwMDI2ZGEyYThmMA==";

    static String issuer = "https://localhost:8443/auth/realms/cbio";
    static String kid = "EpvcxmcSMMkYRnyvuNAYd__VPFMuc4rwwSQsncTjP8k";
    static String jwkUrl = "https://localhost:8443/auth/realms/cbio/protocol/openid-connect/certs";
    static String clientId = "cbioportal";

    // private static boolean isValid(String token) throws RuntimeException {
    //     Jws<Claims> jwsClaims = null;
    //     try {
    //         jwsClaims = Jwts.parser()
    //             // .setSigningKey(secretB64)
    //             .parseClaimsJws(token);
    //     } catch (SignatureException e) {
    //         throw new RuntimeException("signature not valid");
    //     } catch (ExpiredJwtException e) {
    //         throw new RuntimeException("token has expired");
    //     }
    //     return jwsClaims != null;
    // }

    // //Sample method to construct a JWT
    // private static String createJWT(String id, String issuer, String subject) {

    //     //The JWT signature algorithm we will be using to sign the token
    //     SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

    //     //We will sign our JWT with our ApiKey secret
    //     byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(secretB64);
    //     Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

    //     //Let's set the JWT Claims
    //     JwtBuilder builder = Jwts.builder().setId(id)
    //                                 .setSubject(subject)
    //                                 .setIssuer(issuer)
    //                                 .signWith(signatureAlgorithm, signingKey);

    //     return builder.compact();
    // }

    public static void verifyClaims(Map<String, Object> claims) {
        int exp = (Integer) claims.get("exp");
        Date expireDate = new Date(exp * 1000L);
        Date now = new Date();

        if (expireDate.before(now) || !claims.get("iss").equals(issuer) || 
          !claims.get("aud").equals(clientId)) {
            throw new RuntimeException("Invalid claims");
        }
    }

    private static RsaVerifier verifier(String kid) throws Exception {
        JwkProvider provider = new UrlJwkProvider(new URL(jwkUrl));
        Jwk jwk = provider.get(kid);
        RSAPublicKey publicKey = (RSAPublicKey) jwk.getPublicKey();
        return new RsaVerifier(publicKey);
    }

    public static Jwt decode(String token) {
		int firstPeriod = token.indexOf('.');
		int lastPeriod = token.lastIndexOf('.');

        String[] tokenParts = token.split("\\.");

		CharBuffer buffer = CharBuffer.wrap(token, 0, firstPeriod);
		// TODO: Use a Reader which supports CharBuffer
		JwtHeader header = JwtHeaderHelper.create(buffer.toString());

		buffer.limit(lastPeriod).position(firstPeriod + 1);
		byte[] claims = b64UrlDecode(buffer);
		boolean emptyCrypto = lastPeriod == token.length() - 1;

		byte[] crypto;

		if (emptyCrypto) {
			if (!"none".equals(header.parameters.alg)) {
				throw new IllegalArgumentException(
						"Signed or encrypted token must have non-empty crypto segment");
			}
			crypto = new byte[0];
		}
		else {
			buffer.limit(token.length()).position(lastPeriod + 1);
			crypto = b64UrlDecode(buffer);
		}
		return new JwtImpl(header, claims, crypto);
    }
    
    private static myDecodeAndVerify(String token, RsaVerifier verifier) {
        
    }

    public static void main( String[] args )
    {
        // String newToken = createJWT("token1", "pim@thehyve.nl", null);
        // boolean accessToken = isValid(token);
        try {
            // String idToken = token.getAdditionalInformation().get("id_token").toString();

            final Jwt tokenDecoded = myDecodeAndVerify(tokenString, verifier(kid));
        } catch (Exception e) {
            System.out.println("Token is not valid!!!");
        }
        // if (true) {
        //     System.out.println("Token is valid!!!");
        // } else {
        //     System.out.println("Token is not valid!!!");
        // }
    }
}