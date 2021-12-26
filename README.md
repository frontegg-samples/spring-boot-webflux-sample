# Getting Started with Frontegg authorization using Spring Boot and Webflux 

## Overview
This sample shows how to protect your Spring Boot - Webflux application routes using a custom security method and JWT utils.

## Step-By-Step Guide
Follow the steps below to validate tokens with Spring Boot and Webflux

### Step 1: Add required Dependencies

``` xml
                <dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-webflux</artifactId>
		</dependency>
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-api</artifactId>
			<version>${io.jsonwebtoken.version}</version>
		</dependency>
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-impl</artifactId>
			<version>${io.jsonwebtoken.version}</version>
			<scope>runtime</scope>
		</dependency>
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-jackson</artifactId>
			<version>${io.jsonwebtoken.version}</version>
			<scope>runtime</scope>
		</dependency>

```



### Step 2: Add JWTUtil
JWTUtil class purpose is to handle the JWT: 
1. Validate the signature and expiration 
2. Extract roles and permissions

First, when loading the class, we get the Jwks from the well known URL:
``` java
    private void loadKeys() throws IOException, InterruptedException, NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .GET()
                    .uri(URI.create(fronteggWorkspaceUrl + "/.well-known/jwks.json"))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            String body = response.body();
            JsonObject data = gson.fromJson(body, JsonObject.class);

            JsonArray arr = (JsonArray)data.get("keys");
            for(int i=0; i<arr.size();i++) {
                String keyId = ((JsonObject)arr.get(i)).get("kid").getAsString();
                keys.put(keyId, getKey((JsonObject) arr.get(i)));
            }
            
        } catch (Exception e) {
            System.out.println("Got error when fetching Public Key " + e.getMessage());
            throw e;
        }
    }
    
    private PublicKey getKey(JsonObject jwk) throws NoSuchAlgorithmException, InvalidKeySpecException {

        BigInteger modulus = new BigInteger(1, new Base64URL(jwk.get("n").getAsString()).decode());
        BigInteger exponent = new BigInteger(1, new Base64URL(jwk.get("e").getAsString()).decode());

        PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
        return pub;
    }
```
*Note:* 
The `fronteggWorkspaceUrl` property should be copied from frontegg Portal in the domains tab in worksapce settings.

Notice that we get from the .well-known API a list of keys. In the method, we save all the given keys.
When parsing the JWT, we get the right key to validate the JWT by the `kid` property.

``` java
    public Claims getAllClaimsFromToken(String token) {
        Key key = getKey(token);
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }

    private Key getKey(String token) {
        String[] chunks = token.split("\\.");
        Base64.Decoder decoder = Base64.getDecoder();
        String header = new String(decoder.decode(chunks[0]));
        String kid = gson.fromJson(header, JsonObject.class).get("kid").getAsString();
        Key key = this.keys.get(kid);
        return key;
    }
    
    public Date getExpirationDateFromToken(String token) {
        return getAllClaimsFromToken(token).getExpiration();
    }

    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }
    
    public Boolean validateToken(String token) {
        return !isTokenExpired(token);
    }

```

#### Note: In this class you use the Public Key with whome the JWT was generated. You can get the Key from Frontegg Portal.

### Step 3: Add Custom Security Method (FronteggSecurityMethod.java)
Next, you add your custom security method, that will be later used in the Controller. In these methods you shouldn't validate the token, as it is already validated by the AuthenticationManager.java Bean
In the following example, we created two methods, one that validates roles, and one that validates permissions. You can combne them both into one method if needed.
#### Note: the component holding these methods must have a name in its @Component annotation: ``` @Component("fronteggSecurityMethod")``` 
``` java
    public boolean isAuthorizedWithRoles(String authorizationHeader, List<String> roles) {
        return validateExistingClaims(authorizationHeader, "roles", roles);
    }

    public boolean isAuthorizedWithPermissions(String authorizationHeader, List<String> permissions) {
        return validateExistingClaims(authorizationHeader, "permissions", permissions);
    }

    private boolean validateExistingClaims(String authorizationHeader, String claimName, List<String> elements) {
        String token = authorizationHeader.replace("Bearer ", "");
        Claims claims = jwtUtil.getAllClaimsFromToken(token);
        List<String> tokenElements = (List<String>) claims.get(claimName);
        if(tokenElements == null || tokenElements.size() == 0)
            return false;
        tokenElements.retainAll(elements);
        if(tokenElements.size() != 0)
            return true;
        return false;
    }

```

### Step 4: Add AuthenticationManager that validates the JWT token
Next, you create the Bean that validates the token for each request that reaches your service.

``` java
    public Mono<Authentication> authenticate(Authentication authentication) {
        String authToken = authentication.getCredentials().toString();
        String username = jwtUtil.getUsernameFromToken(authToken);
        return Mono.just(jwtUtil.validateToken(authToken))
            .filter(valid -> valid)
            .switchIfEmpty(Mono.empty())
            .map(valid -> {
                ...
            });
    }
```

### Step 5: Add authorization to WebSecurityConfig
In this step,you add the basics of the authentication and authorization configuration of the service. Ususally, you'll already have this configured. Just add the needed configuration to your existing Bean.
``` java
@AllArgsConstructor
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class WebSecurityConfig {

    private AuthenticationManager authenticationManager;
    private SecurityContextRepository securityContextRepository;

    @Bean
    public SecurityWebFilterChain securitygWebFilterChain(ServerHttpSecurity http) {
        return http
                .exceptionHandling()
                .authenticationEntryPoint((swe, e) -> 
                    Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED))
                ).accessDeniedHandler((swe, e) -> 
                    Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.FORBIDDEN))
                ).and()
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .authenticationManager(authenticationManager)
                .securityContextRepository(securityContextRepository)
                .authorizeExchange()
                ...
                .anyExchange().authenticated()
                .and().build();
    }
}

```

### Step 6: Use custom security method in your Controllers
Finally, you can now use your custom security methods in your controller using SpEL 
``` java
    @GetMapping("/resource/with_roles")
    @PreAuthorize("@fronteggSecurityMethod.isAuthorizedWithRoles(#header, {'super_admin'})")
    public Mono<ResponseEntity<Message>> withRoles(@RequestHeader("Authorization") String header) {
        ...
    }

    @GetMapping("/resource/with_permissions")
    @PreAuthorize("@fronteggSecurityMethod.isAuthorizedWithPermissions(#header, {'read-slack', 'read-webhooks'})")
    public Mono<ResponseEntity<Message>> withPermissions(@RequestHeader("Authorization") String header) {
        ...
    }
```