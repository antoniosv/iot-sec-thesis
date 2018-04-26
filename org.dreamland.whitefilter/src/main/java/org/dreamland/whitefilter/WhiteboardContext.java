/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.dreamland.whitefilter;

import java.io.IOException;
import java.net.URL;
import java.util.Base64;
import java.text.ParseException;
import java.util.StringTokenizer;

import java.security.interfaces.*;
import javax.crypto.*;
import java.security.*;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.osgi.service.http.HttpContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A custom http context that does enforces basic authentication
 */
public class WhiteboardContext implements HttpContext {

    private static final Logger LOG = LoggerFactory.getLogger(WhiteboardContext.class);
    private static KeyPair kp = null;
    private static int counter = 0; // this experiment shows that the variable doesn't get set to 0 on every http request. this would be shared among servlets

    public boolean handleSecurity(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
	//	LOG.info("cookie:" + request.getHeader("cookie"));
	//LOG.info("Counter: " + counter++);
	String freshToken = "";
	if(request.getHeader("Authorization") == null && request.getHeader("Cookie") == null) {
	    // this should redirect to a login form
	    LOG.info("No header -- Forbidden access!");
	    response.addHeader("WWW-Authenticate", "Basic realm=\"Test Realm\"");
	    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
	    return false;
	}
	try {
	    // try form authentication first
	    if(formAuthenticated(request)) {
		freshToken = "";
		try {
		    freshToken = generateJwt("baidi","admin");
		    if(verifyJwt(freshToken)) {
			LOG.info("token: " + freshToken);
			response.addHeader("Set-Cookie", freshToken);
		    } } catch(JOSEException e) {}		
	    }
	    else if(jwtAuthenticated(request)) {
		return true;		
	    } else if(basicAuthenticated(request)){
		LOG.info("trying basic auth now...");
		freshToken = "";
		try {
		    freshToken = generateJwt("baidi","admin");
		    if(verifyJwt(freshToken)) {
			LOG.info("token: " + freshToken);
			response.addHeader("Set-Cookie", freshToken);
		    } } catch(JOSEException e) {}
		return true;
	    } else {
		LOG.info("Wrong credentials -- Forbidden access!");
		response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
		return false;
	    }
	} catch(JOSEException e) {
	    // skip
	}
	return false;
    }

    protected KeyPair getKeyPair() {
	if(kp == null) {
	    try {
	    KeyPairGenerator keyGenerator = null;
	    keyGenerator = KeyPairGenerator.getInstance("RSA");
	    keyGenerator.initialize(1024);
	    kp = keyGenerator.genKeyPair();
	    } catch(NoSuchAlgorithmException e) {}
	}
	return kp;
    }

    protected String generateJwt(String username, String claim) throws JOSEException {
	RSAPublicKey publicKey = (RSAPublicKey)getKeyPair().getPublic();
	RSAPrivateKey privateKey = (RSAPrivateKey)getKeyPair().getPrivate();
	JWSSigner signer = new RSASSASigner(privateKey);

	// what's the key ID?
	JWSObject jwsObject = new JWSObject(
    					    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("123").build(),
    					    new Payload(username));
    	jwsObject.sign(signer);
    	String token = jwsObject.serialize();	
	return token;
	
    }

    protected boolean verifyJwt(String token) throws JOSEException{
	boolean valid = false;
	RSAPublicKey publicKey = (RSAPublicKey)getKeyPair().getPublic();
	JWSObject jwsObject = null;

	if(token != null && !token.isEmpty()) {
	    try {
		jwsObject = JWSObject.parse(token);
	    } catch(ParseException e) { LOG.info("problem parsing token: " + token); }
	}
	LOG.info("Before verifier");
	JWSVerifier verifier = new RSASSAVerifier(publicKey);
	if(jwsObject != null) {
	    valid = jwsObject.verify(verifier);
	    LOG.info("Token Payload: " + jwsObject.getPayload().toString());
	}	
	// valid = jwsObject.getPayload().toString().equals("baidi");
	return valid;
    }

    protected boolean formAuthenticated(HttpServletRequest request) throws JOSEException {
	return false;
    }

    protected boolean jwtAuthenticated(HttpServletRequest request) throws JOSEException {
	String token = "";
	boolean verified;
	String authHeader = request.getHeader("Authorization");
	String cookie = request.getHeader("Cookie");

	LOG.info("trying to do jwt auth...");
	
	if (authHeader == null && cookie == null) {
	    return false;
	}

	if (cookie != null) {
	    token = cookie;
	} else if(authHeader != null) {
	    StringTokenizer tokenizer = new StringTokenizer(authHeader, " ");
	    String authType = tokenizer.nextToken();
	    if ("Bearer".equalsIgnoreCase(authType)) {
		token = tokenizer.nextToken();
	    }
	}  
	LOG.info("raw token: " + token);
	verified = verifyJwt(token);
	if(verified) {
	    LOG.info("JWT Authentication successful");	    
	} else {
	    LOG.info("something didn't work in the jwt authentication");
	}
    	return verified;
    }

    protected String extractUserBasic(HttpServletRequest request) {
	String authzHeader = request.getHeader("Authorization");
	String usernameAndPassword = new String(Base64.getDecoder().decode(authzHeader.substring(6).getBytes()));
	int userNameIndex = usernameAndPassword.indexOf(":");
	String username = usernameAndPassword.substring(0, userNameIndex);
	return username;
    }

    protected boolean basicAuthenticated(HttpServletRequest request) {	
	request.setAttribute(AUTHENTICATION_TYPE, HttpServletRequest.BASIC_AUTH);

	String authHeader = request.getHeader("Authorization");
	if (authHeader == null) {
	    return false;
	}
	StringTokenizer tokenizer = new StringTokenizer(authHeader, " ");
	String authType = tokenizer.nextToken();
	if (!"Basic".equalsIgnoreCase(authType)) {
	    return false;
	}
	
	//	LOG.info("Authz header: " +  authHeader);
	String usernameAndPassword = new String(Base64.getDecoder().decode(authHeader.substring(6).getBytes()));
	int userNameIndex = usernameAndPassword.indexOf(":");
	String username = usernameAndPassword.substring(0, userNameIndex);
	String password = usernameAndPassword.substring(userNameIndex + 1);

	boolean success = ((username.equals("poi") && password.equals("poi")));
	if(success) {
	    request.setAttribute(REMOTE_USER, "boy");
	}
	return success;
    }

    private boolean dbAuthenticate(String username, String password) throws Exception {
	// calculate password hash
	// query to database or file to check if username&password are valid	
	return false;
    }
    

    public URL getResource(final String name) {
	throw new IllegalStateException("Can't access this");
    }

    public String getMimeType(String s) {
	throw new IllegalStateException("Not allowed!");
    }
}
