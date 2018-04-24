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

    public boolean handleSecurity(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
	if(request.getHeader("Authorization") == null) {
	    LOG.info("Forbidden access!");
	    response.addHeader("WWW-Authenticate", "Basic realm=\"Test Realm\"");
	    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
	    return false;
	}
	if(basicAuthenticated(request)) {
	    return true;
	} else {
	    LOG.info("Forbidden access!");
	    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
	    return false;
	}	    	
    }

    protected boolean jwtAuthenticated(HttpServletRequest request) throws JOSEException{
    	KeyPairGenerator keyGenerator = null;
    	try {
    	keyGenerator = KeyPairGenerator.getInstance("RSA");
    	keyGenerator.initialize(1024);
    	} catch(NoSuchAlgorithmException e) {
    	    // skip
    	}

    	RSAPublicKey publicKey = null; 
    	RSAPrivateKey privateKey = null;
    	try {	    
    	    KeyPair kp = keyGenerator.genKeyPair();
    	    publicKey = (RSAPublicKey)kp.getPublic();
    	    privateKey = (RSAPrivateKey)kp.getPrivate();	    
    	} catch(Exception e) {
    	    //skip
    	}

    	JWSSigner signer = new RSASSASigner(privateKey);

    	JWSObject jwsObject = new JWSObject(
    					    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("123").build(),
    					    new Payload("Alo polisia"));

    	jwsObject.sign(signer);
	
    	String s = jwsObject.serialize();
    	try {
    	jwsObject = JWSObject.parse(s);
    	} catch(ParseException e) {}
    	JWSVerifier verifier = new RSASSAVerifier(publicKey);

    	LOG.info("Payload: " + jwsObject.getPayload().toString());
	
    	return false;
    }

    protected boolean basicAuthenticated(HttpServletRequest request) {
	request.setAttribute(AUTHENTICATION_TYPE, HttpServletRequest.BASIC_AUTH);

	String authzHeader = request.getHeader("Authorization");
	String usernameAndPassword = new String(Base64.getDecoder().decode(authzHeader.substring(6).getBytes()));
	int userNameIndex = usernameAndPassword.indexOf(":");
	String username = usernameAndPassword.substring(0, userNameIndex);
	String password = usernameAndPassword.substring(userNameIndex + 1);

	boolean success = ((username.equals("poi") && password.equals("poi")));
	if(success) {
	    request.setAttribute(REMOTE_USER, "boy");
	}
	return success;
    }
    

    public URL getResource(final String name) {
	throw new IllegalStateException("Can't access this");
    }

    public String getMimeType(String s) {
	throw new IllegalStateException("Not allowed!");
    }
}
