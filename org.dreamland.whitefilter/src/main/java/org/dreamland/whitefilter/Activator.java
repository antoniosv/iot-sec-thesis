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

import java.util.Dictionary;
import java.util.Hashtable;

import javax.servlet.Filter;
import javax.servlet.Servlet;
import javax.servlet.http.HttpServlet;


import org.ops4j.pax.web.extender.whiteboard.ExtenderConstants;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.http.HttpContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class Activator implements BundleActivator {

    private static final Logger LOG = LoggerFactory.getLogger(Activator.class);

    private ServiceRegistration<Servlet> servletFilteredReg;
    private ServiceRegistration<Filter> filterReg;
    private ServiceRegistration<HttpContext> httpContextReg;
    
    public void start(BundleContext bundleContext) {
        System.out.println("alo polisia");
	Dictionary<String, String> props;

	// let's try to register first the custom http context that handles security
	props = new Hashtable<>();
	props.put(ExtenderConstants.PROPERTY_HTTP_CONTEXT_ID, "forbidden");
	httpContextReg = bundleContext.registerService(HttpContext.class, new WhiteboardContext(), props);
	
	//register the servlet
	props = new Hashtable<>();
	//props.put("alias", "/whitefiltered");
	props.put(ExtenderConstants.PROPERTY_ALIAS, "/whitefiltered");
	props.put(ExtenderConstants.PROPERTY_HTTP_CONTEXT_ID, "forbidden");
	servletFilteredReg = bundleContext.registerService(Servlet.class, new WhiteboardServlet("/whitefiltered"), props);
	
	try {	    
	    // and then register the filter
	    props = new Hashtable<>();
	    props.put(ExtenderConstants.PROPERTY_URL_PATTERNS, "whitefiltered/*");
	    filterReg = bundleContext.registerService(Filter.class, new WhiteboardFilter(), props);	    
	} catch(NoClassDefFoundError ignore) {
	    LOG.warn("Cannot start filter example (javax.servlet version?): " + ignore.getMessage());
	}
    }

    public void stop(BundleContext context) {
        System.out.println("Stopping the bundle");

	if (filterReg != null) {
	    filterReg.unregister();
	    filterReg = null;
	}
	
	if (servletFilteredReg != null) {
	    servletFilteredReg.unregister();
	    servletFilteredReg = null;
	}

    }

}
