package com.example.xxe.controllers;

// XML & Transformation Imports
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.StringWriter;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.springframework.core.io.ClassPathResource;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;

@RestController
@RequestMapping("/api/labels")
public class LabelController {

    @PostMapping("/generate")
    @SuppressWarnings("UseSpecificCatch")
    public String generateLabel(@RequestBody String xsltPayload) {
        try {
            InputStream productStream = new ClassPathResource("data/product.xml").getInputStream();
            
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            Document labelDesign = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xsltPayload.getBytes()));

            // Transformer transformer = compileXSLTVulnerable(labelDesign);
            Transformer transformer = compileXSLTSecure(labelDesign);
            
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(productStream), new StreamResult(writer));
            
            return writer.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * KB: XXE fix — TransformerFactory with security attributes disabled.
     * Rule: java.lang.security.audit.xxe.transformerfactory-dtds-not-disabled
     */
    public static Transformer compileXSLTVulnerable(final Document inXslt) throws TransformerConfigurationException {
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        synchronized (inXslt) {
            return factory.newTransformer(new DOMSource(inXslt));
        }
    }

    /**
     * SECURE: The Remediation.
     * Explicitly disables external DTDs and Stylesheets.
     */
    public static Transformer compileXSLTSecure(final Document inXslt) throws TransformerConfigurationException {
        TransformerFactory factory = TransformerFactory.newInstance();
        
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");

        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

        synchronized (inXslt) {
            return factory.newTransformer(new DOMSource(inXslt));
        }
    }
}