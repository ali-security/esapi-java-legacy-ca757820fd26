/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2019 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author kevin.w.wall@gmail.com
 * @since 2019
 */
package org.owasp.esapi.reference.validation;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.EncoderConstants;
import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.SecurityConfigurationWrapper;
import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.ValidationRule;
import org.owasp.esapi.Validator;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.filters.SecurityWrapperRequest;
import org.owasp.esapi.reference.validation.HTMLValidationRule;

import org.junit.Test;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.After;
import org.junit.Rule;
import org.junit.rules.ExpectedException;
import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;

/**
 * The Class HTMLValidationRuleCleanTest.
 *
 * Based on original test cases, testGetValidSafeHTML() and
 * testIsValidSafeHTML() from ValidatorTest by
 *      Mike Fauzy (mike.fauzy@aspectsecurity.com) and
 *      Jeff Williams (jeff.williams@aspectsecurity.com)
 * that were originally part of src/test/java/org/owasp/esapi/reference/ValidatorTest.java.
 *
 * This class tests the cases where the new ESAPI.property
 *      Validator.HtmlValidationAction
 * is set to "clean", which causes certain calls to
 * ESAPI.validator().getValidSafeHTML() or ESAPI.validator().isValidSafeHTML()
 * to simply log a warning and return the cleansed (sanitizied) output rather
 * than throwing a ValidationException when certain unsafe input is
 * encountered.
 */
public class HTMLValidationRuleCleanTest {

	private static class ConfOverride extends SecurityConfigurationWrapper {
        private String desiredReturn = "clean";

		ConfOverride(SecurityConfiguration orig, String desiredReturn) {
			super(orig);
            this.desiredReturn = desiredReturn;
		}

		@Override
		public String getStringProp(String propName) {
            // Would it be better making this file a static import?
			if ( propName.equals( org.owasp.esapi.reference.DefaultSecurityConfiguration.VALIDATOR_HTML_VALIDATION_ACTION ) ) {
                return desiredReturn;
            } else {
                return super.getStringProp( propName );
            }
        }
    }


    /**
     * Default construstor that instantiates a new {@code HTMLValidationRule} test.
     */
    public HTMLValidationRuleCleanTest() {
    }

    @After
    public void tearDown() throws Exception {
        ESAPI.override(null);
    }

	@Before
    public void setUp() throws Exception {
		ESAPI.override(
			new ConfOverride( ESAPI.securityConfiguration(), "clean" )
		);

    }

    @Test
    public void testGetValidSafeHTML() throws Exception {
        System.out.println("getValidSafeHTML");
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();

        HTMLValidationRule rule = new HTMLValidationRule("test");
        ESAPI.validator().addRule(rule);

        assertEquals("Test.", ESAPI.validator().getRule("test").getValid("test", "Test. <script>alert(document.cookie)</script>"));

        String test1 = "<b>Jeff</b>";
        String result1 = instance.getValidSafeHTML("test", test1, 100, false, errors);
        assertEquals(test1, result1);

        String test2 = "<a href=\"http://www.aspectsecurity.com\">Aspect Security</a>";
        String result2 = instance.getValidSafeHTML("test", test2, 100, false, errors);
        assertEquals(test2, result2);

        String test3 = "Test. <script>alert(document.cookie)</script> Cookie :-)";
        assertEquals("Test.  Cookie :-)", rule.getSafe("test", test3));

        assertEquals("Test. &lt;<div>load=alert()</div>", rule.getSafe("test", "Test. <<div on<script></script>load=alert()"));
        assertEquals("Test. <div>b</div>", rule.getSafe("test", "Test. <div style={xss:expression(xss)}>b</div>"));
        assertEquals("Test. alert(document.cookie)", rule.getSafe("test", "Test. <s%00cript>alert(document.cookie)</script>"));
        assertEquals("Test. alert(document.cookie)", rule.getSafe("test", "Test. <s\tcript>alert(document.cookie)</script>"));
        assertEquals("Test. alert(document.cookie)", rule.getSafe("test", "Test. <s\tcript>alert(document.cookie)</script>"));
        // TODO: ENHANCE waiting for a way to validate text headed for an attribute for scripts
        // This would be nice to catch, but just looks like text to AntiSamy
        // assertFalse(instance.isValidSafeHTML("test", "\" onload=\"alert(document.cookie)\" "));
        // String result4 = instance.getValidSafeHTML("test", test4);
        // assertEquals("", result4);
    }

    // FIXME: Change the method name to reflect the CVE once we have a number for this.
    // Test to confirm that CVE-2022-xxxxx (TBD) is fixed. The cause of this was
    // from a subtle botched regex for 'onsiteURL' in all the versions of
    // antsamy-esapi.xml that had been there as far back as ESAPI 1.4!
    //
    // This TBD CVE should arguably get the same CVSSv3 store as the AntiSamy
    // CVE-2021-35043 as the are very similar.
    @Test
    public void testJavaScriptURL() throws Exception {
        System.out.println("testJavaScriptURL");

        String expectedSafeText = "This is safe from XSS. Trust us!";
        String badVoodoo = "<a href=\"javascript:alert(1)\">" + expectedSafeText + "</a>";
        Validator instance = ESAPI.validator();
        ValidationErrorList errorList = new ValidationErrorList();
        String result = instance.getValidSafeHTML("test", badVoodoo, 100, false, errorList);
        assertEquals( expectedSafeText, result );
    }

    // To confirm fix for CVE-2021-35043 in AntiSamy 1.6.5 and later. Actually,
    // it was never really "broken" in ESAPI's "default configuration" because it is
    // triggers an Intrusion Detection when it is checking the canonicalization
    // and the '&#00058' trips it up, that that's pretty much irrelevant given
    // the (TBD) CVE mented in the previous test case.
    //
    // Note: This test assumes a standard default ESAPI.properties file. In
    // particular, the normal canonicalization has to be enabled.
    public void testAntiSamyCVE_2021_35043Fixed() {
        System.out.println("testAntiSamyCVE_2021_35043Fixed");

        String expectedSafeText = "This is safe from XSS. Trust us!";

            // Translates to '<a href="javascript:x=1,alert("boom")".
        String badVoodoo = "<a href=\"javascript&#00058alert(1)>" + expectedSafeText + "</a>";
        Validator instance = ESAPI.validator();
        // ValidationErrorList errorList = new ValidationErrorList();
        boolean result = instance.isValidSafeHTML("CVE-2021-35043", badVoodoo, 200, false);
        assertFalse( result );  // GHSA-r68h-jhhj-9jvm: isValidSafeHTML() now fails closed.
    }

    //
    // GHSA-r68h-jhhj-9jvm: In "clean" mode, Validator.isValidSafeHTML() used to
    // return true for unsafe input because AntiSamy merely sanitized it (and only
    // logged the scan errors), even though callers then go on to use the original,
    // unsanitized input. It now fails closed: it returns true only if AntiSamy
    // reports no scan errors and the sanitized HTML equals the input exactly.
    @Test
    public void testIsValidSafeHTML() {
        System.out.println("isValidSafeHTML");
        Validator instance = ESAPI.validator();

        assertTrue(instance.isValidSafeHTML("test", "<b>Jeff</b>", 100, false));
        assertTrue(instance.isValidSafeHTML("test", "<a href=\"http://www.aspectsecurity.com\">Aspect Security</a>", 100, false));
        assertFalse(instance.isValidSafeHTML("test", "Test. <script>alert(document.cookie)</script>", 100, false));
        assertFalse(instance.isValidSafeHTML("test", "Test. <div style={xss:expression(xss)}>", 100, false));
        assertFalse(instance.isValidSafeHTML("test", "Test. <s%00cript>alert(document.cookie)</script>", 100, false));
        assertFalse(instance.isValidSafeHTML("test", "Test. <s\tcript>alert(document.cookie)</script>", 100, false));
        assertFalse(instance.isValidSafeHTML("test", "Test. <s\r\n\0cript>alert(document.cookie)</script>", 100, false));

        // TODO: waiting for a way to validate text headed for an attribute for scripts
        // This would be nice to catch, but just looks like text to AntiSamy
        // assertFalse(instance.isValidSafeHTML("test", "\" onload=\"alert(document.cookie)\" "));
        ValidationErrorList errors = new ValidationErrorList();
        assertTrue(instance.isValidSafeHTML("test1", "<b>Jeff</b>", 100, false, errors));
        assertTrue(instance.isValidSafeHTML("test2", "<a href=\"http://www.aspectsecurity.com\">Aspect Security</a>", 100, false, errors));
        assertTrue(errors.size() == 0);
        assertFalse(instance.isValidSafeHTML("test3", "Test. <script>alert(document.cookie)</script>", 100, false, errors));
        assertFalse(instance.isValidSafeHTML("test4", "Test. <div style={xss:expression(xss)}>", 100, false, errors));
        assertFalse(instance.isValidSafeHTML("test5", "Test. <s%00cript>alert(document.cookie)</script>", 100, false, errors));
        assertFalse(instance.isValidSafeHTML("test6", "Test. <s\tcript>alert(document.cookie)</script>", 100, false, errors));
        assertFalse(instance.isValidSafeHTML("test7", "Test. <s\r\n\0cript>alert(document.cookie)</script>", 100, false, errors));
        assertTrue(errors.size() == 5);

        // IE conditional comment hiding a script.
        errors = new ValidationErrorList();
        String input = "<!--[if gte IE 4]>\r\n <SCRIPT>alert('XSS');</SCRIPT>\r\n<![endif]-->";
        assertFalse(instance.isValidSafeHTML("test12", input, 100, false)); // Not safe bc sanitizing changes it to "".
        assertFalse(instance.isValidSafeHTML("test12", input, 100, false, errors));
        assertTrue(errors.size() == 1);

        // Same input as testAntiSamyCVE_2021_35043Fixed()
        String expectedSafeText = "This is safe from XSS. Trust us!";
        String badVoodoo = "<a href=\"javascript&#00058alert(1)>" + expectedSafeText + "</a>";
        boolean result = instance.isValidSafeHTML("CVE-2021-35043", badVoodoo, 200, false);
        assertFalse( result );
    }

    // GHSA-r68h-jhhj-9jvm: Even though Validator.HtmlValidationAction is "clean"
    // (so getValidSafeHTML() only logs the AntiSamy scan errors and returns the
    // sanitized output), isValidSafeHTML() must treat AntiSamy scan errors as a
    // failure and record that ValidationException in the error list.
    @Test
    public void testIsValidSafeHTMLFailsOnScanErrorsInCleanMode() throws Exception {
        System.out.println("testIsValidSafeHTMLFailsOnScanErrorsInCleanMode");
        Validator instance = ESAPI.validator();

        String input = "Test. <script>alert(document.cookie)</script>";
        // In "clean" mode, this does not throw; it silently strips the script.
        String sanitized = instance.getValidSafeHTML("scanErrors-get", input, 100, false);
        assertThat(sanitized, not(containsString("script")));

        ValidationErrorList errors = new ValidationErrorList();
        assertFalse(instance.isValidSafeHTML("scanErrors", input, 100, false, errors));
        assertEquals(1, errors.size());
        ValidationException vex = errors.getError("scanErrors");
        assertNotNull(vex);
        assertEquals("scanErrors: Invalid HTML input", vex.getUserMessage());
        // The AntiSamy scan errors themselves are what was detected, not merely the altered output.
        assertThat(vex.getLogMessage(), containsString("does not follow rules"));

        // Exceptions (here, input longer than maxLength) are also reported as not valid.
        errors = new ValidationErrorList();
        assertFalse(instance.isValidSafeHTML("tooLong", "<b>Jeff</b>", 5, false));
        assertFalse(instance.isValidSafeHTML("tooLong", "<b>Jeff</b>", 5, false, errors));
        assertEquals(1, errors.size());

        // Null / empty input is still valid when (and only when) allowNull is true.
        errors = new ValidationErrorList();
        assertTrue(instance.isValidSafeHTML("empty1", "", 100, true));
        assertTrue(instance.isValidSafeHTML("empty2", null, 100, true, errors));
        assertTrue(errors.isEmpty());
        assertFalse(instance.isValidSafeHTML("empty3", "", 100, false));
        assertFalse(instance.isValidSafeHTML("empty4", null, 100, false, errors));
        assertEquals(1, errors.size());
    }

    // GHSA-r68h-jhhj-9jvm: Input that is canonicalized (decoded) before being
    // scanned, or otherwise altered by sanitization, is never reported as valid,
    // because the caller would otherwise go on to use the original, unsanitized input.
    @Test
    public void testIsValidSafeHTMLFailsWhenSanitizingAltersInput() throws Exception {
        System.out.println("testIsValidSafeHTMLFailsWhenSanitizingAltersInput");
        Validator instance = ESAPI.validator();

        String[] payloads = {
            "<b>Jeff",                                                       // Unclosed tag gets closed.
            "Test. <a href=\"javascript:alert(1)\">click me</a>",            // javascript: URL is dropped.
            "<img src=x onerror=alert(1)>",                                  // Event handler / tag dropped.
            "Test. <b onmouseover=alert(1)>Jeff</b>",                        // Event handler attribute dropped.
            " <b>Jeff</b> "                                                  // Even whitespace changes count.
        };

        int testCase = 0;
        for (String payload : payloads) {
            String testId = "altered-" + testCase++;
            ValidationErrorList errors = new ValidationErrorList();
            String sanitized = instance.getValidSafeHTML(testId + "-get", payload, 100, false, errors);
            assertThat(testId + ": expected sanitizing to alter the payload", sanitized, not(equalTo(payload)));
            assertFalse(testId + ": payload should not be valid", instance.isValidSafeHTML(testId, payload, 100, false));
            assertFalse(testId + ": payload should not be valid", instance.isValidSafeHTML(testId, payload, 100, false, errors));
            assertNotNull(testId + ": expected a recorded ValidationException", errors.getError(testId));
        }
    }

    // GHSA-r68h-jhhj-9jvm: isValidSafeHTML() must not report the raw input as valid
    // when AntiSamy had to neutralize the javascript: link in it.
    @Test
    public void testAntiSamyRegressionCDATAWithJavascriptURL() throws Exception {
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();
        String input = "<style/>b<![cdata[</style><a href=javascript:alert(1)>test";
		assertFalse(instance.isValidSafeHTML("test8", input, 100, false, errors));
		String expected = "b&lt;/style&gt;&lt;a href=javascript:alert(1)&gt;test";
		String output = instance.getValidSafeHTML("javascript Link", input, 250, false);
		assertEquals(expected, output);
		assertTrue(errors.size() == 1);
    }

    // GHSA-r68h-jhhj-9jvm: isValidSafeHTML() must not report the raw input as valid
    // when AntiSamy had to neutralize the script tag in it.
    @Test
    public void testScriptTagAfterStyleClosing() throws Exception {
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();
        String input = "<select<style/>W<xmp<script>alert(1)</script>";
		assertFalse(instance.isValidSafeHTML("test9", input, 100, false, errors));
		String expected = "W&lt;script&gt;alert(1)&lt;/script&gt;";
		String output = instance.getValidSafeHTML("escaping style tag attack with script tag", input, 250, false);
		assertEquals(expected, output);
		assertTrue(errors.size() == 1);
    }

    // GHSA-r68h-jhhj-9jvm: isValidSafeHTML() must not report the raw input as valid
    // when AntiSamy had to neutralize the onfocus handler in it.
    @Test
    public void testOnfocusAfterStyleClosing() throws Exception {
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();
        String input = "<select<style/>k<input<</>input/onfocus=alert(1)>";
		assertFalse(instance.isValidSafeHTML("test10", input, 100, false, errors));
		String expected = "k&lt;input/onfocus=alert(1)&gt;";	// Suspicious??? Doesn't agree w/ AntiSamy test. FIXME?
		String output = instance.getValidSafeHTML("escaping style tag attack with onfocus attribute", input, 250, false);
		assertEquals(expected, output);
		assertTrue(errors.size() == 1);
    }

    // FIXME: This problem is a DoS issue that lies within Neko that is only available for Java 8 and later.
    // However, the latest version that is available for Java 7 is Neko 2.24. It is fixed in later versions
    // that are not available for JDK 7 though. The fix will just start using the one the latest Java 8 version
    // of AntiSamy is using and remove our <exclusion> and specific 2.24 dependency from our pom.xml and use whatever
    // AntiSamy provides. All we should need to do is that and remove the @Ignore annotation here.
    @Test
    @Ignore
    public void testNekoDOSWithAnHTMLComment() throws Exception {
    	/**
    	 * FIXME:  This unit test needs to pass before the next ESAPI release once ESAPI starts using JDK 8 as min JDK.
    	 */
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();
        String input = "<!--><?a/";
		assertFalse(instance.isValidSafeHTML("test11", input, 100, false, errors)); // GHSA-r68h-jhhj-9jvm: Not safe bc sanitizing changes it.
		String expected = "&#x3C;!--&#x3E;&#x3C;?a/";
		String output = instance.getValidSafeHTML("escaping style tag attack", input, 250, false);
		assertEquals(expected, output);
		assertTrue(errors.size() == 1);
    }
}
