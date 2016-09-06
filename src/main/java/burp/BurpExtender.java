package burp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.PrintWriter;

/**
 * Copyright VMware, Inc. All rights reserved. -- VMware Confidential
 */
public class BurpExtender implements IBurpExtender {
   private static final Logger log = LoggerFactory.getLogger(BurpExtender.class);
   private static BurpExtender instance; // = new BurpExtender();
   private IBurpExtenderCallbacks callbacks;
   private IExtensionHelpers helpers;

   public static BurpExtender getInstance() {
      return instance;
   }

   /**
    * This method is invoked when the extension is loaded. It registers an
    * instance of the
    * <code>IBurpExtenderCallbacks</code> interface, providing methods that may
    * be invoked by the extension to perform various actions.
    *
    * @param callbacks An
    *                  <code>IBurpExtenderCallbacks</code> object.
    */
   @Override
   public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
      log.info("Registering the Burp Extension");
      // set our extension name
      String extensionName = "Burp Rest Extension";
      log.info("Setting the Burp Extension Name: {}", extensionName);
      callbacks.setExtensionName(extensionName);
      this.callbacks = callbacks;
      this.helpers = callbacks.getHelpers();
      instance = this;

      // obtain our output and error streams
      PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
      PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);

      // write a message to our output stream
      stdout.println("Checking output stream");

      // write a message to our error stream
      stderr.println("Checking error strem");

      // write a message to the Burp alerts tab
      callbacks.issueAlert("Checking the alerts tab");
   }

   public IBurpExtenderCallbacks getCallbacks() {
      return callbacks;
   }

   public IExtensionHelpers getHelpers() {
      return helpers;
   }
}
