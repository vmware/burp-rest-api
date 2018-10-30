/*
 * Copyright (c) 2018 Doyensec LLC.
 */

package burp;

import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * burp.BurpExtender is the burp-rest-api 2nd-gen entrypoint.
 *
 * This class search for the burp.LegacyBurpExtender 1st-gen entrypoint in the default classpath in order to execute it
 * through reflection. This is needed in order to made Burp able to load more than one extension at a time.
 */
public class BurpExtender implements IBurpExtender {
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
        try {
            legacyRegisterExtenderCallbacks(callbacks);
        } catch (Exception e) {
            PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
            stderr.format("Exception: %s %s %s", e.getClass().getCanonicalName(), e.getCause(),  e.getMessage());
        }
    }

    private static void legacyRegisterExtenderCallbacks(IBurpExtenderCallbacks callbacks)
            throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException, InstantiationException {

        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        Class clazz = classLoader.loadClass("burp.LegacyBurpExtender");
        Object obj = clazz.newInstance();
        Method method = clazz.getMethod("registerExtenderCallbacks", IBurpExtenderCallbacks.class);
        method.invoke(obj, callbacks);
    }
}