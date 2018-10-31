/*
 * Copyright (c) 2018 Doyensec LLC.
 */

package burp;

import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

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
            stderr.format("Exception: %s %s %s\n%s", e.getClass().getCanonicalName(), e.getCause(),  e.getMessage(), e.getStackTrace());
        }
    }

    private static void legacyRegisterExtenderCallbacks(IBurpExtenderCallbacks callbacks)
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, InstantiationException, ClassNotFoundException {
        Class clazz = loadClass("burp.LegacyBurpExtender");
        Object obj = clazz.newInstance();
        Method method = clazz.getMethod("registerExtenderCallbacks", IBurpExtenderCallbacks.class);
        method.invoke(obj, callbacks);
    }

    private static Class loadClass(String name) throws ClassNotFoundException{
        Class clazz = null;
        Iterator<ClassLoader> cls = getClassloaders().iterator();
        ClassLoader i = null;
        if (cls.hasNext())
            i = cls.next();
        List<String> css = new ArrayList<>();

        while (clazz == null && i != null) {
            css.add(i.getClass().getCanonicalName());
            try {
                clazz = i.loadClass(name);
                clazz.newInstance();
            } catch (ClassNotFoundException|InstantiationException|IllegalAccessException|NoClassDefFoundError e) {
                clazz = null;
            }
            i = i.getParent();
            if (i == null && cls.hasNext())
                i = cls.next();
        }

        if (clazz == null) {
            throw new ClassNotFoundException("loadClass cannot find the class in any classloader (" + String.join(", ", css) + ").");
        }

        return clazz;
    }

    private static Iterable<ClassLoader> getClassloaders() {
        List<ClassLoader> cls = new ArrayList<>();
        for (Thread t : Thread.getAllStackTraces().keySet()) {
            ClassLoader cl = t.getContextClassLoader();
            if (cl != null) {
                cls.add(cl);
            }
        }
        return cls;
    }
}