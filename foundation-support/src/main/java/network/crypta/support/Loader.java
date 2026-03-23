package network.crypta.support;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Reflection utilities for loading classes and instantiating objects.
 *
 * <p>This utility caches {@link Class} lookups by fully qualified name and provides convenience
 * methods to create new instances using public constructors selected by parameter types. It does
 * not implement or delegate to a custom {@code ClassLoader}; it relies on the standard {@link
 * Class#forName(String)} semantics provided by the platform.
 *
 * <p>Thread-safety: {@link #load(String)} maintains an internal concurrent cache and is safe for
 * concurrent use. Cached entries are not evicted for the lifetime of the JVM.
 *
 * @author <a href=mailto:blanu@uts.cc.utexas.edu>Brandon Wiley</a>
 * @author oskar (I made this a generic loader, not just for messages).
 */
public class Loader {

  private static final Map<String, Class<?>> classes = new ConcurrentHashMap<>();

  private Loader() {
    // Prevent instantiation of a utility class.
  }

  /**
   * Loads a class by fully qualified name with caching.
   *
   * <p>On the first call for a given name this method delegates to {@link Class#forName(String)}
   * and stores the resulting {@link Class} in an internal concurrent cache. Subsequent calls with
   * the same name return the cached instance, avoiding the overhead of repeated lookups.
   *
   * <p>This method is thread-safe. Entries are kept for the duration of the process.
   *
   * @param name fully qualified binary name of the desired class; must not be {@code null}
   * @return the resolved {@link Class}
   * @throws ClassNotFoundException if the class cannot be located
   * @throws NullPointerException if {@code name} is {@code null}
   */
  public static Class<?> load(String name) throws ClassNotFoundException {
    try {
      return classes.computeIfAbsent(name, Loader::loadClassUnchecked);
    } catch (UncheckedClassNotFoundException e) {
      throw (ClassNotFoundException) e.getCause();
    }
  }

  /**
   * Creates an instance of the named class using its public no-argument constructor.
   *
   * <p>The target class is resolved via {@link #load(String)} and then instantiated with its public
   * no-arg constructor. The class must expose such a constructor.
   *
   * @param classname fully qualified name of the class to instantiate; must not be {@code null}
   * @return a new instance of the requested class
   * @throws ClassNotFoundException if the class cannot be located
   * @throws NoSuchMethodException if no public no-arg constructor exists
   * @throws InstantiationException if the class represents an abstract class or cannot be
   *     instantiated
   * @throws IllegalAccessException if the no-arg constructor is not accessible
   * @throws InvocationTargetException if the constructor itself throws an exception
   * @throws NullPointerException if {@code classname} is {@code null}
   */
  public static Object getInstance(String classname)
      throws InvocationTargetException,
          NoSuchMethodException,
          InstantiationException,
          IllegalAccessException,
          ClassNotFoundException {
    return getInstance(classname, new Class<?>[] {}, new Object[] {});
  }

  /**
   * Creates an instance of the named class using a matching public constructor.
   *
   * <p>The class is resolved via {@link #load(String)} and instantiated by locating a public
   * constructor whose parameter types exactly match {@code argtypes}. Note that constructor
   * selection is exact; primitive types (for example, {@code int.class}) do not match their boxed
   * counterparts (for example, {@link Integer}).
   *
   * @param classname fully qualified name of the class to instantiate; must not be {@code null}
   * @param argtypes parameter types for constructor selection; must not be {@code null}
   * @param args constructor arguments; the array length must match {@code argtypes}
   * @return a new instance created by the selected constructor
   * @throws ClassNotFoundException if the class cannot be located
   * @throws NoSuchMethodException if no public constructor with the exact signature exists
   * @throws InstantiationException if the class represents an abstract class or cannot be
   *     instantiated
   * @throws IllegalAccessException if the constructor is not accessible
   * @throws InvocationTargetException if the constructor itself throws an exception
   * @throws NullPointerException if {@code classname}, {@code argtypes}, or {@code args} is {@code
   *     null}
   */
  public static Object getInstance(String classname, Class<?>[] argtypes, Object[] args)
      throws InvocationTargetException,
          NoSuchMethodException,
          InstantiationException,
          IllegalAccessException,
          ClassNotFoundException {
    return getInstance(load(classname), argtypes, args);
  }

  /**
   * Creates an instance of the given class using a matching public constructor.
   *
   * <p>Constructor selection is exact. Primitive parameter types must be declared explicitly in
   * {@code argtypes}; autoboxing does not apply when locating the constructor via reflection.
   *
   * @param c class to instantiate; must not be {@code null}
   * @param argtypes parameter types for constructor selection; must not be {@code null}
   * @param args constructor arguments; the array length must match {@code argtypes}
   * @return a new instance created by the selected constructor
   * @throws NoSuchMethodException if no public constructor with the exact signature exists
   * @throws InstantiationException if {@code c} is abstract or cannot be instantiated
   * @throws IllegalAccessException if the constructor is not accessible
   * @throws InvocationTargetException if the constructor itself throws an exception
   * @throws NullPointerException if any argument is {@code null}
   */
  public static Object getInstance(Class<?> c, Class<?>[] argtypes, Object[] args)
      throws InvocationTargetException,
          NoSuchMethodException,
          InstantiationException,
          IllegalAccessException {
    Constructor<?> con = c.getConstructor(argtypes);
    return con.newInstance(args);
  }

  // Bridge {@link ClassNotFoundException} through {@code computeIfAbsent}, which requires a
  // function that does not declare checked exceptions. The caller unwraps and rethrows it to
  // preserve the public API.
  private static Class<?> loadClassUnchecked(String className) {
    try {
      return Class.forName(className);
    } catch (ClassNotFoundException e) {
      throw new UncheckedClassNotFoundException(e);
    }
  }

  // Internal runtime wrapper used solely to transport a checked exception through lambdas that do
  // not permit checked throws.
  private static final class UncheckedClassNotFoundException extends RuntimeException {
    UncheckedClassNotFoundException(ClassNotFoundException cause) {
      super(cause);
    }
  }
}
