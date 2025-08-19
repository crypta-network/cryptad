package network.crypta.clients.http.annotation;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * tag a handleMethodXXX with @AllowData(boolean force) to allow payload on the request<br>
 * <br>
 * exception: POST is hard coded with force, RFC says it must have data<br>
 * so tagging it does not have effect<br>
 * <br>
 * <CODE>@AllowData(true)  // request MUST have data</CODE><br>
 * <CODE>@AllowData(false)  // request CAN have data</CODE> <br>
 *
 * @author saces
 */
@Target(METHOD)
@Retention(RUNTIME)
@Documented
public @interface AllowData {
  boolean value() default false;
}
