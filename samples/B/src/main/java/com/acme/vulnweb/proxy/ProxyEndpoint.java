package com.acme.vulnweb.proxy;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

/**
 * Dynamic proxy whose handler dispatches into a vulnerable transformer.
 *
 * <p>The endpoint calls {@code api.call(...)} through a JDK proxy. The concrete work happens in
 * {@link Handler#invoke}. A call graph that does not model proxies sees nothing between the
 * controller and the handler; ReachMap must connect them and mark the hop as an open callback.
 */
@RestController
public class ProxyEndpoint {

    public interface Api {
        String call(String value);
    }

    public static class Handler implements InvocationHandler {
        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            return Gadgets.transform(String.valueOf(args[0]));
        }
    }

    private final Api api = (Api) Proxy.newProxyInstance(
            Api.class.getClassLoader(), new Class<?>[]{Api.class}, new Handler());

    @GetMapping("/proxy")
    public String call(@RequestParam("v") String v) {
        return api.call(v);
    }
}
