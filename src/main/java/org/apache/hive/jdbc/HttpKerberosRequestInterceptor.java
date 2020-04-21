//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package org.apache.hive.jdbc;

import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import org.apache.hive.service.auth.HttpAuthUtils;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.client.CookieStore;
import org.apache.http.protocol.HttpContext;

public class HttpKerberosRequestInterceptor extends HttpRequestInterceptorBase {
    String principal;
    String host;
    String serverHttpUrl;
    boolean assumeSubject;
    private static ReentrantLock kerberosLock = new ReentrantLock(true);

    public HttpKerberosRequestInterceptor(String principal, String host, String serverHttpUrl, boolean assumeSubject, CookieStore cs, String cn, boolean isSSL, Map<String, String> additionalHeaders, Map<String, String> customCookies) {
        super(cs, cn, isSSL, additionalHeaders, customCookies);
        this.principal = principal;
        this.host = host;
        this.serverHttpUrl = serverHttpUrl;
        this.assumeSubject = assumeSubject;
    }

    protected void addHttpAuthHeader(HttpRequest httpRequest, HttpContext httpContext) throws Exception {
        try {
            kerberosLock.lock();
            System.out.println("----->HttpKerberosRequestInterceptor-- >>> principal:"+ this.principal + " host:"+ this.host + " serverHttpUrl:"+ this.serverHttpUrl + " assumeSubject"+ this.assumeSubject);
            String kerberosAuthHeader = HttpAuthUtils.getKerberosServiceTicket(this.principal, this.host, this.serverHttpUrl, this.assumeSubject);
            httpRequest.addHeader("Authorization: Negotiate ", kerberosAuthHeader);
        } catch (Exception var7) {
            throw new HttpException(var7.getMessage(), var7);
        } finally {
            kerberosLock.unlock();
        }

    }
}
