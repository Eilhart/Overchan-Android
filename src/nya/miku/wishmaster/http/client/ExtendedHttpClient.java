/*
 * Overchan Android (Meta Imageboard Client)
 * Copyright (C) 2014-2016  miku-nyan <https://github.com/miku-nyan>
 *     
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package nya.miku.wishmaster.http.client;

import java.io.Closeable;
import java.util.Date;
import android.os.Build;
import android.content.SharedPreferences;
import android.content.SharedPreferences.OnSharedPreferenceChangeListener;
import android.webkit.CookieManager;
import nya.miku.wishmaster.R;
import nya.miku.wishmaster.common.MainApplication;
import nya.miku.wishmaster.http.HttpConstants;
import nya.miku.wishmaster.http.SSLCompatibility;
import cz.msebera.android.httpclient.HttpHost;
import cz.msebera.android.httpclient.client.CookieStore;
import cz.msebera.android.httpclient.client.HttpClient;
import cz.msebera.android.httpclient.client.config.CookieSpecs;
import cz.msebera.android.httpclient.client.config.RequestConfig;
import cz.msebera.android.httpclient.cookie.Cookie;
import cz.msebera.android.httpclient.impl.client.BasicCookieStore;
import cz.msebera.android.httpclient.impl.client.HttpClients;

/**
 * Основной HTTP-клиент, используемый в проекте.<br>
 * Экземпляр хранит свои настройки HTTP-прокси сервера и объект хранилища Cookies,
 * см. методы {@link #getProxy()} и {@link #getCookieStore()}.
 * @author miku-nyan
 *
 */

public class ExtendedHttpClient extends HttpClientWrapper {

    static class ExtendedCookieStore extends BasicCookieStore {
        private static void addCookieToManager(Cookie cookie) {
            String cookieString = cookie.getName() + "=" + cookie.getValue() + "; Domain=" + cookie.getDomain();
            CookieManager.getInstance().setCookie(cookie.getDomain(), cookieString);
        }
        @Override
        public void addCookie(Cookie cookie) {
            addCookieToManager(cookie);
            super.addCookie(cookie);
        }
        @Override
        public void addCookies(Cookie[] cookies) {
            for (Cookie cookie : cookies) {
                addCookieToManager(cookie);
            }
            super.addCookies(cookies);
        }
        @Override
        public void clear() {
            CookieManager.getInstance().removeAllCookie();
            super.clear();
        }
        @Override
        public boolean clearExpired(Date date) {
            CookieManager.getInstance().removeExpiredCookie();
            return super.clearExpired(date);
        }
    }

    private OnSharedPreferenceChangeListener prefsListener;
    private final CookieStore cookieStore;
    private final HttpHost proxy;
    private volatile HttpClient httpClient;
    
    /**
     * Получить хранилище Cookies данного экземпляра
     */
    public CookieStore getCookieStore() {
        return cookieStore;
    }
    
    /**
     * Получить значение HTTP-прокси данного экземпляра
     */
    public HttpHost getProxy() {
        return proxy;
    }
    
    @Override
    protected HttpClient getClient() {
        if (httpClient == null) {
            synchronized (this) {
                if (httpClient == null) {
                    httpClient = build(proxy, getCookieStore());
                }
                if (prefsListener == null) {
                    prefsListener = new OnSharedPreferenceChangeListener() {
                        @Override
                        public void onSharedPreferenceChanged(SharedPreferences preferences, String key) {
                            if (key.equals(MainApplication.getInstance().resources.getString(R.string.pref_key_user_agent_string))) {
                                if (httpClient != null) {
                                    if (httpClient instanceof Closeable) {
                                        try {
                                            ((Closeable)httpClient).close();
                                        } catch (Exception e) {}
                                    }
                                    httpClient = null;
                                }
                            }
                        }
                    };
                    MainApplication.getInstance().preferences.registerOnSharedPreferenceChangeListener(prefsListener);
                }
            }
        }
        return httpClient;
    }
    
    /**
     * Конструктор
     * @param proxy адрес HTTP прокси (возможно null)
     */
    public ExtendedHttpClient(HttpHost proxy) {
        super();
        this.cookieStore = Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT
            ? new BasicCookieStore()
            : new ExtendedCookieStore();
        this.proxy = proxy;
    }
    
    /**
     * Получить билдер конфига запросов с параметрами по умолчанию для данного класса
     * @param timeout значение таймпута
     */
    public static RequestConfig.Builder getDefaultRequestConfigBuilder(int timeout) {
        return RequestConfig.custom().
                setConnectTimeout(timeout).
                setConnectionRequestTimeout(timeout).
                setSocketTimeout(timeout).
                setCookieSpec(CookieSpecs.STANDARD).
                setStaleConnectionCheckEnabled(false);
    }
    
    private static HttpClient build(final HttpHost proxy, CookieStore cookieStore) {
        SSLCompatibility.waitIfInstallingAsync();
        return HttpClients.custom().
                setDefaultRequestConfig(getDefaultRequestConfigBuilder(HttpConstants.DEFAULT_HTTP_TIMEOUT).build()).
                setUserAgent(MainApplication.getInstance().settings.getUserAgentString()).
                setProxy(proxy).
                setDefaultCookieStore(cookieStore).
                setSSLSocketFactory(ExtendedSSLSocketFactory.getSocketFactory()).
                build();
    }
}
