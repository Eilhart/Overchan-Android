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

package nya.miku.wishmaster.chans.kohlchan;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.preference.EditTextPreference;
import android.preference.Preference;
import android.preference.PreferenceGroup;
import android.support.v4.content.res.ResourcesCompat;
import android.text.InputType;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import nya.miku.wishmaster.R;
import nya.miku.wishmaster.api.AbstractLynxChanModule;
import nya.miku.wishmaster.api.interfaces.CancellableTask;
import nya.miku.wishmaster.api.interfaces.ProgressListener;
import nya.miku.wishmaster.api.models.BoardModel;
import nya.miku.wishmaster.api.models.SimpleBoardModel;
import nya.miku.wishmaster.common.IOUtils;
import nya.miku.wishmaster.common.Logger;
import nya.miku.wishmaster.http.streamer.HttpRequestModel;
import nya.miku.wishmaster.http.streamer.HttpResponseModel;
import nya.miku.wishmaster.http.streamer.HttpStreamer;
import nya.miku.wishmaster.http.streamer.HttpWrongStatusCodeException;

public class KohlchanModule extends AbstractLynxChanModule {
    private static final String TAG = "KohlchanModule";
    
    static final String CHAN_NAME = "kohlchan.net";
    private static final String DISPLAYING_NAME = "Kohlchan";
    private static final String DEFAULT_DOMAIN = "kohlchan.net";
    private static final String PREF_KEY_DOMAIN = "domain";
    private static final List<String> DOMAINS_LIST = Arrays.asList(new String[] {
            DEFAULT_DOMAIN, "kohlchan.mett.ru", "kohlchankxguym67.onion", "fastkohlp6h2seef.onion"
    });
    private static final String DOMAINS_HINT = "kohlchan.net, kohlchan.mett.ru, kohlchankxguym67.onion, fastkohlp6h2seef.onion (1 hop)";
    
    private static final String[] ATTACHMENT_FORMATS = new String[] {
            "jpg", "jpeg", "bmp", "gif", "png", "mp3", "ogg", "flac", "opus", "webm", "mp4", "7z", "zip", "pdf", "epub", "txt" };
    
    private String domain;

    public KohlchanModule(SharedPreferences preferences, Resources resources) {
        super(preferences, resources);
    }
    
    @Override
    public String getChanName() {
        return CHAN_NAME;
    }
    
    @Override
    protected void initHttpClient() {
        updateDomain(preferences.getString(getSharedKey(PREF_KEY_DOMAIN), DEFAULT_DOMAIN));
    }

    @Override
    protected String getUsingDomain() {
        return domain;
    }

    private void addDomainPreferences(PreferenceGroup group) {
        Context context = group.getContext();
        Preference.OnPreferenceChangeListener updateDomainListener = new Preference.OnPreferenceChangeListener() {
            @Override
            public boolean onPreferenceChange(Preference preference, Object newValue) {
                if (preference.getKey().equals(getSharedKey(PREF_KEY_DOMAIN))) {
                    updateDomain((String) newValue);
                    return true;
                }
                return false;
            }
        };
        EditTextPreference domainPref = new EditTextPreference(context);
        domainPref.setTitle(R.string.pref_domain);
        domainPref.setDialogTitle(R.string.pref_domain);
        domainPref.setSummary(resources.getString(R.string.pref_domain_summary, DOMAINS_HINT));
        domainPref.setKey(getSharedKey(PREF_KEY_DOMAIN));
        domainPref.getEditText().setHint(DEFAULT_DOMAIN);
        domainPref.getEditText().setSingleLine();
        domainPref.getEditText().setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        domainPref.setOnPreferenceChangeListener(updateDomainListener);
        group.addPreference(domainPref);
    }

    @Override
    public void addPreferencesOnScreen(PreferenceGroup preferenceGroup) {
        addDomainPreferences(preferenceGroup);
        super.addPreferencesOnScreen(preferenceGroup);
    }

    @Override
    protected String[] getAllDomains() {
        String curDomain = getUsingDomain();
        String[] domains;
        if (DOMAINS_LIST.contains(curDomain)) {
            domains = DOMAINS_LIST.toArray(new String[DOMAINS_LIST.size()]);
        } else {
            domains = DOMAINS_LIST.toArray(new String[DOMAINS_LIST.size() + 1]);
            domains[DOMAINS_LIST.size()] = curDomain;
        }
        return domains;
    }

    private void updateDomain(String domain) {
        if (domain.endsWith("/")) domain = domain.substring(0, domain.length() - 1);
        if (domain.contains("//")) domain = domain.substring(domain.indexOf("//") + 2);
        if (domain.equals("")) domain = DEFAULT_DOMAIN;
        this.domain = domain;
    }
    
    @Override
    public String getDisplayingName() {
        return DISPLAYING_NAME;
    }
    
    @Override
    protected boolean canCloudflare() {
        return true;
    }
    
    @Override
    protected boolean canHttps() {
        return true;
    }
    
    @Override
    public Drawable getChanFavicon() {
        return ResourcesCompat.getDrawable(resources, R.drawable.favicon_kohlchan, null);
    }
    
    @Override
    public SimpleBoardModel[] getBoardsList(ProgressListener listener, CancellableTask task, SimpleBoardModel[] oldBoardsList) throws Exception {
        String url = getUsingUrl() + ".static/pages/sidebar.html";

        HttpResponseModel responseModel = null;
        KohlBoardsListReader in = null;
        HttpRequestModel rqModel = HttpRequestModel.builder().setGET().setCheckIfModified(oldBoardsList != null).build();
        try {
            responseModel = HttpStreamer.getInstance().getFromUrl(url, rqModel, httpClient, listener, task);
            if (responseModel.statusCode == 200) {
                in = new KohlBoardsListReader(responseModel.stream);
                if (task != null && task.isCancelled()) throw new Exception("interrupted");
                return in.readBoardsList();
            } else {
                if (responseModel.notModified()) return oldBoardsList;
                byte[] html = null;
                try {
                    ByteArrayOutputStream byteStream = new ByteArrayOutputStream(1024);
                    IOUtils.copyStream(responseModel.stream, byteStream);
                    html = byteStream.toByteArray();
                } catch (Exception e) {}
                throw new HttpWrongStatusCodeException(responseModel.statusCode, responseModel.statusCode + " - " + responseModel.statusReason, html);
            }
        } catch (HttpWrongStatusCodeException e) {
            checkCloudflareError(e, url);
            throw e;
        } catch (Exception e) {
            if (responseModel != null) HttpStreamer.getInstance().removeFromModifiedMap(url);
            throw e;
        } finally {
            IOUtils.closeQuietly(in);
            if (responseModel != null) responseModel.release();
        }
    }

    @Override
    protected Map<String, SimpleBoardModel> getBoardsMap(ProgressListener listener, CancellableTask task) throws Exception {
        try {
            return super.getBoardsMap(listener, task);
        } catch (Exception e) {
            Logger.e(TAG, e);
            return Collections.emptyMap();
        }
    }
    
    @Override
    public BoardModel getBoard(String shortName, ProgressListener listener, CancellableTask task) throws Exception {
        BoardModel model = super.getBoard(shortName, listener, task);
        model.defaultUserName = "Bernd";
        model.attachmentsMaxCount = 4;
        model.allowNames = false;
        model.allowEmails = false;
        model.attachmentsFormatFilters = ATTACHMENT_FORMATS;
        return model;
    }
}
