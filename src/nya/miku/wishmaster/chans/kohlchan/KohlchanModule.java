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
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Bundle;
import android.preference.EditTextPreference;
import android.preference.Preference;
import android.preference.PreferenceGroup;
import android.support.v4.content.res.ResourcesCompat;
import android.text.InputFilter;
import android.text.InputType;
import android.webkit.MimeTypeMap;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.regex.Pattern;

import cz.msebera.android.httpclient.Header;
import cz.msebera.android.httpclient.impl.cookie.BasicClientCookie;
import nya.miku.wishmaster.R;
import nya.miku.wishmaster.api.AbstractLynxChanModule;
import nya.miku.wishmaster.api.interfaces.CancellableTask;
import nya.miku.wishmaster.api.interfaces.ProgressListener;
import nya.miku.wishmaster.api.models.BoardModel;
import nya.miku.wishmaster.api.models.CaptchaModel;
import nya.miku.wishmaster.api.models.DeletePostModel;
import nya.miku.wishmaster.api.models.PostModel;
import nya.miku.wishmaster.api.models.SendPostModel;
import nya.miku.wishmaster.api.models.SimpleBoardModel;
import nya.miku.wishmaster.api.models.UrlPageModel;
import nya.miku.wishmaster.api.util.CryptoUtils;
import nya.miku.wishmaster.api.util.RegexUtils;
import nya.miku.wishmaster.common.IOUtils;
import nya.miku.wishmaster.common.Logger;
import nya.miku.wishmaster.http.ExtendedMultipartBuilder;
import nya.miku.wishmaster.http.streamer.HttpRequestModel;
import nya.miku.wishmaster.http.streamer.HttpResponseModel;
import nya.miku.wishmaster.http.streamer.HttpStreamer;
import nya.miku.wishmaster.http.streamer.HttpWrongStatusCodeException;
import nya.miku.wishmaster.lib.org_json.JSONObject;

public class KohlchanModule extends AbstractLynxChanModule {
    private static final String TAG = "KohlchanModule";
    
    static final String CHAN_NAME = "kohlchan.net";
    private static final String DISPLAYING_NAME = "Kohlchan";
    private static final String DEFAULT_DOMAIN = "kohlchan.net";
    private static final String PREF_KEY_DOMAIN = "domain";
    private static final List<String> DOMAINS_LIST = Arrays.asList(
            DEFAULT_DOMAIN, "kohlchan.mett.ru", "kohlchankxguym67.onion", "fastkohlp6h2seef.onion",
            "kohlchan7cwtdwfuicqhxgqx4k47bsvlt2wn5eduzovntrzvonv4cqyd.onion",
            "fastkohlt5rxcxtl5no7k3efmahlt7mafry7be6yvxdovekhq2hdnwqd.onion");
    private static final String DOMAINS_HINT = "kohlchan.net, kohlchan.mett.ru, kohlchankxguym67.onion, fastkohlp6h2seef.onion";
    
    private static final String[] ATTACHMENT_FORMATS = new String[] {
            "jpg", "jpeg", "bmp", "gif", "png", "mp3", "ogg", "flac", "opus", "webm", "mp4", "7z", "zip", "pdf", "epub", "txt" };
    private static final Pattern INVALID_LESSER_THAN_PATTERN = Pattern.compile("&lt([^;])");
    private static final int MAX_PASSWORD_LENGTH = 8;
    
    private String domain;
    private static HashMap<String, String> captchas = null;
    private String reportCaptchaAnswer = null;

    public KohlchanModule(SharedPreferences preferences, Resources resources) {
        super(preferences, resources);
        if (captchas == null) captchas = new HashMap<String, String>();
    }

    public static void putCaptcha(String captchaID, String answer) {
        if (captchas == null) captchas = new HashMap<String, String>();
        captchas.put(captchaID, answer);
    }
    
    @Override
    public String getChanName() {
        return CHAN_NAME;
    }
    
    @Override
    protected void initHttpClient() {
        updateDomain(preferences.getString(getSharedKey(PREF_KEY_DOMAIN), DEFAULT_DOMAIN));
        BasicClientCookie cookieConsent = new BasicClientCookie("cookieConsent", "true");
        cookieConsent.setDomain(getUsingDomain());
        cookieConsent.setPath("/");
        httpClient.getCookieStore().addCookie(cookieConsent);
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
    public String getDefaultPassword() {
        if (!preferences.contains(getSharedKey(PREF_KEY_PASSWORD))) {
            preferences.edit().putString(getSharedKey(PREF_KEY_PASSWORD),
                    CryptoUtils.genPassword(MAX_PASSWORD_LENGTH)).commit();
        }
        return preferences.getString(getSharedKey(PREF_KEY_PASSWORD), "");
    }

    @Override
    protected void addPasswordPreference(PreferenceGroup group) {
        final Context context = group.getContext();
        EditTextPreference passwordPref = new EditTextPreference(context) {
            @Override
            protected void showDialog(Bundle state) {
                if (!preferences.contains(getSharedKey(PREF_KEY_PASSWORD))) {
                    setText(getDefaultPassword());
                }
                super.showDialog(state);
            }
        };
        passwordPref.setTitle(R.string.pref_password_title);
        passwordPref.setDialogTitle(R.string.pref_password_title);
        passwordPref.setSummary(R.string.pref_password_summary);
        passwordPref.setKey(getSharedKey(PREF_KEY_PASSWORD));
        passwordPref.getEditText().setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
        passwordPref.getEditText().setSingleLine();
        passwordPref.getEditText().setFilters(new InputFilter[] { new InputFilter.LengthFilter(MAX_PASSWORD_LENGTH) });
        group.addPreference(passwordPref);
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
        model.allowEmails = false;
        model.allowRandomHash = true;
        model.attachmentsFormatFilters = ATTACHMENT_FORMATS;
        return model;
    }

    @Override
    protected PostModel mapPostModel(JSONObject object) {
        PostModel model = super.mapPostModel(object);
        model.name = model.name.replace("&apos;", "'");
        model.subject = model.subject.replace("&apos;", "'");
        model.comment = RegexUtils.replaceAll(model.comment, INVALID_LESSER_THAN_PATTERN, "&lt;$1");
        return model;
    }

    @Override
    public CaptchaModel getNewCaptcha(String boardName, String threadNumber, ProgressListener listener, CancellableTask task) throws Exception {
        return null; //Temporary fix
    }

    public ExtendedCaptchaModel getNewCaptcha(ProgressListener listener, CancellableTask task) throws Exception {
        String captchaUrl = getUsingUrl() + "captcha.js?d=" + Math.random();
        return downloadCaptcha(captchaUrl, listener, task);
    }

    protected ExtendedCaptchaModel downloadCaptcha(String captchaUrl, ProgressListener listener, CancellableTask task) throws Exception {
        Bitmap captchaBitmap = null;
        HttpRequestModel requestModel = HttpRequestModel.builder().setGET().setNoRedirect(true).build();
        HttpResponseModel responseModel = HttpStreamer.getInstance().getFromUrl(captchaUrl, requestModel, httpClient, listener, task);
        String captchaId = null;
        try {
            for (Header header : responseModel.headers) {
                if (header != null && "Set-Cookie".equalsIgnoreCase(header.getName())) {
                    String cookie = header.getValue();
                    if (cookie.contains("captchaid")) {
                        try {
                            captchaId = cookie.split(";")[0].split("=")[1];
                        } catch (Exception e) {
                        }
                    }
                    if (captchaId != null) break;
                }
            }
            
            if (responseModel.statusCode == 301 || responseModel.statusCode == 302) {
                captchaUrl = fixRelativeUrl(responseModel.locationHeader);
            }
        } finally {
            responseModel.release();
        }
        //FIXME: obtain captcha cookie and capcha image in 1 request
        responseModel = HttpStreamer.getInstance().getFromUrl(captchaUrl, requestModel, httpClient, listener, task);
        
        try {
            InputStream imageStream = responseModel.stream;
            captchaBitmap = BitmapFactory.decodeStream(imageStream);
        } finally {
            responseModel.release();
        }
        
        responseModel.release();
        ExtendedCaptchaModel captchaModel = new ExtendedCaptchaModel();
        captchaModel.type = CaptchaModel.TYPE_NORMAL;
        captchaModel.bitmap = captchaBitmap;
        captchaModel.captchaID = captchaId;
        return captchaModel;
    }

    private String validateCaptcha(String captchaID, ProgressListener listener, CancellableTask task) throws Exception {
        if (captchaID == null) return null;
        String captchaAnswer = captchas.get(captchaID);
        if (captchaAnswer == null) return null;
        String url = getUsingUrl() + "renewBypass.js?json=1";
        ExtendedMultipartBuilder postEntityBuilder = ExtendedMultipartBuilder.create().
                setDelegates(listener, task).
                addString("captcha", captchaAnswer);
        HttpRequestModel request = HttpRequestModel.builder().setPOST(postEntityBuilder.build()).build();
        JSONObject response = null;
        try {
            response = HttpStreamer.getInstance().getJSONObjectFromUrl(url, request, httpClient, listener, task, true);
        } catch (HttpWrongStatusCodeException e) {
            checkCloudflareError(e, url);
            throw e;
        }
        captchas.remove(captchaID);
        switch (response.optString("status")) {
            case "failed":
            case "new":
            case "next":
                throw new KohlchanCaptchaException();
            case "finish":
                return captchaID;
            case "error":
                throw new Exception(response.optString("data", "Captcha Error"));
            default: throw new Exception("Unknown Error");
        }
    }

    private String checkFileIdentifier(File file, String mime, ProgressListener listener, CancellableTask task) {
        if (mime == null) return null;
        String hash;
        try {
            hash = AbstractLynxChanModule.computeFileMD5(file);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        String identifier = hash + "-" + mime.replace("/", "");
        String url = getUsingUrl() + "checkFileIdentifier.js?json=1&identifier=" + identifier;
        String response = "";
        try {
            response = HttpStreamer.getInstance().getStringFromUrl(url, null, httpClient, listener, task, false);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        if (response.contains("true")) return hash;
        return null;
    }

    public String sendPost(SendPostModel model, ProgressListener listener, CancellableTask task) throws Exception {
        String captchaId;
        try {
            captchaId = captchas.keySet().iterator().next();
        } catch (NoSuchElementException e) {
            captchaId = null;
        }
        if (captchaId != null) validateCaptcha(captchaId, listener, task);
        
        String url = getUsingUrl() + (model.threadNumber == null ? "newThread.js?json=1" : "replyThread.js?json=1");
        
        if (model.password.length() > MAX_PASSWORD_LENGTH) model.password = model.password.substring(0, MAX_PASSWORD_LENGTH);
        ExtendedMultipartBuilder postEntityBuilder = ExtendedMultipartBuilder.create().
                setDelegates(listener, task).
                setCharset(Charset.forName("UTF-8")).
                addString("name", model.name).
                addString("subject", model.subject).
                addString("message", model.comment).
                addString("password", model.password).
                addString("boardUri", model.boardName);
        if (model.sage) postEntityBuilder.addString("sage", "true");
        if (model.threadNumber != null) postEntityBuilder.addString("threadId", model.threadNumber);
        if (model.custommark) postEntityBuilder.addString("spoiler", "true");
        if (model.attachments != null && model.attachments.length > 0) {
            MimeTypeMap mimeTypeMap = MimeTypeMap.getSingleton();
            for (int i = 0; i < model.attachments.length; ++i) {
                String ext = MimeTypeMap.getFileExtensionFromUrl(
                        Uri.fromFile(model.attachments[i]).getEncodedPath());
                String mime = mimeTypeMap.getMimeTypeFromExtension(ext);
                if (mime == null) throw new Exception("Unknown file type");
                String md5 = null;
                if (!model.randomHash) {
                    md5 = checkFileIdentifier(model.attachments[i], mime, listener, task);
                }
                postEntityBuilder.addString("fileName", model.attachments[i].getName());
                if (md5 != null) {
                    postEntityBuilder.addString("fileMd5", md5).addString("fileMime", mime);
                } else {
                    postEntityBuilder.addFile("files", model.attachments[i], mime, model.randomHash);
                }
            }
        }
        HttpRequestModel request = HttpRequestModel.builder().setPOST(postEntityBuilder.build()).setNoRedirect(true).build();
        String response = HttpStreamer.getInstance().getStringFromUrl(url, request, httpClient, null, task, true);
        JSONObject result = new JSONObject(response);
        String status = result.optString("status");
        if ("ok".equals(status)) {
            UrlPageModel urlPageModel = new UrlPageModel();
            urlPageModel.type = UrlPageModel.TYPE_THREADPAGE;
            urlPageModel.chanName = getChanName();
            urlPageModel.boardName = model.boardName;
            urlPageModel.threadNumber = model.threadNumber;
            if (model.threadNumber == null) {
                urlPageModel.threadNumber = Integer.toString(result.optInt("data"));
            } else {
                urlPageModel.postNumber = Integer.toString(result.optInt("data"));
            }
            return buildUrl(urlPageModel);
        } else if (status.contains("error") || status.contains("blank")) {
            String errorMessage = result.optString("data");
            if (errorMessage.length() > 0) {
                throw new Exception(errorMessage);
            }
        } else if ("bypassable".equals(status)) {
            throw new KohlchanCaptchaException();
        } else if("banned".equals(status)) {
            String banMessage = "You have been banned!";
            try {
                banMessage += "\nReason: " + result.getJSONObject("data").getString("reason");
            } catch (Exception e) { }
            throw new Exception(banMessage);
        }
        throw new Exception("Unknown Error");
    }

    @Override
    public String deletePost(DeletePostModel model, final ProgressListener listener, final CancellableTask task) throws Exception {
        String url = getUsingUrl() + "contentActions.js?json=1";
        
        if (model.password.length() > MAX_PASSWORD_LENGTH) model.password = model.password.substring(0, MAX_PASSWORD_LENGTH);
        ExtendedMultipartBuilder multipartBuilder = ExtendedMultipartBuilder.create().setDelegates(listener, task).
                addString("action", "delete").
                addString("password", model.password).
                //addString("deleteMedia", "true"). /* only mods can remove files from server */
                addString(model.boardName + "-" + model.threadNumber +
                                (model.postNumber != null ? ("-" + model.postNumber) : ""), "true");
        if (model.onlyFiles) {
            multipartBuilder.addString("deleteUploads", "true");
        }
        HttpRequestModel request = HttpRequestModel.builder().setPOST(multipartBuilder.build()).build();
        String response;
        try {
            response = HttpStreamer.getInstance().getStringFromUrl(url, request, httpClient, listener, task, false);
        } catch (HttpWrongStatusCodeException e) {
            checkCloudflareError(e, url);
            throw e;
        }
        JSONObject result = new JSONObject(response);
        String status = result.optString("status");
        if ("ok".equals(status)) {
            JSONObject data = result.optJSONObject("data");
            if (data != null) {
                int removedCount = data.optInt("removedPosts", -2) + data.optInt("removedThreads", -2);
                if (removedCount > 0) {
                    return null;
                } else if (removedCount == 0) {
                    throw new Exception("Nothing was removed");
                }
            }
        } else if (status.contains("error")) {
            String errorMessage = result.optString("data");
            if (errorMessage.length() > 0) {
                throw new Exception(errorMessage);
            }
        }
        throw new Exception("Unknown Error");
    }

    @Override
    public String reportPost(DeletePostModel model, ProgressListener listener, CancellableTask task) throws Exception {
        if (reportCaptchaAnswer == null) {
            throw new KohlchanCaptchaException() {
                @Override
                protected void storeResponse(String response) {
                    reportCaptchaAnswer = response;
                }
            };
        }
        
        String url = getUsingUrl() + "contentActions.js?json=1";
        ExtendedMultipartBuilder multipartBuilder = ExtendedMultipartBuilder.create().setDelegates(listener, task).
                addString("action", "report").
                addString("reason", model.reportReason).
                addString("captcha", reportCaptchaAnswer).
                addString("global", "true").
                addString(model.boardName + "-" + model.threadNumber +
                        (model.threadNumber.equals(model.postNumber) ? "" : "-" + model.postNumber), "true");
        reportCaptchaAnswer = null;
        
        HttpRequestModel request = HttpRequestModel.builder().setPOST(multipartBuilder.build()).build();
        String response;
        try {
            response = HttpStreamer.getInstance().getStringFromUrl(url, request, httpClient, listener, task, false);
        } catch (HttpWrongStatusCodeException e) {
            checkCloudflareError(e, url);
            throw e;
        }
        
        JSONObject result = new JSONObject(response);
        String status = result.optString("status");
        if ("ok".equals(status)) {
            return null;
        } else if (status.contains("error")) {
            String errorMessage = result.optString("data");
            if (errorMessage.length() > 0) {
                throw new Exception(errorMessage);
            }
        }
        throw new Exception("Unknown Error");
    }

    class ExtendedCaptchaModel extends CaptchaModel {
        String captchaID = "";
    }
    
}
