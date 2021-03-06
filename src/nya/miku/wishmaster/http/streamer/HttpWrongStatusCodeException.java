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

package nya.miku.wishmaster.http.streamer;

/**
 * Исключение возбуждается, если код статуса HTTP в ответе не позволяет продолжить дальнейшие действия.
 * @author miku-nyan
 *
 */
public class HttpWrongStatusCodeException extends HttpWrongResponseException {
    private final int statusCode;

    public HttpWrongStatusCodeException(int statusCode, String msg, byte[] html) {
        super(msg, html);
        this.statusCode = statusCode;
    }
    
    public HttpWrongStatusCodeException(int statusCode, String msg) {
        super(msg, null);
        this.statusCode = statusCode;
    }

    public int getStatusCode() {
        return statusCode;
    }
}
