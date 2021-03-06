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

package nya.miku.wishmaster.ui;

import android.graphics.Point;
import android.view.Display;
import android.view.View;
import android.view.ViewTreeObserver;

public class AppearanceUtils {
    private AppearanceUtils(){}
    
    public static void callWhenLoaded(final View view, final Runnable runnable) {
        view.getViewTreeObserver().addOnGlobalLayoutListener(new ViewTreeObserver.OnGlobalLayoutListener() {
            @Override
            public void onGlobalLayout() {
                CompatibilityUtils.removeOnGlobalLayoutListener(view, this);
                runnable.run();
            }
        });
    }
    
    public static Point getDisplaySize(Display display) {
        Point size = new Point();
        CompatibilityUtils.getDisplaySize(display, size);
        return size;
    }
}
