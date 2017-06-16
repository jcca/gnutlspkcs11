/* gnutlspkcs11
 *
 * Author: Carlos C. <jccarlos.a@gmail.com>
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

package org.gnutlspkcs11;

import java.security.Key;

/**
 * Created by jcca on 6/14/17.
 */
abstract  class P11Key implements Key {
    private transient String CPtr;
    protected P11Key(String cPtr) {
        this.CPtr = cPtr;
    }

    protected static String getCPtr(P11Key obj) {
        return (obj == null) ? "" : obj.CPtr;
    }

    public String getAlgorithm() {
        return "RSA";
    }
}
