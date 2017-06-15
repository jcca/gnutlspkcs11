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

import java.security.Provider;

/**
 * Created by jcca on 6/12/17.
 */
public final class GnutlsPKCS11 extends Provider{

    public GnutlsPKCS11() {
        this("GNUTLSPKCS11",1.0D, "config");
    }

    protected GnutlsPKCS11(String s, double v, String s1) {
        super(s, v, s1);
        put("Signature.SHA256withRSA", "org.gnutlspkcs11.P11Signature");
    }
}
