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

/**
 * Created by jcca on 6/17/17.
 */
public final class GNUTLS_DIG {
    public static final int UNKNOWN = GNUTLS_MAC.UNKNOWN;
    public static final int NULL = GNUTLS_MAC.NULL;
    public static final int MD5 = GNUTLS_MAC.MD5;
    public static final int SHA1 = GNUTLS_MAC.SHA1;
    public static final int RMD160 = GNUTLS_MAC.RMD160;
    public static final int MD2 = GNUTLS_MAC.MD2;
    public static final int SHA256 = GNUTLS_MAC.SHA256;
    public static final int SHA384 = GNUTLS_MAC.SHA384;
    public static final int SHA512 = GNUTLS_MAC.SHA512;
    public static final int SHA224 = GNUTLS_MAC.SHA224;
/* If you add anything here, make sure you align with
   gnutls_mac_algorithm_t. */
}
