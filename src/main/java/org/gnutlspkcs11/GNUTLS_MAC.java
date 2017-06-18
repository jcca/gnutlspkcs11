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
public final class GNUTLS_MAC {
    public static final int UNKNOWN = 0;
    public static final int NULL = 1;
    public static final int MD5 = 2;
    public static final int SHA1 = 3;
    public static final int RMD160 = 4;
    public static final int MD2 = 5;
    public static final int SHA256 = 6;
    public static final int SHA384 = 7;
    public static final int SHA512 = 8;
    public static final int SHA224 = 9;
    /* If you add anything here, make sure you align with
       gnutls_digest_algorithm_t. */
    public static final int AEAD = 200; /* indicates that MAC is on the cipher */
}
