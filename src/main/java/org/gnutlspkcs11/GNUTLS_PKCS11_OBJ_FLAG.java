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
public final class GNUTLS_PKCS11_OBJ_FLAG {
    public static final int LOGIN = (1<<0);
    public static final int MARK_TRUSTED = (1<<1);
    public static final int MARK_SENSITIVE = (1<<2);
    public static final int LOGIN_SO = (1<<3);
    public static final int MARK_PRIVATE = (1<<4);
    public static final int MARK_NOT_PRIVATE = (1<<5);
    public static final int RETRIEVE_ANY = (1<<6);
    public static final int RETRIEVE_TRUSTED = MARK_TRUSTED;
    public static final int MARK_DISTRUSTED = (1<<8);
    public static final int RETRIEVE_DISTRUSTED = MARK_DISTRUSTED;
    public static final int COMPARE = (1<<9);
    public static final int PRESENT_IN_TRUSTED_MODULE = (1<<10);
    public static final int MARK_CA = (1<<11);
    public static final int MARK_KEY_WRAP = (1<<12);
    public static final int COMPARE_KEY = (1<<13);
    public static final int OVERWRITE_TRUSTMOD_EXT = (1<<14);
    public static final int MARK_ALWAYS_AUTH = (1<<15);
    public static final int MARK_EXTRACTABLE = (1<<16);
    public static final int NEVER_EXTRACTABLE = (1<<17);
    public static final int CRT = (1<<18);
    public static final int WITH_PRIVKEY = (1<<19);
    public static final int PUBKEY = (1<<20);
    public static final int NO_STORE_PUBKEY = PUBKEY;
    public static final int PRIVKEY = (1<<21);
    /* flags 1<<29 and later are reserved - see pkcs11_int.h */
}
