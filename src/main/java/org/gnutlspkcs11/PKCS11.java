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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
/**
 * Created by jcca on 6/12/17.
 */
public class PKCS11 {
    static {
        System.loadLibrary("gpkcs11");
    }

    public native List<String> listTokenUrls(int flags);
    public native List<String> listTokenObjects(String url, int flags);
    private native byte[] signData(String privkey, int dig, byte data[]);
    private native boolean verifyData(String pubkey, int dig, byte data[], byte signature[]);
    public native void delete(String url, int flags);
    public native byte[] generate(String url, int pk, int bits, String label, String id);
    public native byte[] loadCertificate(String url);

    public byte[] sign(PrivateKey privkey, byte data[]) {
        // check privkey instance of p11privkey
        return signData(P11Key.getCPtr((P11Key) privkey), 0, data); // use RSA with sha256 by default
    }

    public boolean verify(PublicKey pubkey, byte data[], byte signature[]) {
        // check
        return verifyData(P11Key.getCPtr((P11Key) pubkey), 0, data, signature);
    }

    // TODO: fixme
    public PrivateKey loadPrivateKey(String url) {
        return new P11PrivateKey(url);
    }

    public PublicKey loadPublickey(String url) {
        return new P11PublicKey(url);
    }
}
