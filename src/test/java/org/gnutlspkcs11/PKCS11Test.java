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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.List;

/**
 * Created by jcca on 6/19/17.
 */
class PKCS11Test {

    static String TOKEN     = "pkcs11:model=PKCS%2315%20emulated;manufacturer=OpenPGP%20project;serial=fffe67130835;"
                              + "token=OpenPGP%20card%20%28User%20PIN%20%28sig%29%29";
    static String ID_OBJECT = "id=%01;object=Signature%20key";

    static String PIN       = "pin-value=123456";
    static String URL       = TOKEN + ";" + ID_OBJECT + ";" + PIN;
    static byte[] data      = "foobar".getBytes();
    PKCS11 p11              = new PKCS11();

    @BeforeAll
    public static void init() {
        Security.addProvider(new GnutlsPKCS11());
    }

    @Test
    void listTokenUrls() {
        List<String> urls = p11.listTokenUrls(GNUTLS_PKCS11_URL.GENERIC);

        boolean token = false;
        for(String url: urls) {
            if (url.equals(TOKEN)) {
                token = true;
                break;
            }
        }

        Assertions.assertTrue(token);
    }

    @Test
    void listTokenObjects() {
        String URL = TOKEN + ";" + PIN;

        int flags = GNUTLS_PKCS11_OBJ_FLAG.PRIVKEY | GNUTLS_PKCS11_OBJ_FLAG.LOGIN;
        List<String> urls = p11.listTokenObjects(URL, flags);

        URL = TOKEN + ";" + ID_OBJECT + ";type=private";
        boolean key = false;
        for(String url: urls) {
            if (url.equals(URL)) {
                key = true;
                break;
            }
        }
        Assertions.assertTrue(key);
    }

    @Disabled("Run only if you have a real pkcs11 token.")
    @Test
    void generateDelete() throws Exception {
        String id = "0102";
        int flags = 0;

        byte pubkey[] = p11.generate(TOKEN, GNUTLS_PK.RSA, 2048, "test", id);
        String URL = TOKEN + ";id=%01%02;object=test;type=public";
        p11.delete(URL, flags);
        URL = TOKEN + ";id=%01%02;object=test;type=private" + ";" + PIN;
        flags |= GNUTLS_PKCS11_OBJ_FLAG.LOGIN;
        p11.delete(TOKEN, flags);
    }

    @Test
    void signVerify() throws Exception {
        PrivateKey privkey = p11.loadPrivateKey(URL);
        Signature privateSignature = Signature.getInstance("SHA256withRSA", "GNUTLSPKCS11");
        privateSignature.initSign(privkey);
        privateSignature.update(data);
        byte signature[] = privateSignature.sign();
        PublicKey pubkey = p11.loadPublickey(URL);
        Signature publicSignature = Signature.getInstance("SHA256withRSA", "GNUTLSPKCS11");
        publicSignature.initVerify(pubkey);
        publicSignature.update(data);
        Assertions.assertTrue(publicSignature.verify(signature));
    }
}
