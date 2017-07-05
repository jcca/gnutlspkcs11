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

import org.junit.jupiter.api.*;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.List;

/**
 * Created by jcca on 6/19/17.
 */
class PKCS11Test {

    public static String TOKEN     = "pkcs11:model=PKCS%2315%20emulated;manufacturer=OpenPGP%20project;serial=fffe67130835;"
                              + "token=OpenPGP%20card%20%28User%20PIN%20%28sig%29%29";
    public static String ID_OBJECT = "id=%01;object=Signature%20key";

    public static String PIN       = "pin-value=123456";
    public static String URL       = TOKEN + ";" + ID_OBJECT + ";" + PIN;
    static byte[] data      = "foobar".getBytes();
    PKCS11 p11              = PKCS11.getInstance();

    @BeforeAll
    public static void before() {
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
    void generate() throws Exception {
        String id = "0102";
        int flags = 0;

        byte pubkey[] = p11.generate(TOKEN, GNUTLS_PK.RSA, 2048, "test", id);
        String URL = TOKEN + ";id=%01%02;object=test;type=public";
        p11.delete(URL, flags);
        URL = TOKEN + ";id=%01%02;object=test;type=private" + ";" + PIN;
        flags |= GNUTLS_PKCS11_OBJ_FLAG.LOGIN;
        p11.delete(TOKEN, flags);
    }

    @Disabled("Run only if you have a real pkcs11 token.")
    @Test
    void write() throws Exception {
        int flags = 0;
        p11.write(TOKEN, "gnutlsp11", "01:02:03", new byte[0], flags);
    }

    @Test
    void sign() throws Exception {
        PrivateKey privkey = p11.loadPrivateKey(URL);
        PublicKey pubkey = p11.loadPublickey(URL);

        byte signature[] = p11.sign(privkey, data);
        Assertions.assertTrue(p11.verify(pubkey, data, signature));
    }

    @AfterAll
    public static void after() {
        Security.removeProvider("GNUTLSPKCS11");
    }
}
