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

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;

/**
 * Created by jcca on 6/21/17.
 */
class P11SignatureTest {

    static String URL       = PKCS11Test.URL;
    static byte[] data      = PKCS11Test.data;
    PKCS11 p11              = new PKCS11();

    @BeforeAll
    public static void before() {
        Security.addProvider(new GnutlsPKCS11());
    }

    @Test
    void sign() throws Exception {
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

    @Test
    void signPDF() throws Exception {

    }

    @AfterAll
    public static void after() {
        Security.removeProvider("GNUTLSPKCS11");
    }
}