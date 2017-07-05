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

import java.security.*;

/**
 * Created by jcca on 6/12/17.
 */
public final class P11Signature extends SignatureSpi {
    private P11PrivateKey privkey;
    private P11PublicKey pubkey;
    private byte data[] = null; // TODO: change to byte buffer
    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (publicKey == null) {
            throw new InvalidKeyException("Key must not be null");
        }
        this.pubkey = (P11PublicKey) publicKey;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (privateKey == null) {
            throw new InvalidKeyException("Key must not be null");
        }
        this.privkey = (P11PrivateKey) privateKey;
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void engineUpdate(byte[] bytes, int i, int i1) throws SignatureException {
        data = bytes;
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        return PKCS11.getInstance().sign(privkey, data);
    }

    @Override
    protected boolean engineVerify(byte[] bytes) throws SignatureException {
        return PKCS11.getInstance().verify(pubkey, data, bytes);
    }

    @Override
    protected void engineSetParameter(String s, Object o) throws InvalidParameterException {

    }

    @Override
    protected Object engineGetParameter(String s) throws InvalidParameterException {
        return null;
    }
}
