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

import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.*;

import java.io.*;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Calendar;
import java.util.List;

/**
 * Created by jcca on 6/21/17.
 */
class P11SignatureTest {

    static String URL       = PKCS11Test.URL;
    static byte[] data      = PKCS11Test.data;
    PKCS11 p11              = PKCS11.getInstance();

    @BeforeAll
    public static void before() {
        Security.addProvider(new GnutlsPKCS11());
    }

    public static byte[] emptyPDF() throws DocumentException, IOException {
        Document document = new Document();
        OutputStream baosPDF = new ByteArrayOutputStream();
        PdfWriter.getInstance(document, baosPDF);
        document.open();
        document.add(new Paragraph("Hello, world!"));
        document.close();
        byte[] result = ((ByteArrayOutputStream) baosPDF).toByteArray();
        baosPDF.close();

        return result;
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

    @Disabled("Run only if you have a real pkcs11 token.")
    @Test
    void signPDF() throws Exception {
        InputStream certstream = new ByteArrayInputStream(p11.loadCertificate(URL, GNUTLS_X509_FMT.DER));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate crt = cf.generateCertificate(certstream);
        Certificate[] chain = new Certificate[] {crt};
        OutputStream os = new ByteArrayOutputStream();

        Provider p = new GnutlsPKCS11();
        Security.addProvider(p);

        PKCS11 p11 = PKCS11.getInstance();

        PrivateKey pk = p11.loadPrivateKey(URL);

        byte [] pdf = emptyPDF();
        PdfReader reader = new PdfReader(pdf);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason("I'm agree");
        ExternalSignature pks = new PrivateKeySignature(pk, DigestAlgorithms.SHA256, p.getName());
        ExternalDigest digest = new BouncyCastleDigest();
        MakeSignature.signDetached(appearance, digest, pks, chain, null, null, null, 0, MakeSignature.CryptoStandard.CMS);

        reader.close();
        os.flush();
        os.close();

        p = new BouncyCastleProvider();
        Security.addProvider(p);
        reader = new PdfReader(((ByteArrayOutputStream) os).toByteArray());
        AcroFields af = reader.getAcroFields();
        List<String> names = af.getSignatureNames();
        for (String name : names) {
            System.out.println("Signature name: " + name);
            System.out.println("Signature covers whole document: " + af.signatureCoversWholeDocument(name));
            System.out.println("Document revision: " + af.getRevision(name) + " of " + af.getTotalRevisions());
            PdfPKCS7 p7 = af.verifySignature(name);
            Calendar cal = p7.getSignDate();
            //Certificate[] pkc = pk.getCertificates();
            System.out.println("Subject: " + CertificateInfo.getSubjectFields(p7.getSigningCertificate()));
            System.out.println("Revision modified: " + !p7.verify());
        }
    }

    @AfterAll
    public static void after() {
        Security.removeProvider("GNUTLSPKCS11");
    }
}