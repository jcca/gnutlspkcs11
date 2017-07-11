GnutlsPkcs11
============
Gnutls PKCS #11 for java.

# Example

List all private keys

```java
import org.gnutlspkcs11.GNUTLS_PKCS11_OBJ_FLAG;
import org.gnutlspkcs11.GNUTLS_PKCS11_URL;
import org.gnutlspkcs11.PKCS11;

public class Example {
    public static void main(String []args) {
        PKCS11 p11 = PKCS11.getInstance();
        String PIN = "<TOKEN PIN>";
        String PROVIDER = "/lib/opensc-pkcs11.so";
        p11.init();
        p11.addProvider(PROVIDER);


        for(String url: p11.listTokenUrls(GNUTLS_PKCS11_URL.GENERIC)) {
            int flags = GNUTLS_PKCS11_OBJ_FLAG.PRIVKEY | GNUTLS_PKCS11_OBJ_FLAG.LOGIN;
            url += ";pin-value=" + PIN;
            for(String pk: p11.listTokenObjects(url, flags)) {
                System.out.println(pk);
            }
        }

        p11.deinit();
    }
}
```