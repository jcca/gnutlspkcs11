/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class org_gnutlspkcs11_PKCS11 */

#ifndef _Included_org_gnutlspkcs11_PKCS11
#define _Included_org_gnutlspkcs11_PKCS11
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     org_gnutlspkcs11_PKCS11
 * Method:    init
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_gnutlspkcs11_PKCS11_init
  (JNIEnv *, jobject);

/*
 * Class:     org_gnutlspkcs11_PKCS11
 * Method:    deinit
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_gnutlspkcs11_PKCS11_deinit
  (JNIEnv *, jobject);

/*
 * Class:     org_gnutlspkcs11_PKCS11
 * Method:    listTokenUrls
 * Signature: (I)Ljava/util/List;
 */
JNIEXPORT jobject JNICALL Java_org_gnutlspkcs11_PKCS11_listTokenUrls
  (JNIEnv *, jobject, jint);

/*
 * Class:     org_gnutlspkcs11_PKCS11
 * Method:    listTokenObjects
 * Signature: (Ljava/lang/String;I)Ljava/util/List;
 */
JNIEXPORT jobject JNICALL Java_org_gnutlspkcs11_PKCS11_listTokenObjects
  (JNIEnv *, jobject, jstring, jint);

/*
 * Class:     org_gnutlspkcs11_PKCS11
 * Method:    signData
 * Signature: (Ljava/lang/String;I[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_gnutlspkcs11_PKCS11_signData
  (JNIEnv *, jobject, jstring, jint, jbyteArray);

/*
 * Class:     org_gnutlspkcs11_PKCS11
 * Method:    verifyData
 * Signature: (Ljava/lang/String;I[B[B)Z
 */
JNIEXPORT jboolean JNICALL Java_org_gnutlspkcs11_PKCS11_verifyData__Ljava_lang_String_2I_3B_3B
  (JNIEnv *, jobject, jstring, jint, jbyteArray, jbyteArray);

/*
 * Class:     org_gnutlspkcs11_PKCS11
 * Method:    verifyData
 * Signature: ([BI[B[B)Z
 */
JNIEXPORT jboolean JNICALL Java_org_gnutlspkcs11_PKCS11_verifyData___3BI_3B_3B
  (JNIEnv *, jobject, jbyteArray, jint, jbyteArray, jbyteArray);

/*
 * Class:     org_gnutlspkcs11_PKCS11
 * Method:    delete
 * Signature: (Ljava/lang/String;I)V
 */
JNIEXPORT void JNICALL Java_org_gnutlspkcs11_PKCS11_delete
  (JNIEnv *, jobject, jstring, jint);

/*
 * Class:     org_gnutlspkcs11_PKCS11
 * Method:    generate
 * Signature: (Ljava/lang/String;IILjava/lang/String;Ljava/lang/String;)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_gnutlspkcs11_PKCS11_generate
  (JNIEnv *, jobject, jstring, jint, jint, jstring, jstring);

/*
 * Class:     org_gnutlspkcs11_PKCS11
 * Method:    write
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[BI)V
 */
JNIEXPORT void JNICALL Java_org_gnutlspkcs11_PKCS11_write
  (JNIEnv *, jobject, jstring, jstring, jstring, jbyteArray, jint);

/*
 * Class:     org_gnutlspkcs11_PKCS11
 * Method:    loadCertificate
 * Signature: (Ljava/lang/String;I)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_gnutlspkcs11_PKCS11_loadCertificate
  (JNIEnv *, jobject, jstring, jint);

/*
 * Class:     org_gnutlspkcs11_PKCS11
 * Method:    addProvider
 * Signature: (Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_org_gnutlspkcs11_PKCS11_addProvider
  (JNIEnv *, jobject, jstring);

#ifdef __cplusplus
}
#endif
#endif
