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

#include "pkcs11.h"
#include <gnutls/pkcs11.h>
#include <gnutls/abstract.h>
#include <stdlib.h>
#include <string.h>

void GnutlsPkcs11Exception(JNIEnv *env, const char *msg) {
  (*env)->ExceptionClear(env);
  jclass excep = (*env)->FindClass(env, "java/lang/Exception");
  if (excep)
    (*env)->ThrowNew(env, excep, msg);
}

int
gnutlspkcs11_sign(const char *url, gnutls_datum_t *data, gnutls_datum_t *signature, unsigned int dig, unsigned int flags)
{
  int ret;
  gnutls_privkey_t privkey;

  if ((ret = gnutls_privkey_init(&privkey)) < 0)
    return ret;

  if ((ret = gnutls_privkey_import_url(privkey, url, flags)) < 0)
    goto sign_end;

  ret = gnutls_privkey_sign_data(privkey, dig, 0, data, signature);

 sign_end:
  gnutls_privkey_deinit(privkey);
  return ret;
}

int
gnutlspkcs11_verify(const char *url, gnutls_datum_t *data, gnutls_datum_t *sig, unsigned int dig, unsigned int flags)
{
  int ret;
  int pk;
  gnutls_pubkey_t pubkey;

  if ((ret = gnutls_pubkey_init(&pubkey)) < 0)
    return ret;

  if ((ret = gnutls_pubkey_import_url(pubkey, url, flags)) < 0)
    goto verify_end;

  pk = gnutls_pubkey_get_pk_algorithm(pubkey, NULL);

  ret = gnutls_pubkey_verify_data2(pubkey, gnutls_pk_to_sign(pk, dig),
                                   0, data, sig);

 verify_end:
  gnutls_pubkey_deinit(pubkey);
  return ret;
}

JNIEXPORT jobject JNICALL Java_org_gnutlspkcs11_PKCS11_listTokenUrls
(JNIEnv *env, jobject thisObj, jint jdetailed) {
  jclass list;
  jmethodID list_;
  jmethodID list_get;
  jmethodID list_add;
  jmethodID list_size;
  list      = (*env)->FindClass(env, "java/util/ArrayList");
  list_     = (*env)->GetMethodID(env, list, "<init>", "(I)V");
  list_get  = (*env)->GetMethodID(env, list, "get", "(I)Ljava/lang/Object;");
  list_add  = (*env)->GetMethodID(env, list, "add", "(Ljava/lang/Object;)Z");
  list_size = (*env)->GetMethodID (env, list, "size", "()I");

  int ret, tokens_size;
  char **urls = NULL;;
  char *url;
  unsigned detailed = jdetailed;
  for (tokens_size = 0;; tokens_size++) {
    ret = gnutls_pkcs11_token_get_url(tokens_size, detailed, &url);
    if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
      break;
    if (ret < 0) {
      /* TODO: ret exception */
    }

    urls = (char**) realloc(urls, (tokens_size + 2)*sizeof(char*));
    urls[tokens_size + 1] = 0;
    urls[tokens_size] = &url[0];
  }
  urls = &urls[0];

  jobject result = (*env)->NewObject(env, list, list_, tokens_size);

  int j;
  for (j = 0; j < tokens_size; j++) {
    jstring element = (*env)->NewStringUTF(env, *urls++);
    (*env)->CallBooleanMethod(env, result, list_add, element);
    (*env)->DeleteLocalRef(env, element);
  }

  /* TODO: Read more*/
  /* for (j = 0; j < i; j++) { */
  /*   printf("free\n"); */
  /*   gnutls_free(urls[i]); */
  /* } */
  /* free(urls); ????*/

  return result;
}

JNIEXPORT jobject JNICALL Java_org_gnutlspkcs11_PKCS11_listTokenObjects
(JNIEnv *env, jobject thisObj, jstring jurl, jint flags) {
  jclass list;
  jmethodID list_;
  jmethodID list_get;
  jmethodID list_add;
  jmethodID list_size;
  list      = (*env)->FindClass(env, "java/util/ArrayList");
  list_     = (*env)->GetMethodID(env, list, "<init>", "(I)V");
  list_get  = (*env)->GetMethodID(env, list, "get", "(I)Ljava/lang/Object;");
  list_add  = (*env)->GetMethodID(env, list, "add", "(Ljava/lang/Object;)Z");
  list_size = (*env)->GetMethodID (env, list, "size", "()I");

  const char *curl = (*env)->GetStringUTFChars(env, jurl, 0);

  int ret, i;
  gnutls_pkcs11_obj_t *crt_list;
  unsigned int crt_list_size = 0;
  char *url;

  ret = gnutls_pkcs11_obj_list_import_url4(&crt_list, &crt_list_size,
                                           curl, flags);
  if (ret < 0){
    fprintf(stderr, "error: %s\n", gnutls_strerror(ret));
    /* new exception */
    return NULL;
  }

  jobject result = (*env)->NewObject(env, list, list_, crt_list_size);

  for (i = 0; i < crt_list_size; i++) {
    gnutls_pkcs11_obj_export_url(crt_list[i], GNUTLS_PKCS11_URL_GENERIC, &url);
    jstring element = (*env)->NewStringUTF(env, url);
    (*env)->CallBooleanMethod(env, result, list_add, element);
    (*env)->DeleteLocalRef(env, element);
    /* free(url); ??? */
  }

  for (i = 0; i < crt_list_size; i++)
    gnutls_pkcs11_obj_deinit(crt_list[i]);
  gnutls_free(crt_list);

  return result;
}

JNIEXPORT void JNICALL Java_org_gnutlspkcs11_PKCS11_delete
(JNIEnv *env, jobject thisObj, jstring jurl, jint flags) {
  int ret;
  const char *url = NULL;
  if (jurl != NULL)
      url = (*env)->GetStringUTFChars(env, jurl, 0);

  if ((ret = gnutls_pkcs11_delete_url(url, flags)) < 0) {
     // new exeption
  }
}

JNIEXPORT jbyteArray JNICALL Java_org_gnutlspkcs11_PKCS11_generate
(JNIEnv *env, jobject thisObj, jstring jurl, jint pk, jint bits, jstring jlabel, jstring jid) {
  int ret;
  unsigned int flags = 0;
  gnutls_datum_t cid = {NULL, 0};
  unsigned char raw_id[128];
  size_t raw_id_size;
  gnutls_datum_t pubkey;
  const char *id = NULL;
  const char *url = NULL;
  const char *label = NULL;
  if (jurl != NULL)
    url = (*env)->GetStringUTFChars(env, jurl, 0);
  if (jid != NULL)
    id = (*env)->GetStringUTFChars(env, jid, 0);
  if (jlabel != NULL)
    label = (*env)->GetStringUTFChars(env, jlabel, 0);

  if (id != NULL) {
    raw_id_size = sizeof(raw_id);
    ret = gnutls_hex2bin(id, strlen(id), raw_id, &raw_id_size);
    if (ret < 0) {
      printf("Error converting hex: %s\n", gnutls_strerror(ret));
      return NULL;                  /* new exception */
    }
    cid.data = raw_id;
    cid.size = raw_id_size;
  }

  flags |= GNUTLS_PKCS11_OBJ_FLAG_LOGIN;
  flags |= GNUTLS_PKCS11_OBJ_FLAG_MARK_SENSITIVE;
  flags |= GNUTLS_PKCS11_OBJ_FLAG_MARK_PRIVATE;

  if ((ret = gnutls_pkcs11_privkey_generate3(url, pk, bits, label, &cid,
                                             GNUTLS_X509_FMT_DER, &pubkey,
                                             GNUTLS_KEY_DIGITAL_SIGNATURE, flags)) != 0)
    {
      printf("Error generating keys: %s\n", gnutls_strerror(ret));
      /* new exception */
      return NULL;
    }

  jbyteArray bArray = (*env)->NewByteArray(env, pubkey.size);
  (*env)->SetByteArrayRegion(env, bArray, 0, pubkey.size, (jbyte*)pubkey.data);

  /* gnutls_free(pubkey.data); ??????*/
  return bArray;
}

JNIEXPORT void JNICALL Java_org_gnutlspkcs11_PKCS11_write
(JNIEnv *env, jobject thisObj, jstring jurl, jstring jlabel, jstring jid, jbyteArray jdata, jint flags) {

}

JNIEXPORT jbyteArray JNICALL Java_org_gnutlspkcs11_PKCS11_signData
(JNIEnv *env, jobject thisObj, jstring jurl, jint dig, jbyteArray jdata) {

  int ret, len;
  gnutls_datum_t signature;
  gnutls_datum_t data;
  unsigned int flags = 0;
  const char *url = (*env)->GetStringUTFChars(env, jurl, 0);
  /* Read data to sign */
  len = (*env)->GetArrayLength (env, jdata);
  unsigned char *buf = (unsigned char*)(*env)->GetByteArrayElements(env, jdata, 0);
  data.data = buf;
  data.size = len;

  if ((ret = gnutlspkcs11_sign(url, &data, &signature, dig, flags)) < 0) {
    GnutlsPkcs11Exception(env, gnutls_strerror(ret));
    return NULL;
  }

  jbyteArray result = (*env)->NewByteArray(env, signature.size);
  (*env)->SetByteArrayRegion(env, result, 0, signature.size, signature.data);

  /* gnutls_free(signature.data); ??????*/
  return result;
}

JNIEXPORT jboolean JNICALL Java_org_gnutlspkcs11_PKCS11_verifyData__Ljava_lang_String_2I_3B_3B
(JNIEnv *env, jobject thisObj, jstring jurl, jint dig, jbyteArray jdata, jbyteArray jsignature) {

  /* GNUTLS_DIG_SHA256 */
  int ret, len;
  gnutls_datum_t signature;
  gnutls_datum_t data;
  unsigned int flags = 0;

  const char *url = (*env)->GetStringUTFChars(env, jurl, 0);
  /* Read data */
  len = (*env)->GetArrayLength (env, jdata);
  unsigned char *buf = (unsigned char*)(*env)->GetByteArrayElements(env, jdata, 0);
  data.data = buf;
  data.size = len;

  /* Read signature */
  len = (*env)->GetArrayLength (env, jsignature);
  unsigned char *sig = (unsigned char*)(*env)->GetByteArrayElements(env, jsignature, 0);
  signature.data = sig;
  signature.size = len;

  if ((ret = gnutlspkcs11_verify(url, &data, &signature, dig, flags)) < 0) {
    // TODO: check ret code and throw exception if status is error
    GnutlsPkcs11Exception(env, gnutls_strerror(ret));
    return JNI_FALSE;
  }

  return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL Java_org_gnutlspkcs11_PKCS11_verifyData___3BI_3B_3B
(JNIEnv *env, jobject thisObj, jbyteArray jpubkey, jint dig, jbyteArray jdata, jbyteArray jsignature) {
  return JNI_TRUE;
}
