#include<feistalBox/feistalBox.h>
#include<jni/FeistalBoxJni.h>

JNIEXPORT jbyteArray JNICALL Java_FeistalBox_getFeistalBoxByte(JNIEnv *env, jclass obj, jstring jkey, jint jround, jint isEnc,jint mode)
{
    const unsigned char* user_key = (*env)->GetStringUTFChars(env, jkey, NULL);
    const int round = jround;
    int enc_flag = (isEnc == FeistalBox_ENC)? eFeistalBoxModeEnc: eFeistalBoxModeDec;
    int ret;
    size_t box_size;
    unsigned char* box_str;
    jbyteArray res;
    FeistalBox fb;
    FeistalBoxConfig cfg;


    ret = initFeistalBoxConfig(FeistalBox_SM4_128_128, user_key, 1, 15, round, &cfg);
    ret = generateFeistalBox(&cfg, enc_flag, &fb);

    if(ret != 0){
        (*env)->ReleaseStringUTFChars(env, jkey, user_key);
        return NULL;
    }

    box_str = FEISTALBOX_export_to_str(&fb, &box_size);
    (*env)->SetByteArrayRegion(env, res, 0, box_size, box_str);

    releaseFeistalBox(&fb);
    free(box_str);
    return res;
}
