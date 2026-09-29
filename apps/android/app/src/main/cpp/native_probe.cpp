#include <jni.h>
#include <dlfcn.h>

#include <string>

namespace {

void fail(JNIEnv* env, const std::string& message) {
    jclass error = env->FindClass("java/lang/IllegalStateException");
    if (error != nullptr) {
        env->ThrowNew(error, message.c_str());
    }
}

}  // namespace

extern "C" JNIEXPORT jbyteArray JNICALL
Java_dev_compatforge_android_NativeProbe_readCapabilityReportBytes(JNIEnv* env, jobject) {
    void* library = dlopen("libcompatforge_ffi.so", RTLD_NOW | RTLD_LOCAL);
    if (library == nullptr) {
        fail(env, std::string("CompatForge Core could not load: ") + dlerror());
        return nullptr;
    }

    using Probe = unsigned int (*)(char**);
    using FreeString = void (*)(char*);
    auto* probe = reinterpret_cast<Probe>(dlsym(library, "cf_probe_capabilities"));
    auto* free_string = reinterpret_cast<FreeString>(dlsym(library, "cf_string_free"));
    if (probe == nullptr || free_string == nullptr) {
        fail(env, "CompatForge Core ABI symbols are missing");
        dlclose(library);
        return nullptr;
    }

    char* report = nullptr;
    const unsigned int status = probe(&report);
    if (status != 0 || report == nullptr) {
        if (report != nullptr) {
            free_string(report);
        }
        fail(env, "CompatForge capability probe failed with status " + std::to_string(status));
        dlclose(library);
        return nullptr;
    }

    const std::string bytes(report);
    free_string(report);
    dlclose(library);
    jbyteArray output = env->NewByteArray(static_cast<jsize>(bytes.size()));
    if (output != nullptr) {
        env->SetByteArrayRegion(output, 0, static_cast<jsize>(bytes.size()),
                                reinterpret_cast<const jbyte*>(bytes.data()));
    }
    return output;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_dev_compatforge_android_NativeProbe_inspectExecutableBytes(JNIEnv* env, jobject,
                                                                jstring absolute_path) {
    if (absolute_path == nullptr) {
        fail(env, "Executable path is missing");
        return nullptr;
    }
    void* library = dlopen("libcompatforge_ffi.so", RTLD_NOW | RTLD_LOCAL);
    if (library == nullptr) {
        fail(env, std::string("CompatForge Core could not load: ") + dlerror());
        return nullptr;
    }

    using Inspect = unsigned int (*)(const char*, char**);
    using FreeString = void (*)(char*);
    auto* inspect = reinterpret_cast<Inspect>(dlsym(library, "cf_inspect_executable"));
    auto* free_string = reinterpret_cast<FreeString>(dlsym(library, "cf_string_free"));
    if (inspect == nullptr || free_string == nullptr) {
        fail(env, "CompatForge inspection ABI symbols are missing");
        dlclose(library);
        return nullptr;
    }

    const char* path = env->GetStringUTFChars(absolute_path, nullptr);
    if (path == nullptr) {
        dlclose(library);
        return nullptr;
    }
    char* report = nullptr;
    const unsigned int status = inspect(path, &report);
    env->ReleaseStringUTFChars(absolute_path, path);
    if (status != 0 || report == nullptr) {
        if (report != nullptr) {
            free_string(report);
        }
        fail(env, "CompatForge PE inspection failed with status " + std::to_string(status));
        dlclose(library);
        return nullptr;
    }

    const std::string bytes(report);
    free_string(report);
    dlclose(library);
    jbyteArray output = env->NewByteArray(static_cast<jsize>(bytes.size()));
    if (output != nullptr) {
        env->SetByteArrayRegion(output, 0, static_cast<jsize>(bytes.size()),
                                reinterpret_cast<const jbyte*>(bytes.data()));
    }
    return output;
}
