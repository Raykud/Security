// ----------------------------------------------------------------------------
// <auto-generated>
// This is autogenerated code by Embeddinator-4000.
// Do not edit this file or all your changes will be lost after re-generation.
// </auto-generated>
// ----------------------------------------------------------------------------
#include "Security.h"
#include "glib.h"
#include "mono_embeddinator.h"
#include "c-support.h"

mono_embeddinator_context_t __mono_context;
MonoImage* __Security_dll_image;

static MonoClass* class_Security_Resource = 0;
static MonoClass* class_Security_Encryption = 0;
static MonoClass* class_Security_EncryptionResult = 0;
static MonoClass* class_Security_Attribute = 0;
static MonoClass* class_Security_String = 0;

static void __initialize_mono()
{
    if (__mono_context.domain)
        return;
    mono_embeddinator_init(&__mono_context, "mono_embeddinator_binding");
}

static void __lookup_assembly_Security_dll()
{
    if (__Security_dll_image)
        return;
    __Security_dll_image = mono_embeddinator_load_assembly(&__mono_context, "Security.dll");
}

static void __lookup_class_Security_Resource()
{
    if (class_Security_Resource == 0)
    {
        __initialize_mono();
        __lookup_assembly_Security_dll();
        class_Security_Resource = mono_class_from_name(__Security_dll_image, "Security", "Resource");
    }
}

Security_Resource* Security_Resource_new()
{
    const char __method_name[] = "Security.Resource:.ctor()";
    static MonoMethod *__method = 0;

    if (!__method)
    {
        __lookup_class_Security_Resource();
        __method = mono_embeddinator_lookup_method(__method_name, class_Security_Resource);
    }

    Security_Resource* __object = (Security_Resource*) calloc(1, sizeof(Security_Resource));
    MonoObject* __instance = mono_object_new(__mono_context.domain, class_Security_Resource);
    mono_embeddinator_init_object(__object, __instance);

    MonoObject* __exception = 0;
    MonoObject* __result = mono_runtime_invoke(__method, __instance, 0, &__exception);

    if (__exception)
    {
        free(__object);
        mono_embeddinator_throw_exception(__exception);
        return 0;
    }

    return __object;
}

static void __lookup_class_Security_Encryption()
{
    if (class_Security_Encryption == 0)
    {
        __initialize_mono();
        __lookup_assembly_Security_dll();
        class_Security_Encryption = mono_class_from_name(__Security_dll_image, "Security", "Encryption");
    }
}

Security_Encryption* Security_Encryption_new()
{
    const char __method_name[] = "Security.Encryption:.ctor()";
    static MonoMethod *__method = 0;

    if (!__method)
    {
        __lookup_class_Security_Encryption();
        __method = mono_embeddinator_lookup_method(__method_name, class_Security_Encryption);
    }

    Security_Encryption* __object = (Security_Encryption*) calloc(1, sizeof(Security_Encryption));
    MonoObject* __instance = mono_object_new(__mono_context.domain, class_Security_Encryption);
    mono_embeddinator_init_object(__object, __instance);

    MonoObject* __exception = 0;
    MonoObject* __result = mono_runtime_invoke(__method, __instance, 0, &__exception);

    if (__exception)
    {
        free(__object);
        mono_embeddinator_throw_exception(__exception);
        return 0;
    }

    return __object;
}

const char* Security_Encryption_SHA256(const char* UrlToHash)
{
    const char __method_name[] = "Security.Encryption:SHA256(string)";
    static MonoMethod *__method = 0;

    if (!__method)
    {
        __lookup_class_Security_Encryption();
        __method = mono_embeddinator_lookup_method(__method_name, class_Security_Encryption);
    }

    void* __args[1];
    MonoString* __UrlToHash_0 = (UrlToHash) ? mono_string_new(__mono_context.domain, UrlToHash) : 0;
    __args[0] = __UrlToHash_0;

    MonoObject* __exception = 0;
    MonoObject* __result = mono_runtime_invoke(__method, 0, __args, &__exception);

    if (__exception)
        mono_embeddinator_throw_exception(__exception);

    char* __string = mono_string_to_utf8((MonoString*) __result);

    return __string;
}

Security_EncryptionResult* Security_Encryption_Encrypt(const char* ToEncrypt, bool format)
{
    const char __method_name[] = "Security.Encryption:Encrypt(string,bool)";
    static MonoMethod *__method = 0;

    if (!__method)
    {
        __lookup_class_Security_Encryption();
        __method = mono_embeddinator_lookup_method(__method_name, class_Security_Encryption);
    }

    void* __args[2];
    MonoString* __ToEncrypt_0 = (ToEncrypt) ? mono_string_new(__mono_context.domain, ToEncrypt) : 0;
    __args[0] = __ToEncrypt_0;
    __args[1] = &format;

    MonoObject* __exception = 0;
    MonoObject* __result = mono_runtime_invoke(__method, 0, __args, &__exception);

    if (__exception)
        mono_embeddinator_throw_exception(__exception);

    Security_EncryptionResult* __result_obj = __result ? (Security_EncryptionResult*) mono_embeddinator_create_object(__result) : 0;

    return __result_obj;
}

static void __lookup_class_Security_EncryptionResult()
{
    if (class_Security_EncryptionResult == 0)
    {
        __initialize_mono();
        __lookup_assembly_Security_dll();
        class_Security_EncryptionResult = mono_class_from_name(__Security_dll_image, "Security", "EncryptionResult");
    }
}

Security_EncryptionResult* Security_EncryptionResult_new(const char* payload, const char* iv, const char* key)
{
    const char __method_name[] = "Security.EncryptionResult:.ctor(string,string,string)";
    static MonoMethod *__method = 0;

    if (!__method)
    {
        __lookup_class_Security_EncryptionResult();
        __method = mono_embeddinator_lookup_method(__method_name, class_Security_EncryptionResult);
    }

    Security_EncryptionResult* __object = (Security_EncryptionResult*) calloc(1, sizeof(Security_EncryptionResult));
    MonoObject* __instance = mono_object_new(__mono_context.domain, class_Security_EncryptionResult);
    mono_embeddinator_init_object(__object, __instance);

    void* __args[3];
    MonoString* __payload_0 = (payload) ? mono_string_new(__mono_context.domain, payload) : 0;
    __args[0] = __payload_0;
    MonoString* __iv_1 = (iv) ? mono_string_new(__mono_context.domain, iv) : 0;
    __args[1] = __iv_1;
    MonoString* __key_2 = (key) ? mono_string_new(__mono_context.domain, key) : 0;
    __args[2] = __key_2;

    MonoObject* __exception = 0;
    MonoObject* __result = mono_runtime_invoke(__method, __instance, __args, &__exception);

    if (__exception)
    {
        free(__object);
        mono_embeddinator_throw_exception(__exception);
        return 0;
    }

    return __object;
}

const char* Security_EncryptionResult_get_Payload(Security_EncryptionResult* object)
{
    const char __method_name[] = "Security.EncryptionResult:get_Payload()";
    static MonoMethod *__method = 0;

    if (!__method)
    {
        __lookup_class_Security_EncryptionResult();
        __method = mono_embeddinator_lookup_method(__method_name, class_Security_EncryptionResult);
    }

    MonoObject* __instance = mono_gchandle_get_target(object->_handle);
    MonoObject* __exception = 0;
    MonoObject* __result = mono_runtime_invoke(__method, __instance, 0, &__exception);

    if (__exception)
        mono_embeddinator_throw_exception(__exception);

    char* __string = mono_string_to_utf8((MonoString*) __result);

    return __string;
}

void Security_EncryptionResult_set_Payload(Security_EncryptionResult* object, const char* value)
{
    const char __method_name[] = "Security.EncryptionResult:set_Payload(string)";
    static MonoMethod *__method = 0;

    if (!__method)
    {
        __lookup_class_Security_EncryptionResult();
        __method = mono_embeddinator_lookup_method(__method_name, class_Security_EncryptionResult);
    }

    MonoObject* __instance = mono_gchandle_get_target(object->_handle);
    void* __args[1];
    MonoString* __value_0 = (value) ? mono_string_new(__mono_context.domain, value) : 0;
    __args[0] = __value_0;

    MonoObject* __exception = 0;
    MonoObject* __result = mono_runtime_invoke(__method, __instance, __args, &__exception);

    if (__exception)
        mono_embeddinator_throw_exception(__exception);
}

const char* Security_EncryptionResult_get_IV(Security_EncryptionResult* object)
{
    const char __method_name[] = "Security.EncryptionResult:get_IV()";
    static MonoMethod *__method = 0;

    if (!__method)
    {
        __lookup_class_Security_EncryptionResult();
        __method = mono_embeddinator_lookup_method(__method_name, class_Security_EncryptionResult);
    }

    MonoObject* __instance = mono_gchandle_get_target(object->_handle);
    MonoObject* __exception = 0;
    MonoObject* __result = mono_runtime_invoke(__method, __instance, 0, &__exception);

    if (__exception)
        mono_embeddinator_throw_exception(__exception);

    char* __string = mono_string_to_utf8((MonoString*) __result);

    return __string;
}

void Security_EncryptionResult_set_IV(Security_EncryptionResult* object, const char* value)
{
    const char __method_name[] = "Security.EncryptionResult:set_IV(string)";
    static MonoMethod *__method = 0;

    if (!__method)
    {
        __lookup_class_Security_EncryptionResult();
        __method = mono_embeddinator_lookup_method(__method_name, class_Security_EncryptionResult);
    }

    MonoObject* __instance = mono_gchandle_get_target(object->_handle);
    void* __args[1];
    MonoString* __value_0 = (value) ? mono_string_new(__mono_context.domain, value) : 0;
    __args[0] = __value_0;

    MonoObject* __exception = 0;
    MonoObject* __result = mono_runtime_invoke(__method, __instance, __args, &__exception);

    if (__exception)
        mono_embeddinator_throw_exception(__exception);
}

const char* Security_EncryptionResult_get_Key(Security_EncryptionResult* object)
{
    const char __method_name[] = "Security.EncryptionResult:get_Key()";
    static MonoMethod *__method = 0;

    if (!__method)
    {
        __lookup_class_Security_EncryptionResult();
        __method = mono_embeddinator_lookup_method(__method_name, class_Security_EncryptionResult);
    }

    MonoObject* __instance = mono_gchandle_get_target(object->_handle);
    MonoObject* __exception = 0;
    MonoObject* __result = mono_runtime_invoke(__method, __instance, 0, &__exception);

    if (__exception)
        mono_embeddinator_throw_exception(__exception);

    char* __string = mono_string_to_utf8((MonoString*) __result);

    return __string;
}

void Security_EncryptionResult_set_Key(Security_EncryptionResult* object, const char* value)
{
    const char __method_name[] = "Security.EncryptionResult:set_Key(string)";
    static MonoMethod *__method = 0;

    if (!__method)
    {
        __lookup_class_Security_EncryptionResult();
        __method = mono_embeddinator_lookup_method(__method_name, class_Security_EncryptionResult);
    }

    MonoObject* __instance = mono_gchandle_get_target(object->_handle);
    void* __args[1];
    MonoString* __value_0 = (value) ? mono_string_new(__mono_context.domain, value) : 0;
    __args[0] = __value_0;

    MonoObject* __exception = 0;
    MonoObject* __result = mono_runtime_invoke(__method, __instance, __args, &__exception);

    if (__exception)
        mono_embeddinator_throw_exception(__exception);
}

static void __lookup_class_Security_Attribute()
{
    if (class_Security_Attribute == 0)
    {
        __initialize_mono();
        __lookup_assembly_Security_dll();
        class_Security_Attribute = mono_class_from_name(__Security_dll_image, "Security", "Resource/Attribute");
    }
}

static void __lookup_class_Security_String()
{
    if (class_Security_String == 0)
    {
        __initialize_mono();
        __lookup_assembly_Security_dll();
        class_Security_String = mono_class_from_name(__Security_dll_image, "Security", "Resource/String");
    }
}
int32_t Security_String_get_app_name()
{
    static MonoClassField *__field = 0;
    if (!__field)
    {
        __lookup_class_Security_String();
        const char __field_name[] = "app_name";
        __field = mono_class_get_field_from_name(class_Security_String, __field_name);
    }
    MonoObject* __result = mono_field_get_value_object(__mono_context.domain, __field, 0);
    void* __unbox = mono_object_unbox(__result);
    return *((int32_t*)__unbox);
}

void Security_String_set_app_name(int32_t value)
{
    static MonoClassField *__field = 0;
    if (!__field)
    {
        __lookup_class_Security_String();
        const char __field_name[] = "app_name";
        __field = mono_class_get_field_from_name(class_Security_String, __field_name);
    }
    void* __value = &value;
    MonoVTable* __vtable = mono_class_vtable(__mono_context.domain, class_Security_String);
    mono_field_static_set_value(__vtable, __field, __value);
}

int32_t Security_String_get_hello()
{
    static MonoClassField *__field = 0;
    if (!__field)
    {
        __lookup_class_Security_String();
        const char __field_name[] = "hello";
        __field = mono_class_get_field_from_name(class_Security_String, __field_name);
    }
    MonoObject* __result = mono_field_get_value_object(__mono_context.domain, __field, 0);
    void* __unbox = mono_object_unbox(__result);
    return *((int32_t*)__unbox);
}

void Security_String_set_hello(int32_t value)
{
    static MonoClassField *__field = 0;
    if (!__field)
    {
        __lookup_class_Security_String();
        const char __field_name[] = "hello";
        __field = mono_class_get_field_from_name(class_Security_String, __field_name);
    }
    void* __value = &value;
    MonoVTable* __vtable = mono_class_vtable(__mono_context.domain, class_Security_String);
    mono_field_static_set_value(__vtable, __field, __value);
}

