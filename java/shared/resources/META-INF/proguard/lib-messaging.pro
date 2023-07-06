# Prevent native methods from being renamed as long as they're used.
-keepclasseswithmembernames,includedescriptorclasses class com.cystack.ready.libmessaging.** {
    native <methods>;
}

# Keep members that the Rust library accesses directly on a variety of classes.
-keepclassmembers class com.cystack.ready.libmessaging.** {
    long unsafeHandle;
    <init>(long);

    byte[] serialize();

    void log(...);
}

# Keep constructors for all our exceptions.
# (This could be more fine-grained but doesn't really have to be.)
-keep,includedescriptorclasses class com.cystack.ready.libmessaging.**.*Exception {
    <init>(...);
}

# Keep some types that the Rust library constructs unconditionally.
# (The constructors are covered by the above -keepclassmembers)
-keep class com.cystack.ready.libmessaging.protocol.SignalProtocolAddress
-keep class com.cystack.ready.libmessaging.protocol.message.* implements com.cystack.ready.libmessaging.protocol.message.CiphertextMessage

# Keep names for store-related types, and the members used from the Rust library not covered above.
# (Thus, if you don't use a store, it won't be kept.)
-keepnames interface com.cystack.ready.libmessaging.**.*Store { *; }

-keepnames enum com.cystack.ready.libmessaging.protocol.state.IdentityKeyStore$Direction { *; }
-keepnames class com.cystack.ready.libmessaging.protocol.IdentityKey
-keepnames class com.cystack.ready.libmessaging.**.*Record
