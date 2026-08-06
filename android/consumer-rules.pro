# JMRTD / SCUBA / BouncyCastle dùng phản xạ để nạp provider và các lớp LDS.
-keep class org.jmrtd.** { *; }
-keep class net.sf.scuba.** { *; }
-keep class org.bouncycastle.** { *; }
-keep class com.gemalto.jp2.** { *; }
-keep class com.nfcpassport.** { *; }

-dontwarn org.jmrtd.**
-dontwarn net.sf.scuba.**
-dontwarn org.bouncycastle.**
-dontwarn javax.naming.**
-dontwarn java.awt.**
-dontwarn javax.swing.**
