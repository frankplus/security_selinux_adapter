hdc_std.exe file send chkcon /bin/
hdc_std.exe file send getenforce /bin/
hdc_std.exe file send setenforce /bin/
hdc_std.exe file send restorecon /bin/
hdc_std.exe file send load_policy /bin/
hdc_std.exe file send getfilecon /bin/
hdc_std.exe file send setfilecon /bin/
hdc_std.exe file send selinuxexeccon /bin/
hdc_std.exe file send selinux_check_access /bin/
hdc_std.exe file send getpidcon /bin/
hdc_std.exe file send demoloop /bin/

hdc_std.exe file send libload_policy.z.so /system/lib/
hdc_std.exe file send librestorecon.z.so /system/lib/
hdc_std.exe file send libpcre2.z.so /system/lib/
hdc_std.exe file send libselinux.z.so /system/lib/
hdc_std.exe file send libsepol.z.so /system/lib/

hdc_std.exe shell mkdir -pv /etc/selinux/targeted/contexts/files/
hdc_std.exe shell mkdir -pv /etc/selinux/targeted/policy/
hdc_std.exe file send config /etc/selinux/config
hdc_std.exe file send policy.31 /etc/selinux/targeted/policy/policy.31
hdc_std.exe file send file_contexts /etc/selinux/targeted/contexts/files/file_contexts

hdc_std.exe shell chmod -v 755 /bin/chkcon
hdc_std.exe shell chmod -v 755 /bin/getenforce
hdc_std.exe shell chmod -v 755 /bin/setenforce
hdc_std.exe shell chmod -v 755 /bin/restorecon
hdc_std.exe shell chmod -v 755 /bin/load_policy
hdc_std.exe shell chmod -v 755 /bin/demoloop
hdc_std.exe shell chmod -v 755 /bin/getfilecon
hdc_std.exe shell chmod -v 755 /bin/setfilecon
hdc_std.exe shell chmod -v 755 /bin/selinuxexeccon
hdc_std.exe shell chmod -v 755 /bin/selinux_check_access
hdc_std.exe shell chmod -v 755 /bin/getpidcon

hdc_std.exe shell chmod -v 644 /system/lib/libload_policy.z.so
hdc_std.exe shell chmod -v 644 /system/lib/librestorecon.z.so
hdc_std.exe shell chmod -v 644 /system/lib/libpcre2.z.so
hdc_std.exe shell chmod -v 644 /system/lib/libselinux.z.so
hdc_std.exe shell chmod -v 644 /system/lib/libsepol.z.so
hdc_std.exe shell chmod -v 644 /etc/selinux/targeted/policy/policy.31
pause
