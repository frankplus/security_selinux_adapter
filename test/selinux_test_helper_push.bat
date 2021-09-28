hdc_std.exe file send selinux_test /bin/
hdc_std.exe shell chmod 755 /bin/selinux_test

hdc_std.exe file send selinux_test_helper.sh /bin/
hdc_std.exe shell chmod 755 /bin/selinux_test_helper.sh
hdc_std.exe shell /bin/selinux_test_helper.sh

pause
