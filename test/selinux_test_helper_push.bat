::
:: Copyright (c) 2021 北京万里红科技有限公司
::
:: Licensed under the Apache License, Version 2.0 (the "License");
:: you may not use this file except in compliance with the License.
:: You may obtain a copy of the License at
::
::     http://www.apache.org/licenses/LICENSE-2.0
::
:: Unless required by applicable law or agreed to in writing, software
:: distributed under the License is distributed on an "AS IS" BASIS,
:: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
:: See the License for the specific language governing permissions and
:: limitations under the License.
::

hdc_std.exe file send selinux_test /bin/
hdc_std.exe shell chmod 755 /bin/selinux_test

hdc_std.exe file send selinux_test_helper.sh /bin/
hdc_std.exe shell chmod 755 /bin/selinux_test_helper.sh
hdc_std.exe shell /bin/selinux_test_helper.sh

pause
