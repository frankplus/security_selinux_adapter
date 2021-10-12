#!/usr/bin/env bash
#
# Copyright 2021 北京万里红科技有限公司
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

TDIR="/data/selinux/"

{
  mkdir -pv "$TDIR"

  for file in "${TDIR}/"test{1,2,3}.txt
  do
    rm -vf "$file"
    echo "$file" >"$file"

    if [[ "test3.txt" == "$file" ]]
    then
      setfilecon 'u:object_r:app_data_file:s0' "$file"
    else
      setfilecon 'u:object_r:data_file:s0' "$file"
    fi
  done
}
