#!/usr/bin/env bash
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
