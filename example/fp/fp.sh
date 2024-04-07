#!/bin/bash

cat $1 | grep "fp_extractor.go" | grep '=' | sed 's/.* =  //' > fp.draft

while IFS="" read -r p || [ -n "$p" ]
do
  printf '%02x' "$p"
done <fp.draft

rm fp.draft
