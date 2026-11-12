#!/usr/bin/env bash

read -r firstline < .VERSION
tag_value="${firstline##*tag: }"

if [[ "${tag_value:0:1}" == "v" ]]; then
    version_string="${tag_value%%[,)]*}"
fi

echo "${version_string:-v0.0.0}"
