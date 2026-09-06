#!/usr/bin/env bash

XZ_OPT="-9e" tar --exclude=".git" --exclude="*.log" --exclude="*.der" --exclude="*/target" --exclude="*/.cache" --exclude="*/__pycache__" --exclude="*/myenv" -cvJf ../Shadow6.tar.xz ./

# To extract, use "tar -xvf <filename>" without "<>"
