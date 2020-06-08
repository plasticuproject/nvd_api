#!/bin/sh

cd api;
python update.py;
cd ../;
coverage run test_basic.py -v;
