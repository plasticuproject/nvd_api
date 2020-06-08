#!/bin/sh

cd api;
python update.py;
cd ../;
python test_basic.py;
