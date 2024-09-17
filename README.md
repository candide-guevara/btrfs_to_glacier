# Btrfs backup into Glacier

The goal of this project is to make periodic snapshots of my btrfs volumes and upload them to Glacier.

## Directory hierarchy

* btrfs\_lib : some c code to list btrfs subvolumes and a python module wrapper around it
* python : code to create btrfs subvolume backups and send them to glacier

## Getting started

* Modify `config.properties` for your directory structure
* Prepare a test btrfs filesystem to run the test suite
* `make test` : build and launch the test suite

## Dependencies

* btrfs
* python module dateutil
* AWS boto3
* Coverage.py
* Moto aws mock server

A dummy PR test
