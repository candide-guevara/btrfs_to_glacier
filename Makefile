.ONESHELL:
.SECONDARY:
.PHONY: all clean fs_init c_code go_code go_debug go_unittest test

PROJ_ROOT     := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))
include etc/Makefile.include
STAGE_PATH    := /tmp/bin_btrfs_to_glacier

BTRFS_LIB     := /usr/lib
BTRFS_INCLUDE := /usr/include
BTRFS_LDLIB   := -lbtrfsutil -lbtrfs

GOENV    := $(STAGE_PATH)/go_env
MYGOSRC  := src/golang
GO_PROTOC_INSTALL := $(STAGE_PATH)/gobin/protoc-gen-go
# Chose NOT to store generated proto sources in git
# Can be problematic for some languages like C++ (see groups.google.com/g/protobuf/c/Qz5Aj7zK03Y)
GO_PROTO_GEN_SRCS := $(MYGOSRC)/messages/config.pb.go $(MYGOSRC)/messages/messages.pb.go
MYDLVINIT         := $(STAGE_PATH)/dlv_init
AWS_TEMP_CREDS    := $(STAGE_PATH)/aws_temp_creds
PROTOSRC          := src/proto
CC                := gcc
CPPFLAGS          := -D_GNU_SOURCE -D__LEVEL_LOG__=4 -D__LEVEL_ASSERT__=1
CFLAGS_BTRFS      := -std=gnu11
# -mtune=native -march=native -O3
CFLAGS            := $(CFLAGS_BTRFS) -I$(BTRFS_INCLUDE) "-I$(PROJ_ROOT)/include" -Wall -Werror
CFLAGS_DBG        := $(CFLAGS) -ggdb -Og
LDFLAGS           :=
LDLIBS            :=

headers  := $(wildcard include/*.h)
go_files := $(shell find "$(MYGOSRC)" -type f -name '*.go')
c_lib     = bin/$(1).so bin/$(1).a bin/$(1)_test

all: go_code c_code
go_code c_code test: | bin

c_code: $(call c_lib,linux_utils) bin/btrfs_progs_test

clean:
	if [[ -f "$(GOENV)" ]]; then
	  GOPATH="`GOENV="$(GOENV)" go env GOPATH`"
		chmod --recursive 'a+wx' "$$GOPATH"
	fi
	rm -rf bin/*

dyn_integ: all $(AWS_TEMP_CREDS)
	ACCESS=`cat "$(AWS_TEMP_CREDS)" | grep '"AccessKeyId":' | sed -r 's/.*"([^"]+)",?$$/\1/'`
	SECRET=`cat "$(AWS_TEMP_CREDS)" | grep '"SecretAccessKey":' | sed -r 's/.*"([^"]+)",?$$/\1/'`
	SESSION=`cat "$(AWS_TEMP_CREDS)" | grep '"SessionToken":' | sed -r 's/.*"([^"]+)",?$$/\1/'`
	pushd "$(MYGOSRC)"
	GOENV="$(GOENV)" go run ./cloud/cloud_integration \
		--access="$$ACCESS" --secret="$$SECRET" --session="$$SESSION" \
		--region="$(AWS_REGION)" --table="$(AWS_DYN_TAB)"

test: all go_unittest | $(SUBVOL_PATH)
	bin/btrfs_progs_test "$(SUBVOL_PATH)" || exit 1
	pushd "$(MYGOSRC)"
	GOENV="$(GOENV)" go run ./shim/shim_integration \
	  --subvol="$(SUBVOL_PATH)" \
		--rootvol="$(MOUNT_TESTVOL_SRC)" \
		--snap1="$(SNAP1_PATH)" --snap2="$(SNAP2_PATH)"

$(SUBVOL_PATH) fs_init:
	[[ `id -u` == "0" ]] && echo never run this as root && exit 1
	bash etc/setup_test_drive.sh -r -d "$(DRIVE_UUID)" -l "$(FS_PREFIX)" -s "$(SUBVOL_NAME)"

go_code: c_code $(GOENV) $(go_files) $(GO_PROTO_GEN_SRCS)
	pushd "$(MYGOSRC)"
	GOENV="$(GOENV)" go install ./...

go_unittest: go_code
	pushd "$(MYGOSRC)"
	# add --test.v to get verbose tests
	# add --test.count=1 to not cache results
	pkg_to_test=( `GOENV="$(GOENV)" go list btrfs_to_glacier/... | grep -vE "_integration$$|/shim|/types"` )
	GOENV="$(GOENV)" go test "$${pkg_to_test[@]}"

go_debug: go_code
	pushd "$(MYGOSRC)"
	echo '
	break btrfs_to_glacier/encryption.(*aesGzipCodec).EncryptStream
	break btrfs_to_glacier/encryption.(*aesGzipCodec).DecryptStream
	# break encryption/aes_gzip_codec.go:250
	continue
	' > "$(MYDLVINIT)"
	# https://github.com/go-delve/delve/blob/master/Documentation/usage/dlv_debug.md
	CGO_CFLAGS="$(CFLAGS_DBG)" GOENV="$(GOENV)" \
	  dlv test "btrfs_to_glacier/encryption" --init="$(MYDLVINIT)" --output="$(STAGE_PATH)/debugme" \
		  -- --test.run='TestEncryptStream$$' --test.v

$(GOENV): | bin
	# Could also be achieved with linker flags to override global vars
	# https://www.digitalocean.com/community/tutorials/using-ldflags-to-set-version-information-for-go-applications
	COMMIT_ID="`git rev-list -1 HEAD`"
	GOENV="$(GOENV)" go env -w CC="$(CC)" \
														 CGO_CPPFLAGS="-DBTRFS_TO_GLACIER_VERSION=\"$$COMMIT_ID\"" \
	                           CGO_CFLAGS="$(CFLAGS)" \
														 CGO_LDFLAGS="$(BTRFS_LDLIB) $(STAGE_PATH)/linux_utils.a -lcap" \
														 GOPATH="$(STAGE_PATH)/gopath" \
														 GOBIN="$(STAGE_PATH)/gobin" \
														 GOCACHE="$(STAGE_PATH)/go-build"
	#GOENV="$(GOENV)" go env

bin: | $(STAGE_PATH)
	[[ -L bin ]] || ln -s $(STAGE_PATH) bin

$(STAGE_PATH):
	[[ -d $(STAGE_PATH) ]] || mkdir $(STAGE_PATH)

$(GO_PROTOC_INSTALL): $(GOENV)
	GOENV="$(GOENV)" go get google.golang.org/protobuf/cmd/protoc-gen-go

$(MYGOSRC)/messages/%.pb.go: $(PROTOSRC)/%.proto $(GOENV) | $(GO_PROTOC_INSTALL)
	export PATH="$(PATH):`GOENV="$(GOENV)" go env GOBIN`"
	protoc '-I=$(PROTOSRC)' '--go_out=$(MYGOSRC)' "$<"

$(AWS_TEMP_CREDS): | bin
	aws --profile=dynamo_root sts get-session-token --duration-seconds=54000 \
	  > "$(AWS_TEMP_CREDS)"
	EXPIRE=`cat "$(AWS_TEMP_CREDS)" | grep '"Expiration":' | sed -r 's/.*"([^"]+)",?$$/\1/'`
	EXP_SECS=`date --date="$$EXPIRE" +%s`
	NOW_SECS=`date +%s`
	[[ "$$NOW_SECS" -le "$$EXP_SECS" ]] || echo "ERROR expired creds"

$(call c_lib,linux_utils): LDLIBS := -lcap
$(call c_lib,linux_utils): bin/linux_utils.o bin/common.o

bin/%.o : src/%.c $(headers)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o "$@" "$<"

bin/%.so:
	$(CC) -shared $(LDFLAGS) -o "$@" $^ $(LOADLIBES) $(LDLIBS)

bin/%.a:
	ar rcs "$@" $^

bin/%_test: bin/%_test.o bin/%.o
	$(CC) $(LDFLAGS) -o "$@" $^ $(LOADLIBES) $(LDLIBS)

bin/btrfs_progs_test: bin/btrfs_progs_test.o bin/common.o
	$(CC) $(LDFLAGS) -o "$@" $^ $(BTRFS_LDLIB)

