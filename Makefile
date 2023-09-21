.ONESHELL:
.SECONDARY:
.PHONY: all clean fs_init fuzzer c_code go_code go_debug go_unittest go_deflake test

PROJ_ROOT     := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))
include etc/Makefile.include
STAGE_PATH    := /tmp/bin_btrfs_to_glacier

BTRFS_LIB     := /usr/lib
BTRFS_INCLUDE := /usr/include
BTRFS_LDLIB   := -lbtrfsutil -lbtrfs

GOENV             := $(STAGE_PATH)/go_env
GO_TEST_FLAGS     :=
MYGOSRC           := src/golang
GO_PROTOC_INSTALL := $(STAGE_PATH)/gobin/protoc-gen-go
# Chose NOT to store generated proto sources in git
# Can be problematic for some languages like C++ (see groups.google.com/g/protobuf/c/Qz5Aj7zK03Y)
GO_PROTO_GEN_SRCS := $(MYGOSRC)/messages/config.pb.go $(MYGOSRC)/messages/messages.pb.go
MYDLVINIT         := $(STAGE_PATH)/dlv_init
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
go_files := $(shell find "$(MYGOSRC)" -type f -name '*.go' -not -name '*.pb.go')
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

canary_integ: all
	pushd "$(MYGOSRC)"
	GOENV="$(GOENV)" go run ./workflow/backup_restore_canary/canary_integration

cloud_integ: all
	pushd "$(MYGOSRC)"
	GOENV="$(GOENV)" go run ./volume_store/cloud_integration

shim_integ: all | $(SUBVOL_PATH)
	bin/btrfs_progs_test "$(SUBVOL_PATH)" || exit 1
	pushd "$(MYGOSRC)"
	GOENV="$(GOENV)" go run ./shim/shim_integration \
	  --subvol="$(SUBVOL_PATH)" \
		--subvol-alt="$(SUBVOL_ALT_PATH)" \
		--rootvol="$(MOUNT_TESTVOL_SRC)" \
		--destvol="$(MOUNT_TESTVOL_DST)" \
		--snap1="$(SNAP1_PATH)" --snap2="$(SNAP2_PATH)"

fuzzer: all
	pushd "$(MYGOSRC)"
	GOENV="$(GOENV)" go run ./encryption/fuzz_correctness

linters:
	bash etc/check_on_test_code_in_prod.sh "$(MYGOSRC)"

test: go_unittest fuzzer canary_integ cloud_integ shim_integ linters

$(SUBVOL_PATH):
	echo "$(SUBVOL_PATH)"
	[[ `id -u` == "0" ]] && echo never run this as root && exit 1
	bash etc/setup_test_drive.sh -r -f -p \
	  -e "$(EXT4_PREFIX)" -l "$(FS_PREFIX)" -s "$(SUBVOL_NAME)"

fs_init: $(SUBVOL_PATH)

go_code: c_code $(GOENV) $(go_files) $(GO_PROTO_GEN_SRCS)
	pushd "$(MYGOSRC)"
	GOENV="$(GOENV)" go install ./...

go_unittest: go_code
	pushd "$(MYGOSRC)"
	# add --test.v to get verbose tests
	# add --test.count=1 to not cache results
	# add --test.run=filter_rx to choose tests to run
	pkg_to_test=( `GOENV="$(GOENV)" go list btrfs_to_glacier/... | grep -vE "_integration$$|/types|/fuzz"` )
	GOENV="$(GOENV)" go test $(GO_TEST_FLAGS) "$${pkg_to_test[@]}"

go_deflake: go_code
	# example call:
	# make go_deflake DEFLAKE_TEST=TestBucketCreation_Immediate DEFLAKE_PKG=volume_store/aws_s3_common
	pushd "$(MYGOSRC)"
	echo
	echo "### Deflaking the following tests:"
	GOENV="$(GOENV)" go test "btrfs_to_glacier/$(DEFLAKE_PKG)" --test.list="$(DEFLAKE_TEST)"
	while true; do
	  GOENV="$(GOENV)" go test "btrfs_to_glacier/$(DEFLAKE_PKG)" --test.count=1 \
		  --test.run="$(DEFLAKE_TEST)" --test.failfast || break
	done

go_debug: go_code
	# example call:
	# make go_debug DEBUG_TEST=TestBucketCreation_Immediate DEBUG_PKG=volume_store/aws_s3_common
	pushd "$(MYGOSRC)"
	echo '
	break btrfs_to_glacier/$(DEBUG_PKG).$(DEBUG_TEST)
	continue
	' > "$(MYDLVINIT)"
	# https://github.com/go-delve/delve/blob/master/Documentation/usage/dlv_debug.md
	CGO_CFLAGS="$(CFLAGS_DBG)" GOENV="$(GOENV)" \
	  dlv test "btrfs_to_glacier/$(DEBUG_PKG)" \
		  --build-flags='-tags=delve' --init="$(MYDLVINIT)" --output="$(STAGE_PATH)/debugme" \
		  -- --test.run='$(DEBUG_TEST)' --test.v

# Fails with a linker error if missing `c_code`
go_upgrade_mods: $(GOENV) c_code
	pushd "$(MYGOSRC)"
	GOENV="$(GOENV)" go list -u -m all
	#GOENV="$(GOENV)" go mod graph
	GOENV="$(GOENV)" go get -t -u ./...
	GOENV="$(GOENV)" go mod tidy

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
	pushd "$(MYGOSRC)"
	GOENV="$(GOENV)" go install google.golang.org/protobuf/cmd/protoc-gen-go

$(MYGOSRC)/messages/%.pb.go: $(PROTOSRC)/%.proto $(GOENV) | $(GO_PROTOC_INSTALL)
	export PATH="$(PATH):`GOENV="$(GOENV)" go env GOBIN`"
	protoc '-I=$(PROTOSRC)' '--go_out=$(MYGOSRC)' "$<"

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

