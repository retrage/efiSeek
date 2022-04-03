#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright 2019 Alex James <theracermaster@gmail.com>
# Based on: https://github.com/al3xtjames/ghidra-firmware-utils/blob/master/data/gen_prf.sh

set -x

# Default ARCH is X64. Possible values are AArch64, Arm, Ebc, Ia32, RiscV64, X64
ARCH="${ARCH:-X64}"
DATA_DIR="${DATA_DIR:-$(dirname "$0")/../data}"

EDK2_VERSION="edk2-stable202202"
EDK2_TARBALL="$EDK2_VERSION.tar.gz"
EDK2_URL="https://github.com/tianocore/edk2/archive/refs/tags/$EDK2_TARBALL"

EDK2_PATH="$DATA_DIR/edk2-$EDK2_VERSION"
EDK2_TARBALL_PATH="$DATA_DIR/$EDK2_TARBALL"

case $ARCH in
  AArch64 | Arm | Ebc | Ia32 | RiscV64 | X64)
    ARCH_NAME="$(echo $ARCH | tr '[:upper:]' '[:lower:]')"
    ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

mkdir -p "$DATA_DIR"

if [ ! -f "$EDK2_TARBALL_PATH" ]; then
  wget --quiet $EDK2_URL -O $EDK2_TARBALL_PATH
fi

rm -rf "$EDK2_PATH"
tar -xf $EDK2_TARBALL_PATH -C $DATA_DIR

for FILE in $(find patches -name "*.patch"); do
  patch -p1 -d "$EDK2_PATH" < $FILE
done

PRF_PATH="$DATA_DIR/edk2_$ARCH_NAME.prf"
EDK2_MDE_INC_PATH="$(realpath $EDK2_PATH/MdePkg/Include)"

cat << EOF > "$PRF_PATH"
$EDK2_MDE_INC_PATH/Uefi.h
$EDK2_MDE_INC_PATH/PiDxe.h
$EDK2_MDE_INC_PATH/PiMm.h
$EDK2_MDE_INC_PATH/PiPei.h
$EDK2_MDE_INC_PATH/PiSmm.h
$EDK2_MDE_INC_PATH/Library/DxeCoreEntryPoint.h
$EDK2_MDE_INC_PATH/Library/PeiCoreEntryPoint.h
$EDK2_MDE_INC_PATH/Library/PeimEntryPoint.h
$EDK2_MDE_INC_PATH/Library/StandaloneMmDriverEntryPoint.h
$EDK2_MDE_INC_PATH/Library/UefiApplicationEntryPoint.h
$EDK2_MDE_INC_PATH/Library/UefiDriverEntryPoint.h
$(find "$EDK2_MDE_INC_PATH/Pi" -type f)
$(find "$EDK2_MDE_INC_PATH/Ppi" -type f)
$(find "$EDK2_MDE_INC_PATH/Protocol" -type f)
$(find "$EDK2_MDE_INC_PATH/IndustryStandard" -type f)

-I"$EDK2_MDE_INC_PATH/$ARCH"
-I"$EDK2_MDE_INC_PATH"
-DGHIDRA_CPARSER
EOF