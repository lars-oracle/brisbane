#!/bin/bash

#
# Copyright (c) 2026 Oracle and/or its affiliates.
#
# The Universal Permissive License (UPL), Version 1.0
#
# Subject to the condition set forth below, permission is hereby granted to any
# person obtaining a copy of this software, associated documentation and/or data
# (collectively the "Software"), free of charge and under any and all copyright
# rights in the Software, and any and all patent rights owned or freely
# licensable by each licensor hereunder covering either (i) the unmodified
# Software as contributed to or provided by such licensor, or (ii) the Larger
# Works (as defined below), to deal in both
#
# (a) the Software, and
#
# (b) any piece of software and/or hardware listed in the lrgrwrks.txt file if
# one is included with the Software (each a "Larger Work" to which the Software
# is contributed by such licensors),
#
# without restriction, including without limitation the rights to copy, create
# derivative works of, display, perform, and distribute the Software and make,
# use, sell, offer for sale, import, export, have made, and have sold the
# Software and the Larger Work(s), and to sublicense the foregoing rights on
# either these or other terms.
#
# This license is subject to the following condition:
#
# The above copyright notice and either this complete permission notice or at
# a minimum a reference to the UPL must be included in all copies or
# substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

# Generates PBMAC1 PKCS12 keystores using different providers and MAC algorithms.
# Requires:
#  JDK version 26
#  OpenSSL Version 3.4 or later

function print_usage()
{
   echo "$0 (--keystore-provider <SUN|OpenSSL>) (--mac-algorithm <hmacsha1|hmacsha224|hmacsha256|hmacsha384|hmacsha512>) (--help)"
}

function get_java_major_version()
{
   java_version=$(java -version 2>&1)
   echo "$java_version" | grep version | grep -oE '[0-9]+(\.[0-9]+)*' | head -n 1 | awk -F. '{print ($1 == "1") ? $2 : $1}'
}

function get_openssl_minor_version()
{
   openssl_version=$(openssl -version | awk '{print $2}')
   echo "$openssl_version" | awk -F. '{print $2}'
}

while [[ $# -gt 0 ]]; do
   case $1 in
    --help)
      print_usage
      exit 1
      ;;
    --keystore-provider)
      KEYSTORE_PROVIDER="$2"
      shift # past argument
      shift # past value
      ;;
    --mac-algorithm)
      MAC_ALGORITHM="$2"
      shift # past argument
      shift # past value
      ;;
       *)
      >&2 echo "Unsupported option: $1"
      >&2 print_usage
      exit 1
      ;;
   esac
done


if [ -z ${KEYSTORE_PROVIDER+x} ]; then
  KEYSTORE_PROVIDER="SUN"
fi

case $KEYSTORE_PROVIDER in
  SUN)
    MAJOR_VERSION=$(get_java_major_version)
    if [[ ${MAJOR_VERSION} -lt 26 ]]; then
      >&2 echo "Unsupported Java version: ${MAJOR_VERSION}. Minimum supported Java version: 26"
      exit 1
    fi
    ;;
  OpenSSL)
    if [[ $(get_openssl_minor_version) -lt 4 ]]; then
      >&2 echo "Unsupported OpenSSL version $(openssl -version | awk '{print $2}'). Minimum supported OpenSSL version: 3.4.0"
      exit -1
    fi
    ;;
  *)
    >&2 echo "Unsupported keystore provider: $KEYSTORE_PROVIDER"
    >&2 print_usage
    exit 1
    ;;
esac

if [ -z ${MAC_ALGORITHM+x} ]; then
  MAC_ALGORITHM="hmacsha256"
fi

case $MAC_ALGORITHM in
  hmacsha1)
    MD="sha1"
    ;;
  hmacsha224)
    MD="sha224"
    ;;
  hmacsha256)
    MD="sha256"
    ;;
 hmacsha384)
    MD="sha384"
    ;;
  hmacsha512)
    MD="sha512"
    ;;
  *)
    >&2 echo "Unsupported mac algorithm: $MAC_ALGORTHM"
    >&2 print_usage
    exit 1
    ;;
esac

if [ "${KEYSTORE_PROVIDER}" == "OpenSSL" ]; then
  PBE="AES-256-CBC"
else
  PBE="PBEWithHmacSHA512andAES_256"
fi

PASSWORD="password"
ALIAS=test

if [ "${KEYSTORE_PROVIDER}" == "OpenSSL" ]; then
  SUBJECT="/C=AU/ST=QLD/L=Brisbane/O=Oracle/OU=OCI/CN=Test"

  PBE_CLAUSE="-certpbe ${PBE} -keypbe ${PBE}"
  PBMAC1_CLAUSE="-pbmac1_pbkdf2 -pbmac1_pbkdf2_md ${MD} -macsaltlen 16"
  FILENAME="OpenSSL.pbmac1.${MAC_ALGORITHM}.keystore.p12"

  rm -f ${ALIAS}.private.key.pem ${ALIAS}.cert.pem ${FILENAME}

  # Create test private key and self signed ca
  openssl req -newkey rsa:2048 -sha256 -nodes -keyout ${ALIAS}.private.key.pem -x509 -days 7300 -out ${ALIAS}.cert.pem -subj "${SUBJECT}"

  # Wrap up content in pkcs12
  openssl pkcs12 -export -in ${ALIAS}.cert.pem -inkey ${ALIAS}.private.key.pem \
                 -name ${ALIAS} -out ${FILENAME} -passout pass:${PASSWORD} \
                 ${PBE_CLAUSE} ${PBMAC1_CLAUSE}

else
  DNAME="CN=Test, OU=OCI, O=Oracle, L=Brisbane, ST=QLD, C=AU"

  SECURITY_PROPERTIES_CLAUSE=" -J-Dkeystore.pkcs12.keyProtectionAlgorithm=${PBE} "
  SECURITY_PROPERTIES_CLAUSE+="-J-Dkeystore.pkcs12.certProtectionAlgorithm=${PBE} "
  SECURITY_PROPERTIES_CLAUSE+="-J-Dkeystore.pkcs12.macAlgorithm=pbewith${MAC_ALGORITHM}"

  FILENAME="${KEYSTORE_PROVIDER}.pbmac1.${MAC_ALGORITHM}.keystore.p12"
  rm -f ${FILENAME}

  keytool -keystore ${FILENAME} -genkey -alias ${ALIAS} -keyalg "rsa" -dname "${DNAME}" \
          -destprovidername ${KEYSTORE_PROVIDER} -deststoretype pkcs12 \
          -deststorepass ${PASSWORD} -destkeypass ${PASSWORD} \
          ${SECURITY_PROPERTIES_CLAUSE}
fi
