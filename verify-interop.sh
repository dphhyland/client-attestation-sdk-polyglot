#!/usr/bin/env bash
# Build every port's credential from the shared vectors and verify them through the real Java AS-side
# ClientAttestationVerifier. Requires: python3, node/npm, go, a JDK, and the Java SDK jars installed in
# ~/.m2 (build the sibling client-attestation repo with `mvn -o install` first).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

echo "== emit: python =="
( cd python && PYTHONPATH=src python3 emit.py )

echo "== emit: typescript =="
( cd typescript && npm install --silent && npm run --silent emit )

echo "== emit: go =="
( cd go && go run ./cmd/emit )

echo "== assemble Java classpath from ~/.m2 =="
M2="$HOME/.m2/repository"
CP=""
for j in \
  com/pingidentity/ps/oidf/client-attestation/0.1.0/client-attestation-0.1.0.jar \
  com/pingidentity/ps/oidf/oidf-jose/0.1.0/oidf-jose-0.1.0.jar \
  org/bitbucket/b_c/jose4j/0.9.6/jose4j-0.9.6.jar \
  com/fasterxml/jackson/core/jackson-databind/2.17.1/jackson-databind-2.17.1.jar \
  com/fasterxml/jackson/core/jackson-core/2.17.1/jackson-core-2.17.1.jar \
  com/fasterxml/jackson/core/jackson-annotations/2.17.1/jackson-annotations-2.17.1.jar \
  commons-logging/commons-logging/1.2/commons-logging-1.2.jar ; do
  if [ -f "$M2/$j" ]; then CP="$CP:$M2/$j"; else
    echo "missing $j — build the client-attestation Java SDK first: (cd ../client-attestation && mvn -o install)"; exit 1
  fi
done
SLF4J="$(find "$M2/org/slf4j/slf4j-api" -name 'slf4j-api-*.jar' | sort -V | tail -1)"
CP="${CP#:}:$SLF4J"

echo "== compile + run the interop verifier =="
JH="$(/usr/libexec/java_home 2>/dev/null || echo "${JAVA_HOME:-}")"
mkdir -p interop/out
"$JH/bin/javac" -cp "$CP" -d interop/out interop/VerifyInterop.java
"$JH/bin/java" -cp "$CP:interop/out" VerifyInterop "$ROOT/vectors"
