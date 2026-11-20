.PHONY: all build test clean samples

all: build

build:
	tools/build.sh

samples:
	@for p in A B C; do ../samples/build-sample.sh $$p; done

test: build samples
	python3 tools/evaluate.py --skip-build

clean:
	rm -rf build

# Convenience: analyze the three bundled samples end to end (build everything first).
demo: build
	@for p in A B C; do ../samples/build-sample.sh $$p >/dev/null; done
	@for p in A B C; do tools/run-sample.sh $$p; done
