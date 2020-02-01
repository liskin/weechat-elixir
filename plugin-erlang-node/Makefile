.PHONY: build
build: _build/build.ninja
	ninja -C _build

_build/build.ninja: | meson.build
	meson _build

.PHONY: clean
clean:
	git clean -fdX
