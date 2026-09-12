.PHONY: check replay build
check:
	python -m pytest -q
replay:
	replay scenarios --all
build:
	python -m build
