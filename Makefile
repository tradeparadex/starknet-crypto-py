.PHONY: default clean check build sdist develop test

default: build

clean:
	@echo "🧹 Cleaning..."
	cargo clean
	rm -rf *~ dist *.egg-info build target

check:
	@echo "🩺 Checking..."
	cargo fmt --check
	poetry run ruff check .
	cargo check
	poetry check

build:
	@echo "🔨 Building..."
	poetry run maturin build -i 3.10 --sdist --release --strip \
		--compatibility manylinux_2_28

sdist:
	@echo "🔨 Building..."
	poetry run maturin sdist

develop:
	@echo "⛏️ Building..."
	poetry run maturin develop

test: develop
	@echo "🧪 Testing code: Running pytest"
# 	cargo test
	poetry run pytest -vv
	poetry run mypy .
