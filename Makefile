# Self-contained entry points for the evaluation lab.
# Run inside `nix develop`; docker must reach the host daemon.
.PHONY: all collector images check solve-test clean

all: collector

collector:
	$(MAKE) -C collector collector

images:
	./pentagi-lab/build-victims.sh

check:
	./pentagi-lab/render.py --check

solve-test:
	@echo "bring a profile up first: docker compose -f pentagi-lab/docker-compose.yml --profile <profile> up -d"
	./pentagi-lab/solve-test.sh all

clean:
	$(MAKE) -C collector clean
