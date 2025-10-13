.PHONY: all build run dev

all: dev

build:
	docker build --network=host -t onboarding-tools .

run:
	docker run --network=host -e OPENSLICE_HOST=10.255.31.117 -e PORT=8004 -e LOG_LEVEL=DEBUG onboarding-tools

push:
	docker build --network=host -t diogosantosua/onboarding-tools:latest .
	docker push diogosantosua/onboarding-tools:latest

dev:
	. venv/bin/activate && fastapi dev src/main.py

deploy:
	helm install my-onboarding-tools helm/ --kubeconfig ~/repos/bolsa/one_testbed/kubeconfig
