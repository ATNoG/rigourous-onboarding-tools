APP_NAME = diogosantosua/onboarding-tools
TAG := $(shell . venv/bin/activate && python3 -c "from src.settings import settings; print(f'{settings.version}.{settings.sub_version}')")

.PHONY: all build run dev

all: dev

dev:
	. venv/bin/activate && fastapi dev src/main.py

build:
	docker build --network=host -t $(APP_NAME):latest .

run:
	docker run --network=host -e OPENSLICE_HOST=10.255.31.117 -e PORT=8004 -e LOG_LEVEL=DEBUG $(APP_NAME):latest

push:
	docker tag $(APP_NAME):latest $(APP_NAME):$(TAG)
	docker push $(APP_NAME):latest
	docker push $(APP_NAME):$(TAG)

deploy:
	helm install my-onboarding-tools helm/ --kubeconfig ~/repos/bolsa/one_testbed/kubeconfig
