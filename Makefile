APP_NAME = diogosantosua/onboarding-tools
TAG := $(shell . venv/bin/activate && python3 -c "from src.settings import settings; print(f'{settings.version}.{settings.sub_version}')")

.PHONY: all build run dev push deploy

all: dev

dev:
	. venv/bin/activate && cd src && uvicorn main:app --port 8004 --reload --log-level debug

build:
	docker build --network=host -t $(APP_NAME):latest .

run:
	docker run --network=host -e OPENSLICE_HOST=10.255.31.117 -e PORT=8004 -e LOG_LEVEL=DEBUG $(APP_NAME):latest

push:
	docker tag $(APP_NAME):latest $(APP_NAME):$(TAG)
	docker push $(APP_NAME):$(TAG)
	docker push $(APP_NAME):latest

deploy:
	helm install my-onboarding-tools helm/ --kubeconfig ~/repos/bolsa/one_testbed/kubeconfig
