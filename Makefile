PROTOCCMD = protoc
PROTOGEN_PATH = $(shell which protoc-gen-go) 
PROTOGENGRPC_PATH = $(shell which protoc-gen-go-grpc) 

GO_FILES := $(shell find $(SRC_DIR) -name '*.go')

GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean

LDFLAGS := -s -w

ifeq ($(OS), Windows_NT)
	DEFAULT_BUILD_FILENAME := StealthIMUser.exe
else
	DEFAULT_BUILD_FILENAME := StealthIMUser
endif

.PHONY: run
run: build
	./bin/$(DEFAULT_BUILD_FILENAME)

StealthIM.DBGateway/db_gateway_grpc.pb.go StealthIM.DBGateway/db_gateway.pb.go: proto/db_gateway.proto
	$(PROTOCCMD) --plugin=protoc-gen-go=$(PROTOGEN_PATH) --plugin=protoc-gen-go-grpc=$(PROTOGENGRPC_PATH) --go-grpc_out=. --go_out=. proto/db_gateway.proto

StealthIM.Session/session_grpc.pb.go StealthIM.Session/session.pb.go: proto/session.proto
	$(PROTOCCMD) --plugin=protoc-gen-go=$(PROTOGEN_PATH) --plugin=protoc-gen-go-grpc=$(PROTOGENGRPC_PATH) --go-grpc_out=. --go_out=. proto/session.proto

StealthIM.User/user_grpc.pb.go StealthIM.User/user.pb.go: proto/user.proto
	$(PROTOCCMD) --plugin=protoc-gen-go=$(PROTOGEN_PATH) --plugin=protoc-gen-go-grpc=$(PROTOGENGRPC_PATH) --go-grpc_out=. --go_out=. proto/user.proto

.PHONY: proto
proto: ./StealthIM.DBGateway/db_gateway_grpc.pb.go ./StealthIM.DBGateway/db_gateway.pb.go ./StealthIM.User/user_grpc.pb.go ./StealthIM.User/user.pb.go StealthIM.Session/session_grpc.pb.go StealthIM.Session/session.pb.go

.PHONY: build
build: ./bin/$(DEFAULT_BUILD_FILENAME)

./bin/StealthIMUser.exe: $(GO_FILES) proto
	GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o ./bin/StealthIMUser.exe

./bin/StealthIMUser: $(GO_FILES) proto
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ./bin/StealthIMUser

.PHONY: build_win build_linux
build_win: ./bin/StealthIMUser.exe
build_linux: ./bin/StealthIMUser

.PHONY: docker_run
docker_run:
	docker-compose up

./bin/StealthIMUser.docker.zst: $(GO_FILES) proto
	docker-compose build
	docker save stealthimuser-app > ./bin/StealthIMUser.docker
	zstd ./bin/StealthIMUser.docker -19
	@rm ./bin/StealthIMUser.docker

.PHONY: build_docker
build_docker: ./bin/StealthIMUser.docker.zst

.PHONY: release
release: build_win build_linux build_docker

.PHONY: clean
clean:
	@rm -rf ./StealthIM.*
	@rm -rf ./bin
	@rm -rf ./__debug*

.PHONY: dev
dev:
	./run_env.sh

.PHONY: debug_proto
debug_proto:
	cd test && python -m grpc_tools.protoc -I. --python_out=. --mypy_out=.  --grpclib_python_out=. --proto_path=../proto user.proto
	cd test && python -m grpc_tools.protoc -I. --python_out=. --mypy_out=.  --grpclib_python_out=. --proto_path=../proto session.proto
