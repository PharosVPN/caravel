module github.com/PharosVPN/caravel/core

go 1.25.7

require (
	github.com/PharosVPN/coxswain v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.80.0
	google.golang.org/protobuf v1.36.11
	golang.org/x/crypto v0.51.0
)

replace github.com/PharosVPN/coxswain => ../../../helm
