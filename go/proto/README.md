# Caravel proto codegen

This directory will contain the generated Go code from:
- `pharos.account.v1.AccountSync` (account/sync service)
- `pharos.buoy.v1.Control` (node tunnel config)

Generated files are built by:
```
cd ../../../docs && buf generate --path=proto/pharos/account/v1/
```

Run gomobile to generate native bindings:
```
cd .. && gomobile bind -target=android,ios ./
```
