# Solidity code generator for zk-aggregate

## Step 1. Generate solidity contract file

Setup verifier circuit as indicated by `../halo2-snark-aggregator/README.md`.
After running the first 4 and 5.b(i.e. verify_solidity) steps, all files
are in the directory `../halo2-snark-aggregator/output`.

## Step 2. Setup environment for waffle

TL;DR
```
setup.sh
```

## Step 3. Run waffle test

```
cd waffle
yarn test
```
