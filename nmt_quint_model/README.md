# What is Quint?

The folder `nmt_quint_model` contains a formal specification of the NMT proof/verification logic in [Quint](https://github.com/informalsystems/quint).

[Quint](https://github.com/informalsystems/quint) is a specification language, best suited modeling and analyzing distributed systems.
Quint builds upon Temporal Logic of Actions (TLA) and aims to be easy to learn and use, with state-of-the-art static analysis and development tooling.

The benefits of having a Quint specification are threefold:

- It is a precise description of the expected behavior, and yet it resides on a higher level of abstraction than the code. Furthermore, it is executable, which makes it easier to spot and eliminate mistakes in the specification. Module [nmt](https://github.com/ivan-gavran/nmt/blob/c3cc6b7acba34c97a1a4d5e8fa4be1d355535c1e/formal_spec/nmt.qnt#L253) captures the logic of namespace proof generation and verification, and the invariant [`verificationAlwaysCorrect`](https://github.com/ivan-gavran/nmt/blob/c3cc6b7acba34c97a1a4d5e8fa4be1d355535c1e/formal_spec/nmt.qnt#L592) is an example of a property against which a specification can be checked.
- It allows for test generation. Module [`nmtTest`](https://github.com/ivan-gavran/nmt/blob/c3cc6b7acba34c97a1a4d5e8fa4be1d355535c1e/formal_spec/nmt.qnt#LL597C17-L597C17) iteratively generates proofs and non-deterministically corrupts them. These generated test runs are exported in a json format (e.g., file [ITF_traces/runTest.itf.json](https://github.com/ivan-gavran/nmt/blob/ivan/quint_spec/formal_spec/ITF_files/runTest.itf.json)). To be executed as a part of the standard suite, an adapter [simulation_test.go](https://github.com/ivan-gavran/nmt/blob/ivan/quint_spec/simulation_test.go) is necessary. (The adapter iterates through the json-represented execution state and translates them to function calls.) The generation of the tests happens through simulation. In that sense, it is similar to the existing tests [fuzz_test.go](https://github.com/celestiaorg/nmt/blob/master/fuzz_test.go), except that it also adds corruption of the data.
- Having specifications written in Quint makes it possible to change tests/specs quickly: either by taking advantage of updates to Quint (e.g., going from simulation to exhaustive checks by changing a command) or by virtue of making changes on the level higher than code (and thus less details need to be changed).

Current limitations:

- the specification does not model absence proofs
- there is an assumption that every tree is full and complete
- the specification does not model special handling of parity namespace (`ignoreMaxNamespace` option). Modelling it correctly depends on the decision of what the desired behaviour is (issue #148 )

# Intro to Using Quint and the NMT Model

## Installation

- install `quint` tool by running `npm i @informalsystems/quint -g`  (more details [here](https://github.com/informalsystems/quint/blob/main/quint/README.md))
- install the VSCode plugin from [here](https://marketplace.visualstudio.com/items?itemName=informal.quint-vscode). While this is not necessary, it is of great help when writing models.

## Basic resources

- a sequence of very gentle and fun tutorials [here](https://github.com/informalsystems/quint/blob/main/tutorials/README.md)
- language [cheatsheet](https://github.com/informalsystems/quint/blob/main/doc/quint-cheatsheet.pdf)
- documentation for built-in operators [here](https://github.com/informalsystems/quint/blob/main/doc/builtin.md)

## REPL

After installing the quint tool, run the REPL by typing `quint` to terminal.
Then you can play with the REPL by trying some basic expressions, e.g.

- `2+3`
- `val x = Set(1,3,4)`
- `x.powerset()`
- `x.map(i => i*2)`

## Inspecting the NMT model

As a first step, examine the model operators from within REPL.
Example commands to try out after running `quint` within the `formal_spec` folder:

```bluespec
.load nmt.qnt

import basics.*

import nmt_helpers.*

import nmt.*

val c_leaves = [{ value: ("data", 0), namespaceId: 0 }, { value: ("data", 1), namespaceId: 2 }, { value: ("data", 2), namespaceId: 2 }, { value: ("data", 3), namespaceId: 4 }]

val c_tree = BuildTree(c_leaves)

val proofZero = CreateProofNamespace(0, c_tree)

CreateProofNamespace(2, c_tree)

val c_root = c_tree.hashes.get(1)

verifyInclusionProof(proofZero, c_root, 0, [{ value: ("data", 0), namespaceId: 0 }])

MerkleRangeHash(proofZero, [{ value: ("data", 0), namespaceId: 0 }])

verifyInclusionProof(proofZero, c_root, 0, [{ value: ("data", 0), namespaceId: 2 }])

import nmtProofVerification.*

// runs the initialization action
init 

// runs one step of the model
step 

// runs another step of the model
step 
```

After getting acquainted with all the operators, you can simulate the model behavior by running

- `quint run --main=nmtProofVerification --max-samples=1 --max-steps=100 nmt.qnt --invariant=verificationAlwaysCorrect`
This command will run the module `nmtProofVerification`, which iteratively generates data, creates a proof for a namespace and then verifies it. It will run 100 steps of the model and will check that the property `verificationAlwaysCorrect` always holds. It will output the steps to the terminal. (For options, run `quint run --help`)

- `quint run --main=nmtTest --max-samples=1 --max-steps=100 nmt.qnt --out-itf=ITF_files/out.itf.json`
This command will simulate the module `nmtTest`, which non-deterministically corrupts the generated proof and outputs the simulation steps to the file `ITF_files/out.itf.json`, to be used in tests.

## Running tests

Once a test file is generated, it is read by `simulation_test.go`, a regular go test. (A path to the json file that should be tested needs to be given - at the moment [hardcoded](https://github.com/ivan-gavran/nmt/blob/c3cc6b7acba34c97a1a4d5e8fa4be1d355535c1e/simulation_test.go#L85) in the code.)
