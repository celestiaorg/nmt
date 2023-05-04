// -*- mode: Bluespec; -*-

// This file contains a Quint specification of the (part of the) Namespaced Merkle Tree
// library. 
// The specification is written in Quint (https://github.com/informalsystems/quint), a modern specification
// language based on TLA.
// 
// The file is split into five modules:
//  - basics: some basic functions and types
//  - nmt_helpers: helper function (e.g., generation of trees, pairwise hashing etc.)
//  - nmt: creation of NMT proof and their verification
//  - nmtProofVerification: actions that generate proofs and verify them, thereby checking if 
//    the logic of the spec is sound
//  - nmtTest: actions that generate proof and non-deterministically corrupt them afterwards,
//    whose output can be used in test generation
//  
//  The specification models Inclusion proofs, but does not model Absence proofs.

module basics{

    type BINARY = List[int]

    def binary(n: int) : BINARY =
        if (n == 0)
            [0]
        else
            range(0,n).foldl(
                [],
                (acc, i) => {
                    val c = n / 2^i
                    if (c > 0)
                        [c % 2].concat(acc)
                    else
                        acc
                }
            )
    
    // this function gets the first power of 
    // 2 which is greater than `lastNode`
    def getFullTreeSize(lastNode : int) : int =
       if (lastNode == 0)
            1
        else
            2^length(binary(lastNode))
    
    def sum(list: List[int]) : int =
        list.foldl(0, (acc, i) => acc + i)
    
    def min(S: Set[int]) : int = 
        // val tentativeMin = chooseSome(S) ---> chooseSome is not supported yet
        val tentativeMin = -1
        S.fold(
            tentativeMin, 
            (acc, i) => if ((acc == tentativeMin) or (i < acc)) i else acc
            )

    def listToSet(S: List[int]) : Set[int] = 
        S.foldl(Set(), (acc, i) => acc.union(Set(i)))


    def setToSortedList(S: Set[int]) : List[int] = 
        S.fold(
            [], 
            (acc, i) => acc.concat(
                [min(S.exclude(listToSet(acc)))]
                )
            )

    def max(S: Set[int]) : int = 
        // val tentativeMax = chooseSome(S) --> chooseSome not supported yet
        val tentativeMax = -1
        S.fold(
            tentativeMax, 
            (acc, i) => if ((acc == -1) or (i > acc)) i else acc
            )
    
        
    

    def reverse(L: List[x]) : List[x] =
        L.foldl([], (acc, i) => [i].concat(acc))

    def getWithDefault(mapX: int -> a, key: int, default: a) : a =
        if (mapX.keys().contains(key))
            mapX.get(key)
        else
            default        


}

module nmt_helpers{
    import basics.*

    type NODE_IDX = int

    // hashes will be of type WORD
    type WORD = List[(str, int)]

    // each tree is a mapping from node indices (=integers) to the
    // corresponding data at leaf nodes and hashes of all nodes.
    // the root of the tree has index 1, its child 2 and 3 etc. (as captured in functions
    // `getParentIdx`, `getLeftChildidx` and `getRightChildIdx`)
    // 
    type TREE = {
        leaves: NODE_IDX -> DATA_ITEM,        
        hashes: NODE_IDX -> NAMESPACE_HASH      
    }

    type NAMESPACE_HASH = {minNS: int, maxNS: int, hash: WORD}
    
    type PROOF = {start: int, end: int, supporting_hashes: List[NAMESPACE_HASH]}

    type DATA = (str, int)

    type DATA_ITEM  = {value: DATA, namespaceId: int}


    def getParentIdx(idx : NODE_IDX) : NODE_IDX =
        idx / 2

    def getLeftChildIdx(idx : NODE_IDX) : NODE_IDX =
        2 * idx

    def getLeftUncleIdx(idx : NODE_IDX, uncle_level : int) : NODE_IDX =
        idx/2^uncle_level - 1

    def getRightUncleIdx(idx : NODE_IDX, uncle_level : int) : NODE_IDX =
        idx/2^uncle_level + 1


    def getRightChildIdx(idx : NODE_IDX) : NODE_IDX =
        2 * idx + 1

    // hash is defined trivially, as the identity function.
    // When used for testing, it should be replaced by a real hash function
    def Hash(data: WORD) : WORD =
        data

    def mergeWithLeftAndRight(left: WORD, middle: WORD, right: WORD) : WORD =
        concat(concat(left, middle), right)


    // takes a list and maps it to a new list which contains hashes 
    // of consecutive pairs of elements from the original list
    def pairwiseHash(dataList: WORD) : WORD =
        
        if (length(dataList) == 1)
            dataList
        else
            range(0, length(dataList)).foldl(
                [],
                (acc, i) => {
                    if (i % 2 == 0)
                        acc
                    else
                        acc.concat(Hash(concat([dataList[i-1]],[dataList[i]])))
                }
            ) 

    // This function takes as parameters:
    //  - `namespaceBordersSet`: a sorted list of integers which defines borders between different namespaces.
    //     For instance, [3, 5] would indicate that leaves 0,1,2, belong to a same namespace; leaves 3 and 4 to another namespace; 
    //     leaf 5 and all leaves after 5 to a third namespace.
    //  - `power`: an integer defining the height of the tree. The tree will have 2^(power-1) leaves
    // 
    // The function returns a list of data items. In this model, we don't care about the data itself, so we just use dummy data.
    // Our format for dummy ddata is a pair (str, int), where the first element is always "data" and the second element is the index of the leaf.    
    def GenerateLeavesCorrectly(power: int, namespaceBordersSet : Set[int]) : List[DATA_ITEM] =
        
        // add left-most and right-most borders to namespaces
        val namespaceBorders = concat(
            concat([0], setToSortedList(namespaceBordersSet)),
            [2^(power-1)]
        )        
        
        val generated_leaves_dummy_hash : List[DATA_ITEM] = 
            // for each namespace
            range(0, length(namespaceBorders)-1).foldl(
                [],
                (acc, i) => 
                    acc.concat(
                        // and for each leaf between two namespaces
                        range(namespaceBorders[i], namespaceBorders[i+1]).foldl(
                            [],
                            // create a data point
                            (acc2, j) => acc2.concat([{value: ("data", 0), namespaceId: i*2}])
                            )
                        )
            )

        // this is mostly for debugging purposes: have data value correspond exactly to the index
        // of the leaf. (This enables easier reasoning about the generated proofs later)
        val generated_leaves : List[DATA_ITEM] = 
            range(0, length(generated_leaves_dummy_hash)).foldl(
                [],
                (acc, i) => acc.concat(                    
                    [{value: ("data", i), namespaceId: generated_leaves_dummy_hash[i].namespaceId}]
                )
        )

        generated_leaves




    def BuildTree(leaves: List[DATA_ITEM]) : TREE = 
        // because of the way trees are represented (nodes enumerated from 1 to 2^n - 1),
        // and the assumption of full and complete trees, we know that leaves
        // are occupying the half of the tree. Thus, their starting index equals their length
        val leaf_idx_start = length(leaves)

        val tree_leaves : NODE_IDX -> DATA_ITEM = 
            range(0, length(leaves)).foldl(
                Map(),
                (acc, i) => acc.put(leaf_idx_start + i, leaves[i])
            )

        val tree_leaves_hashes : NODE_IDX -> NAMESPACE_HASH = 
            range(0, length(leaves)).foldl(
                Map(),
                (acc, i) => 
                acc.put(
                    leaf_idx_start + i, 
                    {minNS: leaves[i].namespaceId, maxNS: leaves[i].namespaceId, hash: Hash([leaves[i].value])})
            )

        // starting from leaves, calculating the hashes for all other nodes 
        // of the tree
        val tree_hashes : NODE_IDX -> NAMESPACE_HASH = 
            reverse(range(1, leaf_idx_start)).foldl(
                tree_leaves_hashes,
                (acc, i) =>
                acc.put(
                    i,
                    {
                        // minimum is the minimum of the left child because of the ordering assumption
                        minNS: acc.get(getLeftChildIdx(i)).minNS,
                        // max is the max of the right child because of the ordering assumption
                        maxNS: acc.get(getRightChildIdx(i)).maxNS,
                        hash: Hash(
                            concat(
                                acc.get(getLeftChildIdx(i)).hash,
                                acc.get(getRightChildIdx(i)).hash
                            )
                        )
                    }
                )  
        )

        {leaves: tree_leaves, hashes: tree_hashes}
    

 

    
}



module nmt {    
    // ASSUMPTIONS/LIMITATIONS: 
    // - each tree is full and complete (2^n leaves at the bottom level)
    // - not modelling ignoring max namespace

    import basics.*
    import nmt_helpers.*
    

    
    

    
    pure val MAX_POWER = 5
    pure val MAX_NAMESPACE_ID = 100
    pure val EMPTY_PROOF = {start: -1, end: -1, supporting_hashes: []}
    pure val EMPTY_TREE = {leaves: Map(), hashes: Map()}
    pure val EMPTY_LEAVES = []

    
    

    
    // This function creates a proof for a given `namespaceId` and a given `tree`.
    // Following the NMT documentation (https://github.com/celestiaorg/nmt/blob/master/docs/spec/nmt.md#namespace-proof),
    // the tproof consists of `start` and `end` indices and the hashes of the nodes (`supporting_hashes`) that are left siblings
    // in the regular Merkle proof of `start` and those that are right hashes in the regular proof of `end-1` 
    def CreateProofNamespace(namespaceId: int, tree: TREE): PROOF =
        val leavesStart = min(tree.leaves.keys())                
        // take only those keys that are of the desired namespace
        val relevantLeavesKeys = tree.leaves.keys().fold(
            Set(),
            (acc, i) => 
                if (tree.leaves.get(i).namespaceId == namespaceId)
                    union(acc, Set(i))
                else
                    acc            
        )
        val start = min(relevantLeavesKeys)        

        // we want to get the binary representation of the number leaves from the `start` (first node of the 
        // leaves that go to the proof) and the very beginning of leaves because this encodes left siblings, 
        // uncles, etc., which are needed for the merkle proof. The fact that we use it reversed is because the 
        // proof defines the nodes to be in-order, thus, older ancestors come first (bcs they are more left)
        val binaryLeftLimitDistanceReversed = reverse(binary(start - leavesStart))
        
        val left_hashes : List[NAMESPACE_HASH] = 
            range(0, length(binaryLeftLimitDistanceReversed)).foldl(
                [],
                (acc, i) =>
                    if (binaryLeftLimitDistanceReversed[i] == 1)                    
                        concat([tree.hashes.get(getLeftUncleIdx(start, i))], acc)
                    else
                        acc
                )

        val end = max(relevantLeavesKeys)
        val binaryRightLimitDistanceReversed = reverse(binary(2*leavesStart-1 - end))

        val right_hashes : List[NAMESPACE_HASH] = 
            range(0, length(binaryRightLimitDistanceReversed)).foldl(
                [],
                (acc, i) =>
                    if (binaryRightLimitDistanceReversed[i] == 1)                    
                        acc.concat([tree.hashes.get(getRightUncleIdx(end, i))])
                    else
                        acc
                )            

        // start needs to be expressed relative to leaves start and so does end. 
        {
            start: start - leavesStart, 
            // the +1 is because the range has to be non-inclusive at the right side
            end: end - leavesStart +1, 
            supporting_hashes: concat(left_hashes, right_hashes)
        }

       
    
    
    def SensibleStartEnd(start: int, end: int) : bool =
        and {
            start >= 0,            
            start < end
        }

    // all leaf nodes in the proof should have the same namespace
    def CorrectNamespaceValue(proof: PROOF, namespaceId: int, leaves: List[DATA_ITEM]) : bool =
        val elementsWithWrongId = leaves.select(x => x.namespaceId != namespaceId)        
        length(elementsWithWrongId) == 0
        
       
    // Given `proof` and `leaves`, this function calculates the Merkle roo (which is hash) for that range.
    def MerkleRangeHash(proof: PROOF, leaves: List[DATA_ITEM]) : WORD =
        
        // the number of leaves in a complete subtree that covers the last leaf
        // in the proof
        val fullTreeSize = getFullTreeSize(proof.end - 1)

        // binary representation of the nodes to the left of proof.start.
        // Binary representation captures well left uncles needed for the Merkle proof.
        val binaryLeftLimitDistance = binary(proof.start)

        val binaryRightLimitDistance = binary(fullTreeSize - proof.end)

        // create a mapping levelOfTheTree -> hash. This enables knowing which of the supporting_hashes
        // is used on which level of the tree (from the left side)
        val leftMap : int -> WORD = 
            range(0, length(binaryLeftLimitDistance)).foldl(
                Map(),
                (accMap, i) => 
                    // if the bit is 1, then the left uncle from the tree level i is necessary in the Merkle proof
                    if (binaryLeftLimitDistance[i] == 1) 
                        accMap.put(
                            // reversing: because the supporting nodes are given in-order, closer relatives of
                            // the leaf node will come the last
                            length(binaryLeftLimitDistance) - 1 - i, 
                            // adding the first unused of the supporting hashes (hence, key equals to the size of the growing map)
                            proof.supporting_hashes[size(accMap.keys())].hash
                            ) 
                    else 
                        accMap
                )

        // similarly to leftMap, the rightMap holds the mapping of the supporting leaves from the right side of the
        // range
        val rightMap : int -> WORD = 
            range(0, length(binaryRightLimitDistance)).foldl(
                Map(),
                (accMap, i) 
                => 
                if (binaryRightLimitDistance[i] == 1) 
                    accMap.put(
                        i, 
                        proof.supporting_hashes[sum(binaryLeftLimitDistance) + size(accMap.keys())].hash
                        ) 
                else 
                    accMap
                )

        val numLeavesUsed = sum(binaryLeftLimitDistance)+sum(binaryRightLimitDistance)
        

        // after the left and right maps are created, the remaining supporting hashes 
        // are the ones that are not used. They are necessarily on the right side of the leaf range
        // and can be treated as a proof path in a regular (not the range-based) Merkle tree
        val remainingSupportNodes : List[NAMESPACE_HASH] = 
            if (numLeavesUsed == length(proof.supporting_hashes)) 
                [] 
            else 
                proof.supporting_hashes.slice(numLeavesUsed,length(proof.supporting_hashes))
        
        // height of the smallest tree which starts at the leaf index 0 and encompasses the whole range
        val treeHeight : int = 
            if (proof.end == 1) 1 else length(binary(proof.end-1)) + 1

                        
        // a list of hashes of the leaves in the [start, end) range
        val leafHashes: WORD = 
            leaves.foldl(
                [],
                (acc, leaf) => acc.concat(Hash([leaf.value]))
                )
        
        val partialTreeRootHash : WORD = 
            // Fold over the levels of the tree, starting from the leaf level.
            // Progress to the next level by hashing pairs of hashes from the previous level.
            // Each level is half the size of the previous one until finally a list containing a single hash is returned. 
            range(0,treeHeight).foldl(
                leafHashes,
                // pairwiseHash will map a list to a new list by taking a hash of every two consecutive values
                (acc, i) => pairwiseHash( 
                    mergeWithLeftAndRight(
                        getWithDefault(leftMap, i, []),
                        acc,
                        getWithDefault(rightMap, i, [])
                    )
                )
            )          

        // having computed the partialTreeRootHash, we can now treat the rest of the supporting hashes
        // as a regular Merkle inclusion proof and starting from the `partialTreeRootHash` chain the hashes
        // computation.
        val calculatedRootHash : WORD = remainingSupportNodes.foldl(
            partialTreeRootHash,
            (acc, levelHashes) => Hash(acc.concat(levelHashes.hash))
        )
        
        // a hash value that is returned
        calculatedRootHash


    // none of the proof nodes should have an overlap with the `namespaceId`
    def Completeness(proof: PROOF, namespaceId: int) : bool = 
        val allSupportingNamespaceIds = 
            proof.supporting_hashes.foldl(
                Set(),
                (acc, el) => union(acc, el.minNS.to(el.maxNS))
            )
        
        not(allSupportingNamespaceIds.contains(namespaceId))


    def verifyInclusionProof(proof: PROOF, rootHash: NAMESPACE_HASH, namespaceId: int, leaves: List[DATA_ITEM]) : bool = {
        
        and {            
            SensibleStartEnd(proof.start, proof.end),            
            CorrectNamespaceValue(proof, namespaceId, leaves),            
            Completeness(proof, namespaceId),
            rootHash.hash == MerkleRangeHash(proof, leaves)
        }
    }
    
}


module nmtProofVerification {

    // this module iteratively generates a proof and then verifies it.
    //  run by:
    // quint run --main=nmtProofVerification --max-samples=1 --max-steps=100 nmt.qnt --invariant=verificationAlwaysCorrect
    // to run the simulation for 100 steps and check the invariant `verificationAlwaysCorrect`


    import basics.*
    import nmt_helpers.*
    import nmt.*

    var proof_v : PROOF
    var tree_v : TREE    
    var namespace_v : int
    var verification_success_v : bool
    var state_v : string


    action init = {              
        all{            
            tree_v' = EMPTY_TREE,
            proof_v' = EMPTY_PROOF,
            verification_success_v' = false,
            state_v' = "requirements",
            namespace_v' = -1
        }        
    }

    // step is modelled as a loop of the four always repeating states: 
    // 1) requirements, 2) generation,  3) verification, and 4) final state.
    // 
    // 1) when in the "requirements" or "init" state, a random size of the tree and the namespaces 
    // corresponding to leaves,
    // are generated and one of the namespaces is chosen to generate a proof for
    // 2) when in the "generation" state, a proof is generated for the generated tree and the chosen namespace
    // 3) when in the "verification" state, that proof is verified
    // 4) final step collects all the results
    // 
    // The three steps happen one after another (no non-determinism involved)
    action step = {
        any{

            // 1): requirements
            all{
                // state precondition
                state_v == "requirements",
                // update state for the next step
                state_v' = "generation",

                nondet power = oneOf(3.to(MAX_POWER))  
                //TODO: there must be a better way to generate this set
                nondet namespaceBordersSet = 1.to(2^(power-1) - 2).powerset().filter(x => size(x) > 1).oneOf()
                val leaves = GenerateLeavesCorrectly(power, namespaceBordersSet)
                all{                    
                    val tree = BuildTree(leaves)
                    all{
                        tree_v' = tree,
                        nondet namespaceId = tree.leaves.keys().fold(
                            Set(),
                            (acc, leaf_key) => 
                            union(acc, Set(tree.leaves.get(leaf_key).namespaceId))                    
                        ).oneOf()                 
                        namespace_v' = namespaceId,
                    }
                },
                proof_v' = proof_v,                
                verification_success_v' = verification_success_v,
            },

            // 2): generation
            all{
                // state preconditions
                state_v == "generation",
                // update state for the next step
                state_v' = "verification",
                proof_v' = CreateProofNamespace(namespace_v, tree_v),
                namespace_v' = namespace_v,
                verification_success_v' = verification_success_v,
                tree_v' = tree_v                
            },

            // 3): verification
            all{
                // state preconditions
                state_v == "verification",
                // update state for the next step
                state_v' = "final",
                namespace_v' = namespace_v,

                val min_leaf_key = min(tree_v.leaves.keys())
                val max_leaf_key = max(tree_v.leaves.keys())
                val leaves : List[DATA_ITEM] = 
                    range(min_leaf_key, max_leaf_key+1)
                        .foldl(
                            [],
                            (acc, leaf_key) => 
                            if ((proof_v.start <= leaf_key - min_leaf_key) and (leaf_key - min_leaf_key < proof_v.end))
                                acc.append(
                                    tree_v.leaves.get(leaf_key)
                                    )
                            else
                                acc
                        )
                        
                verification_success_v' = verifyInclusionProof(proof_v, tree_v.hashes.get(1), namespace_v, leaves),
                tree_v' = tree_v,
                proof_v' = proof_v,                
            },

            // 4): collecting all results
            all {
                // state preconditions
                state_v == "final",
                //update state for the next step
                state_v' = "requirements",
                // resetting the state to initial values
                namespace_v' = -1,
                tree_v' = EMPTY_TREE,
                proof_v' = EMPTY_PROOF,
                verification_success_v' = false,
            }
        }
    }

    // this invariant states that after the full loop of states,
    // verification will be successful
    val verificationAlwaysCorrect = 
        (state_v == "final") implies (verification_success_v == true)
}


module nmtTest {

    // this module iteratively generates a proof and then non-deterministically corrupts it.
    // run by:
    // quint run --main=nmtTest --max-samples=1 --max-steps=100 nmt.qnt --out-itf=ITF_files/out.itf.json
    // to simulate 100 steps and save output into `out.itf.json`. This output can be used to generate 
    // test cases (eg., in `simulation_test.go`)

    import basics.*
    import nmt_helpers.*
    import nmt.* 

    var proof_v : PROOF
    var tree_v : TREE    
    var namespace_v : int    
    var state_v : string
    var leaves_v : List[DATA_ITEM]
    var corrupted : bool
    var corruption_type : string
    var corruption_diff : {changed_start: int, changed_end: int, changed_namespace: int, changed_indices: List[int]}

    action init = {              
        all{            
            tree_v' = EMPTY_TREE,
            proof_v' = EMPTY_PROOF,
            corrupted' = false,
            state_v' = "init",
            namespace_v' = -1,
            leaves_v' = EMPTY_LEAVES,
            corruption_type' = "",
            corruption_diff' = 
            {
                changed_start: -1,
                changed_end: -1,
                changed_namespace: -1,
                changed_indices: []
            }

        }        
    }

    action requirements = {
        all{
            // state precondition
            state_v == "requirements",
            // update state for the next step
            state_v' = "generation",

            nondet power = oneOf(3.to(MAX_POWER))  
            //TODO: there must be a better way to generate this set
            nondet namespaceBordersSet = 1.to(2^(power-1) - 2).powerset().filter(x => size(x) > 1).oneOf()
            val leaves = GenerateLeavesCorrectly(power, namespaceBordersSet)
            all{                    
                val tree = BuildTree(leaves)
                all{
                    leaves_v' = leaves,
                    tree_v' = tree,
                    nondet namespaceId = tree.leaves.keys().fold(
                        Set(),
                        (acc, leaf_key) => 
                        union(acc, Set(tree.leaves.get(leaf_key).namespaceId))                    
                    ).oneOf()                 
                    namespace_v' = namespaceId,
                }
            },
            // unchanged variables
            proof_v' = proof_v,                
            corrupted' = corrupted,
            corruption_type' = corruption_type,
            corruption_diff' = corruption_diff
            }
    }

    action generation = {
        all{
            // state preconditions
            state_v == "generation",
            // update state for the next step
            state_v' = "final",
            proof_v' = CreateProofNamespace(namespace_v, tree_v),
            // unchanged variables
            namespace_v' = namespace_v,
            corrupted' = false,
            tree_v' = tree_v,
            leaves_v' = leaves_v,
            corruption_type' = corruption_type,
            corruption_diff' = corruption_diff            
        }
    }


   



    action final = {
        all {
            // state preconditions
            state_v == "final",
            //update state for the next step
            state_v' = "requirements",
            // resetting the state to initial values
            namespace_v' = -1,
            tree_v' = EMPTY_TREE,
            proof_v' = EMPTY_PROOF,
            corrupted' = false,
            leaves_v' = EMPTY_LEAVES,
            corruption_type' = "",
            corruption_diff' = 
            {
                changed_start: -1,
                changed_end: -1,
                changed_namespace: -1,
                changed_indices: []
            }
            }
    }

    action corruptProof = {
        all{
            // state preconditions
            state_v == "final",
            corrupted == false,

            // corrupting the proof
            any{
                // corrupting the start value: we will change its value, while maintaining the property that it must
                // be smaller than `proof_v.end` (we get that by requiring `new_start` to be from the set {0, ..., proof_v.end - 1}).
                // We will also require that it is indeed different from `proof_v.start`.
                all{
                    proof_v.end != 1,
                    namespace_v' = namespace_v,
                    nondet new_start = oneOf(
                        0.to(proof_v.end - 1).exclude(Set(proof_v.start))
                        )
                    all{
                                        
                        proof_v' = {start: new_start, end: proof_v.end, supporting_hashes: proof_v.supporting_hashes},                        
                        corruption_type' = "start",                        
                        corruption_diff' = corruption_diff.with("changed_start", new_start),
                    }
                },

                // corrupting the end value: we will change its value, while maintaining the property that it must 
                // be greater than start by at least 1 (we get that by requiring `new_end` to be from the set {proof_v.start, ..., proof_v.end - 1})
                all{
                    proof_v.start < proof_v.end - 1,
                    namespace_v' = namespace_v,
                    nondet new_end = oneOf(proof_v.start.to(proof_v.end - 1))
                    all{
                        proof_v' = {start: proof_v.start, end: new_end, supporting_hashes: proof_v.supporting_hashes},
                        corruption_type' = "end",
                        corruption_diff' = corruption_diff.with("changed_end", new_end),
                    }
                    
                },
                
                // corrupting the supporting hashes in a controlled way: we will take a subset of existing supporting hashes
                all{
                    proof_v.supporting_hashes.length() > 1,
                    namespace_v' = namespace_v,
                    // We use the original set of indices and then take a subset of it as a corrupted one.
                    // We do so by selecting `oneOf` from the set of all subsets of existing indices (`powerse`), 
                    // provided that it is not the empty set and not the full set of indices. (`filter`).
                    // Note that this is non-deterministic value (`nondet`) because of the function `oneOf`.
                    nondet new_supporting_hashes_indices = oneOf(
                        0.to(proof_v.supporting_hashes.length()-1)
                            .powerset()
                            .filter(
                                x => 
                                and{
                                    size(x) < proof_v.supporting_hashes.length(),
                                    size(x) > 0
                                }
                        )
                    )

                    // Now we use the calculated subset of indices to extract the corresponding subset of supporting hashes.
                    // We do so by iterating over the set of indices. Iteration over lists in Quint is done by using the concept of 
                    // the left fold (`foldl`). For more info on `foldl`, check 
                    // https://github.com/informalsystems/quint/blob/main/doc/builtin.md#pure-def-foldl-lista-b-b-a--b--b
                    val new_supporting_hashes = range(0, proof_v.supporting_hashes.length())
                        .foldl(
                            [],
                            (acc, i) => 
                            if (new_supporting_hashes_indices.contains(i))
                                acc.append(proof_v.supporting_hashes[i])
                            else
                                acc
                        )          
                    all{          
                        proof_v' = {start: proof_v.start, end: proof_v.end, supporting_hashes: new_supporting_hashes},
                        corruption_type' = "supporting_hashes",
                        val new_indices = range(0, proof_v.supporting_hashes.length())
                            .foldl(
                                [],
                                (acc, i) => 
                                if (new_supporting_hashes_indices.contains(i))
                                    acc.append(i)
                                else
                                    acc
                            )
                        corruption_diff' = corruption_diff.with("changed_indices", new_indices),
                    }
                    
                },
                
                // corrupting the namespace value: we will change the value of the namespace for which the proof is written.
                // We do so by selecting `newNamespace` from the set {1,...,MAX_NAMESPACE_ID}, while requiring that it is 
                // indeed different from `namespace_v`.
                all{                 
                    proof_v' = proof_v,
                    nondet newNamespace = 1.to(MAX_NAMESPACE_ID).exclude(Set(namespace_v)).oneOf()
                    all{
                        namespace_v' = newNamespace,
                        corruption_type' = "namespace",
                        corruption_diff' = corruption_diff.with("changed_namespace", newNamespace),
                    }
                }
            },            
            corrupted' = true,

            // unchanged variables
            state_v' = state_v,
            tree_v' = tree_v,            
            leaves_v' = leaves_v
        }
        

    }

    // step is modelled as by 4 states:
    // 1) requirements, 2) generation,  2a) corruptProof, and 3) final state.
    // 
    // The state `corruptProof` is marked by 2a because it may be skipped (leaving the proof uncorrupted)
    // 1) when in the "requirements" or "init" state, a random size of the tree and the namespaces 
    // corresponding to leaves,
    // are generated and one of the namespaces is chosen to generate a proof for
    // 2) when in the "generation" state, a proof is generated for the generated tree and the chosen namespace
    // 2a) when in the `final` state, the proof may be corrupted by changing its start, end, nodes, or namespace
    // and not transitioning to the next state, but remaining in `final`. (There will be no two corruptions because
    // the variable `corrupted` is set to true after the first corruption.)
    // 3) when in the `final` state, the state is reset to the initial values
    // 
    // The three steps happen one after another (no non-determinism involved)
    action step = {
        any{

            // 1): requirements: defining the tree and the namespace to generate a proof for
            requirements,

            // 2): generation of the proof 
            generation,
            
            // 2b): corrupting the proof
            corruptProof,            

            // 3): collecting all results
            final
            
        }

    }
   
}
