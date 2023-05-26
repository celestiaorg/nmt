module basics {

    def listToSet(l: List[a]) : Set[a] = 
        l.foldl(Set(), (acc, x) => union(acc, Set(x)))
    
    def min(S: Set[int]) : int = 
        // val tentativeMin = chooseSome(S) ---> chooseSome is not supported yet
        val tentativeMin = -1
        S.fold(
            tentativeMin, 
            (acc, i) => if ((acc == tentativeMin) or (i < acc)) i else acc
            )

    
    def max(S: Set[int]) : int = 
        // val tentativeMax = chooseSome(S) --> chooseSome not supported yet
        val tentativeMax = -1
        S.fold(
            tentativeMax, 
            (acc, i) => if ((acc == -1) or (i > acc)) i else acc
            )
    
    
}

// This module creates leaves with namespaces and a namespace id to search for.
// Its purpose is to create data for tests similar to those from 
// nmt_test.go::TestNamespacedMerkleTree_ProveNamespace_Ranges_And_Verify
// 
// The approach taken here is different from the one in nmt.qnt: here,
// in every step, one leaf is generated. Thus, the final test data is available in the 
// last step

module tests {     

    import basics.*
    pure val MAX_NAMESPACE_ID = 100

    var leaves_namespace_idx_v : List[int]
    var namespace_v : int  
    var namespaceIdFound_v : bool

    // syntactic sugar, for better readability
    def require(pred: bool) : bool = pred

    action init = {
        nondet first_element = oneOf(0.to(MAX_NAMESPACE_ID))
        nondet namespace = oneOf(0.to(MAX_NAMESPACE_ID))
        all {                        
            leaves_namespace_idx_v' = [first_element],                        
            namespace_v' = namespace,  
            namespaceIdFound_v' = first_element == namespace
        }
    }

    action step = {
        val l = length(leaves_namespace_idx_v)
        val lastElement = leaves_namespace_idx_v[l-1]
        nondet new_index = oneOf(
                lastElement.to(MAX_NAMESPACE_ID)                    
            )            
        all{   
            require(lastElement < MAX_NAMESPACE_ID),                                             
            leaves_namespace_idx_v' = append(leaves_namespace_idx_v, new_index),
            namespace_v' = namespace_v,
            namespaceIdFound_v' = (namespaceIdFound_v or (new_index == namespace_v))
        }
    }
    
    // 
    // test scenarios, as originally described in nmt_test.go
    //     

    // original test comment (from nmt_test.go): "not found",
    val namespaceIdNotFound =               
        val leavesSet = listToSet(leaves_namespace_idx_v)
        not(leavesSet.contains(namespace_v))

    val namespaceIdNotFoundTest =                 
            not(namespaceIdNotFound)
            
        

    // original test comment (from nmt_test.go): "two leaves and found"
    val twoLeavesAndFound = 
        and{
            length(leaves_namespace_idx_v) == 2,
            val leavesSet = listToSet(leaves_namespace_idx_v)
            leavesSet.contains(namespace_v)
        }

    val twoLeavesAndFoundTest = 
        not(twoLeavesAndFound)

    
    // original test comment (from nmt_test.go): "5 leaves and not found but within range"
    val fiveLeavesAndNotFoundButWithinRange = 
        val leavesSet = listToSet(leaves_namespace_idx_v)
        and{
            length(leaves_namespace_idx_v) == 5,            
            not(leavesSet.contains(namespace_v)),
            min(leavesSet) < namespace_v,
            max(leavesSet) > namespace_v
        }

    val fiveLeavesAndNotFoundButWithinRangeTest = 
        not(fiveLeavesAndNotFoundButWithinRange)
        
                
                    
        
        

}