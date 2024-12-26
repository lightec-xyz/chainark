# chainark
a ZKP library to prove a chain of any given relationship, block chain, signature chain, etc. The relationship is defined by application developers, while this library focuses on how we can prove the entire relationship chain with only one proof. This library comes with an easy to understand [example](example/README.md).

Under the hood, we have defined two roles:

- Units, the circuit that application developers should implement to constraint the relationship to be proved;
- Recursive, the rolling proof to attestate the chain structure from `Genesis` to the latest in the chain.

We have upgraded chainark to allow Units to have multiple implementations, providing a more compact proving system. In the attached example, we may have the unit to prove `1` relationship (`nextId = hash(currentId)`), or `2` (`nextNextId = hash(hash(currentId))`), etc. 

When all the unit circuits and the recursive ciruits have sizes in the same range (for this version, (2^23 ~2^24)), there is an optional optimization that oculd be turned on to reduce the size of the recursive circuit. Turn on optimization by adding the optional parameter with value `true` to the `chainark.NewRecursiveCircuit` function all. This optimization may reduce over 3 million constraints but the prerequisite might not hold in a future version of chainark.