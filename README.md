# chainark
a ZKP library to prove a chain of any given relationship, block chain, signature chain, etc. The relationship is defined by application developers, while this library focuses on how we can prove the entire relationship chain with only one proof. This library comes with an easy to understand [example](example/README.md).

Under the hood, we have defined three roles:

- Units, the circuit that application developers should implement to constraint the relationship to be proved;
- Genesis, the first in the relationship chain;
- Recursive, the rolling proof to attestate the chain structure from `Genesis` to the latest in the chain.

We have upgraded chainark to allow Units to have multiple implementations, providing a more compact proving system. In the attached example, we may have the unit to prove `1` relationship (`nextId = hash(currentId)`), or `2` (`nextNextId = hash(hash(currentId))`), etc. 