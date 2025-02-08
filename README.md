# chainark
a ZKP library to prove a chain of any given relationship, block chain, signature chain, etc. The relationship is defined by application developers, while this library focuses on how we can prove the entire relationship chain with only one proof. This library comes with an easy to understand [example](example/README.md).

Under the hood, we have defined two roles:

- Units, the circuit that application developers should implement to constraint the relationship to be proved;
- Recursive, the rolling proof to attestate the chain structure from `Genesis` to the latest in the chain.

We have upgraded chainark to allow Units to have multiple implementations, providing a more compact proving system. In the attached example, we may have the unit to prove `1` relationship (`nextId = hash(currentId)`), or `2` (`nextNextId = hash(hash(currentId))`), etc. 

Further, chainark also allows to have multiple implementation for Recursive circuits. A typical example is to have the recursive circuit directly (non-recursive) verify some relationship to further extend the link, resulting in the `HybridCircuit`. This has been added to the attached example as well.

When all the unit circuits, the recursive ciruit, and all the hybrid cricuits have sizes in the same 2's-power range (for this version, ($2^{23}$ ~ $2^{24}$)), there is an optional optimization that oculd be turned on to reduce the size of the recursive circuit. Turn on optimization by adding the optional parameter with value `true` to the `chainark.NewRecursiveCircuit` function call. This optimization may reduce over 1.2 ~ 3 million constraints (depending on gnark version) but the prerequisite might not hold in a future version of chainark or gnark. The `example/setup2.sh` demonstrates this feature by adding some extra costs to the circuit to adjust the constraint count of the circuits.

## how to use
Besides following the [example](example/README.md) to write contraints for your own business logic, note that you also need to verify if `SelfFps` used during recursive verification are as expected, in order to verify a proof generated by the Recursive or Hybrid circuit. To simplify the API and prevent from missing crucial constraints, we have added a [recursive verifier API](./verifier.go) to verify proof generated by the Recursive or Hybrid circuit.

## security
If you found security issues in chainark, please send an email to `hello@lightec.xyz`. We appreciate your contributions. Once the zkBTC project goes live, we will be able to reward some tokens once the issue has been confirmed. 
