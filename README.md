# Note: Big refactoring pending

The pyspqsigs project is currently undergoing a bit refactoring into what has been renamed to [coinZdense](https://coin.z-den.se/). Check out the [technical deep-dive](https://hive.blog/coinzdense/@pibara/coinzdense-deep-dive-index) documents to see what's comming.

# coinzdense-python
Simple Hash Based Post Quantum Signatures : Python implementation

The coinZdense project is a continuation of the spq\_sigs project using lessons learned to create a new
has-based signatures library for use in/with utility-blockchains, blockchain-based distributed exchanges, and other setups where 
key-reuse-by design is required and the solution should be post-quantum ready. 

Please note that the signatures for coinZdense aren't compatible with those from it's predecesor spq\_sigs.

This project currently hasn't reached MVP status yet. Focus is currently on creating a stable API and signature format Stabilizing state serialisation format isn't a focus yet, and neither is cross-language compatibility of state serialization. 

