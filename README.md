# An Implementation of Anonymous Counting Tokens.

An anonymous counting token (ACT) scheme allows Clients to obtain blind
signatures or MACs (aka tokens) on messages of their choice, while at the same
time enabling Issuers to enforce rate limits on the number of tokens that a
client can obtain for each message. Specifically,

*   Blind issuance: The Issuer doesn't see the message for which a token is
    being requested
*   Unlinkability: When the Client redeems a token, the token cannot be linked
    to the issuance phase
*   Throttled issuance on identical messages: The Issuer can detect if a
    particular Client is requesting a token for a previously used message.

This repository implements a variant of the scheme described in [1], which is
secure in the random oracle model under the q-DDHI assumption (in a cyclic
group) and the DCR assumption. The variant implemented here relaxes the proven
soundness guarantee to the non-concurrent setting. It also assumes that the
server generates its parameters correctly. Future versions will support server
proofs for correct parameter generation.

This implementation also supports batched token issuance. Batched token issuance
can have significant performance benefits as compared to individual token
issuance.

> [[1] "Anonymous Counting Tokens." Fabrice Benhamouda, Mariana Raykova, Karn
> Seth.](https://eprint.iacr.org/2023/320)

## Building/Running Tests

This repository requires Bazel. You can install Bazel by
following the instructions for your platform on the
[Bazel website](https://docs.bazel.build/versions/master/install.html).

Once you have installed Bazel you can clone this repository and run all tests
that are included by navigating into the root folder and running:

```bash
bazel test //...
```


## Disclaimer

This is not an officially supported Google product. The code is provided as-is,
with no guarantees of correctness or security.