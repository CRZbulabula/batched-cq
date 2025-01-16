# Batched CQ
Consider the scenario where the prover seeks to demonstrate possession of $k$ polynomials $f_1(X),f_2(X),\cdots,f_k(X)$, simultaneously, without actually revealing them. The Cached Quotients (CQ) protocol, as described in this [paper](https://eprint.iacr.org/2022/1763.pdf), can be adapted to efficiently fulfill this requirement.

## Preliminaries
The following high-quality blogs are recommended for reading before delving into the CQ protocol:

+ [A (Relatively Easy To Understand) Primer on Elliptic Curve Cryptography](https://blog.cloudflare.com/a-relatively-easy-to-understand-primer-on-elliptic-curve-cryptography/)
+ [Exploring Elliptic Curve Pairings](https://vitalik.eth.limo/general/2017/01/14/exploring_ecp.html)
+ [KZG polynomial commitments](https://dankradfeist.de/ethereum/2020/06/16/kate-polynomial-commitments.html)

## Intuition
To effectively leverage the CQ protocol, we can first explore a method to combine these $k$ polynomials into a single polynomial. Intuitively, multiplying these polynomials presents a natural approach, as it seamlessly incorporates the essential log-derivative method (Lemma 2.3).

Given the n-sparsity of the polynomials $f_1(X),f_2(X),\cdots,f_k(X)$, interpolating the integrated polynomial requires $O(kn)$ Lagrange basis. Consequently, in this batched version of the CQ protocol, the complexity of the prover's work increases to $O(kn \log kn)$, while the complexities of preprocessing, proof size, and verifier's work remain unchanged.

## Correctness
Let $f_i(X)=\prod_{j=1}^n(x-f_{i,j})$ and $F(X)=\prod_{i=1}^kf_i(X)$. We will show that, following the approach outlined in Lemma 2.3, verifying the correctness of $F(x)$ is equivalent to verifying the correctness of each $f_i(X)$ individually. To begin, we have:
$$
\begin{aligned}
\frac{d}{dx}\log(F(x))&=\frac{d}{dx}\log(\prod_{i=1}^kf_i(X)) \\
&=\frac{d}{dx}\sum_{i=1}^k\log(f_i(X)) \\
&=\sum_{i=1}^{k}\sum_{j=1}^n\frac{d}{dx}\log(x-f_{i,j}) \\
&=\sum_{i=1}^{k}\sum_{j=1}^n\frac{1}{x-f_{i,j}}
\end{aligned}
$$

Given the public $T(X)=\prod_{j=1}^N(x-t_j)$, each $f_i(X)$ can be expressed as $f_i(X)=\prod_{j=1}^N(x-t_j)^{m_{i,j}}$. Consequently, we have:
$$
\begin{aligned}
\frac{d}{dx}\log(F(x))&=\frac{d}{dx}\log(\prod_{i=1}^kf_i(X)) \\
&=\sum_{i=1}^k\sum_{j=1}^Nm_{i,j}\frac{d}{dx}\log((x-t_j)) \\
&=\sum_{i=1}^k\sum_{j=1}^N\frac{m_{i,j}}{x-t_j} \\
&=\sum_{j=1}^N\frac{\sum_{i=1}^km_{i,j}}{x-t_j}
\end{aligned}
$$

Since the above equalities preserve the same structure as those in Lemma 2.3, we can conclude that the correctness of $F(x)$ is equivalent to the correctness of each $f_i(X)$.

## Quick Benchmark
We verify the correctness of both $F(X)$ and $f_i(X)$ in the example provided in [src/lib.rs](src/lib.rs) - `test_bach_roundtrip`.
