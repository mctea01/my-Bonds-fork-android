// SPDX-License-Identifier: Apache-2.0
// Synthetic startup vector; no circomlib or other circuit libraries are used.
pragma circom 2.2.3;

template AddOne() {
    signal input a;
    signal output b;
    b <== a + 1;
}

component main {public[a]} = AddOne();
