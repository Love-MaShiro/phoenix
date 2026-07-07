/*
The software is provided by the Institute of Commercial Cryptography Standards
(ICCS), and is used for algorithm submissions in the Next-generation Commercial
Cryptographic Algorithms Program (NGCC).

ICCS doesn't represent or warrant that the operation of the software will be
uninterrupted or error-free in all cases. ICCS will take no responsibility for
the use of the software or the results thereof, if the software is used for any
other purposes.
*/

#ifndef AUXFUNC_H
#define AUXFUNC_H

#ifdef __cplusplus
extern "C"
{
#endif

    /// @brief An eXtensible Output Function (XOF) constructed using KDF-SM3 to generate an output of specified length
    ///        It is only used for correctness verification of implementations, and does not guarantee security
    /// @param[in] output_len_bits Total bits (less than (2^40-2^8)) of output
    /// @param[in] msg Base address of input message byte array
    /// @param[in] msg_len_bits Total bits of input message
    /// @param[out] output Base address of output byte array
    /// @return 0 for success, others for error
    int pseudoXOF(unsigned long long output_len_bits, const unsigned char *msg, unsigned long long msg_len_bits, unsigned char *output);

#ifdef __cplusplus
}
#endif

#endif